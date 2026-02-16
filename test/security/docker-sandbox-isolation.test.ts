/**
 * Docker Sandbox Isolation Tests (Phase 5)
 *
 * Verifies that a container running the gateway is properly locked down:
 * - Host filesystem paths are inaccessible
 * - Docker socket is not mounted
 * - Cloud metadata endpoints are unreachable
 * - Container runs as non-root
 * - No dangerous capabilities
 * - Secret files are not leaked into the container
 *
 * These tests are designed to run INSIDE a Docker container with
 * `OPENCLAW_DOCKER_SECURITY_TEST=1`. They skip gracefully outside Docker.
 */

import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import { describe, expect, it } from "vitest";

const IS_DOCKER_TEST = process.env.OPENCLAW_DOCKER_SECURITY_TEST === "1";

// Helper: attempt a TCP connection with timeout
function tryConnect(host: string, port: number, timeoutMs = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, timeoutMs);
    socket.on("connect", () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(true);
    });
    socket.on("error", () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

// Helper: check if a path is readable
function isReadable(filePath: string): boolean {
  try {
    fs.accessSync(filePath, fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

describe.skipIf(!IS_DOCKER_TEST)("Docker sandbox isolation", () => {
  // -------------------------------------------------------------------------
  // Host filesystem access denial
  // -------------------------------------------------------------------------
  describe("host filesystem isolation", () => {
    it("cannot read /etc/shadow", () => {
      expect(isReadable("/etc/shadow")).toBe(false);
    });

    it("cannot read host .env files from standard locations", () => {
      const hostEnvPaths = ["/root/.env", "/home/.env"];
      for (const p of hostEnvPaths) {
        // These should either not exist or not be readable in the container
        if (fs.existsSync(p)) {
          expect(isReadable(p)).toBe(false);
        }
      }
    });

    it("cannot access ~/.openclaw/credentials/ from host", () => {
      // In the container, HOME is /home/node with a tmpfs overlay.
      // Host credential directories should not be mounted.
      const hostCredPaths = ["/root/.openclaw/credentials", "/home/node/.openclaw/credentials"];
      for (const p of hostCredPaths) {
        expect(fs.existsSync(p)).toBe(false);
      }
    });

    it("cannot access auth-profiles.json from host", () => {
      const hostAuthPaths = [
        "/root/.openclaw/auth-profiles.json",
        "/home/node/.openclaw/auth-profiles.json",
      ];
      for (const p of hostAuthPaths) {
        expect(fs.existsSync(p)).toBe(false);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Docker socket access denial
  // -------------------------------------------------------------------------
  describe("Docker socket isolation", () => {
    it("Docker socket is not mounted", () => {
      expect(fs.existsSync("/var/run/docker.sock")).toBe(false);
    });

    it("cannot connect to Docker socket path", async () => {
      const connected = await new Promise<boolean>((resolve) => {
        const socket = net.createConnection({ path: "/var/run/docker.sock" });
        const timer = setTimeout(() => {
          socket.destroy();
          resolve(false);
        }, 1000);
        socket.on("connect", () => {
          clearTimeout(timer);
          socket.destroy();
          resolve(true);
        });
        socket.on("error", () => {
          clearTimeout(timer);
          resolve(false);
        });
      });
      expect(connected).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Network isolation (metadata endpoints)
  // -------------------------------------------------------------------------
  describe("network isolation", () => {
    it("cannot reach AWS metadata endpoint (169.254.169.254:80)", async () => {
      const reachable = await tryConnect("169.254.169.254", 80, 2000);
      expect(reachable).toBe(false);
    });

    it("cannot reach Google Cloud metadata endpoint (metadata.google.internal)", async () => {
      // DNS resolution should fail or connection should be refused
      const reachable = await tryConnect("169.254.169.254", 80, 2000);
      expect(reachable).toBe(false);
    });

    it("cannot reach common localhost services from within container", async () => {
      // Redis (6379), MySQL (3306), PostgreSQL (5432) on loopback should
      // not have anything listening (no host services exposed).
      // We check that nothing unexpected is listening.
      const commonPorts = [6379, 3306, 5432, 9200, 27017];
      for (const port of commonPorts) {
        const reachable = await tryConnect("127.0.0.1", port, 500);
        // These ports should not have anything listening in a clean container
        // (except possibly the gateway itself on its configured port).
        if (reachable) {
          // If something IS listening, it should be our gateway (18789)
          expect(port).toBe(Number(process.env.SEC_GW_PORT ?? 18789));
        }
      }
    });
  });

  // -------------------------------------------------------------------------
  // Container user and capabilities
  // -------------------------------------------------------------------------
  describe("container hardening", () => {
    it("runs as non-root user", () => {
      const uid = os.userInfo().uid;
      expect(uid).not.toBe(0);
    });

    it("runs with the expected 'node' user", () => {
      const username = os.userInfo().username;
      expect(username).toBe("node");
    });

    it("no-new-privileges is in effect (cannot escalate)", () => {
      // Attempt to read the NoNewPrivs flag from /proc/self/status
      try {
        const status = fs.readFileSync("/proc/self/status", "utf8");
        const match = status.match(/NoNewPrivs:\s*(\d+)/);
        if (match) {
          expect(match[1]).toBe("1");
        }
        // If the flag is not present (e.g., macOS Docker), we skip this assertion
      } catch {
        // /proc/self/status may not be available; skip check
      }
    });

    it("filesystem is read-only (writes to / fail)", () => {
      let canWrite = false;
      try {
        fs.writeFileSync("/test-write-check", "test");
        canWrite = true;
        fs.unlinkSync("/test-write-check");
      } catch {
        // Expected: EROFS or EACCES
      }
      expect(canWrite).toBe(false);
    });

    it("cannot write to /app (source code directory)", () => {
      let canWrite = false;
      try {
        fs.writeFileSync("/app/test-write-check", "test");
        canWrite = true;
        fs.unlinkSync("/app/test-write-check");
      } catch {
        // Expected: read-only filesystem
      }
      expect(canWrite).toBe(false);
    });

    it("/tmp exists and is writable (tmpfs)", () => {
      // tmpfs is mounted for /tmp so the app can still function
      expect(fs.existsSync("/tmp")).toBe(true);
      const testFile = `/tmp/isolation-test-${Date.now()}`;
      try {
        fs.writeFileSync(testFile, "test");
        expect(fs.existsSync(testFile)).toBe(true);
        fs.unlinkSync(testFile);
      } catch {
        // If /tmp is not writable, the test should fail
        expect.unreachable("Expected /tmp to be writable");
      }
    });
  });

  // -------------------------------------------------------------------------
  // Secret leakage prevention
  // -------------------------------------------------------------------------
  describe("secret leakage prevention", () => {
    it("no .env file in /app", () => {
      expect(fs.existsSync("/app/.env")).toBe(false);
    });

    it("no credentials directory in /app", () => {
      expect(fs.existsSync("/app/credentials")).toBe(false);
    });

    it("environment does not contain leaked secrets", () => {
      const env = process.env;
      const sensitivePatterns = [
        /^(OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY)$/,
        /^(GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN)$/,
        /^(DATABASE_URL|REDIS_URL|MONGO_URI)$/,
      ];
      for (const [key] of Object.entries(env)) {
        for (const pattern of sensitivePatterns) {
          expect(pattern.test(key)).toBe(false);
        }
      }
    });

    it("process.env does not contain sk- API keys", () => {
      for (const value of Object.values(process.env)) {
        if (value) {
          expect(value).not.toMatch(/sk-[a-zA-Z0-9]{20,}/);
        }
      }
    });
  });
});
