import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import { request as httpRequest } from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import type { OpenClawConfig } from "../../src/config/types.openclaw.js";
import { sleep } from "../../src/utils.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SecurityTestConfig = {
  /** Human label for this test instance. */
  name?: string;
  /** Partial config overrides merged into the base config. */
  configOverrides?: Partial<OpenClawConfig>;
  /** Extra env vars passed to the gateway process. */
  env?: Record<string, string>;
  /** Max time (ms) to wait for the gateway port to open. Default 45_000. */
  startTimeoutMs?: number;
};

export type SecurityGatewayInstance = {
  name: string;
  port: number;
  hookToken: string;
  gatewayToken: string;
  homeDir: string;
  stateDir: string;
  configPath: string;
  child: ChildProcessWithoutNullStreams;
  stdout: string[];
  stderr: string[];
};

export type WebhookResponse = {
  status: number;
  json: unknown;
};

// ---------------------------------------------------------------------------
// Port helpers
// ---------------------------------------------------------------------------

export async function getFreePort(): Promise<number> {
  const srv = net.createServer();
  await new Promise<void>((resolve) => srv.listen(0, "127.0.0.1", resolve));
  const addr = srv.address();
  if (!addr || typeof addr === "string") {
    srv.close();
    throw new Error("failed to bind ephemeral port");
  }
  await new Promise<void>((resolve) => srv.close(() => resolve()));
  return addr.port;
}

export async function waitForPortOpen(
  proc: ChildProcessWithoutNullStreams,
  port: number,
  timeoutMs: number,
  chunksOut: string[] = [],
  chunksErr: string[] = [],
): Promise<void> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (proc.exitCode !== null) {
      const stdout = chunksOut.join("");
      const stderr = chunksErr.join("");
      throw new Error(
        `gateway exited before listening (code=${String(proc.exitCode)} signal=${String(proc.signalCode)})\n` +
          `--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}`,
      );
    }

    try {
      await new Promise<void>((resolve, reject) => {
        const socket = net.connect({ host: "127.0.0.1", port });
        socket.once("connect", () => {
          socket.destroy();
          resolve();
        });
        socket.once("error", (err) => {
          socket.destroy();
          reject(err);
        });
      });
      return;
    } catch {
      // keep polling
    }

    await sleep(25);
  }
  const stdout = chunksOut.join("");
  const stderr = chunksErr.join("");
  throw new Error(
    `timeout waiting for gateway to listen on port ${port}\n` +
      `--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}`,
  );
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

export function deepMergeConfig<T extends Record<string, unknown>>(
  base: T,
  override: Partial<T>,
): T {
  const result = { ...base } as Record<string, unknown>;
  for (const [key, value] of Object.entries(override)) {
    if (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      typeof result[key] === "object" &&
      result[key] !== null &&
      !Array.isArray(result[key])
    ) {
      result[key] = deepMergeConfig(
        result[key] as Record<string, unknown>,
        value as Record<string, unknown>,
      );
    } else {
      result[key] = value;
    }
  }
  return result as T;
}

// ---------------------------------------------------------------------------
// Gateway spawn / teardown
// ---------------------------------------------------------------------------

const DEFAULT_START_TIMEOUT_MS = 45_000;

export async function spawnSecurityGateway(
  opts: SecurityTestConfig = {},
): Promise<SecurityGatewayInstance> {
  const name = opts.name ?? `sec-${randomUUID().slice(0, 8)}`;
  const port = await getFreePort();
  const hookToken = `hook-${name}-${randomUUID()}`;
  const gatewayToken = `gw-${name}-${randomUUID()}`;
  const homeDir = await fs.mkdtemp(path.join(os.tmpdir(), `openclaw-sec-${name}-`));
  const configDir = path.join(homeDir, ".openclaw");
  await fs.mkdir(configDir, { recursive: true });
  const configPath = path.join(configDir, "openclaw.json");
  const stateDir = path.join(configDir, "state");

  const baseConfig: OpenClawConfig = {
    gateway: {
      port,
      bind: "loopback",
      auth: { mode: "token", token: gatewayToken },
    },
    hooks: { enabled: true, token: hookToken, path: "/hooks" },
    channels: {},
    tools: { profile: "coding" },
    agents: { defaults: { sandbox: { mode: "off" } } },
  };

  const merged = opts.configOverrides
    ? deepMergeConfig(
        baseConfig as Record<string, unknown>,
        opts.configOverrides as Record<string, unknown>,
      )
    : baseConfig;

  await fs.writeFile(configPath, JSON.stringify(merged, null, 2), "utf8");

  const stdout: string[] = [];
  const stderr: string[] = [];
  let child: ChildProcessWithoutNullStreams | null = null;

  try {
    child = spawn(
      "node",
      [
        "dist/index.js",
        "gateway",
        "--port",
        String(port),
        "--bind",
        "loopback",
        "--allow-unconfigured",
      ],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          HOME: homeDir,
          OPENCLAW_CONFIG_PATH: configPath,
          OPENCLAW_STATE_DIR: stateDir,
          OPENCLAW_GATEWAY_TOKEN: "",
          OPENCLAW_GATEWAY_PASSWORD: "",
          OPENCLAW_SKIP_CHANNELS: "1",
          OPENCLAW_SKIP_BROWSER_CONTROL_SERVER: "1",
          OPENCLAW_SKIP_CANVAS_HOST: "1",
          ...opts.env,
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (d) => stdout.push(String(d)));
    child.stderr?.on("data", (d) => stderr.push(String(d)));

    await waitForPortOpen(
      child,
      port,
      opts.startTimeoutMs ?? DEFAULT_START_TIMEOUT_MS,
      stdout,
      stderr,
    );

    return {
      name,
      port,
      hookToken,
      gatewayToken,
      homeDir,
      stateDir,
      configPath,
      child,
      stdout,
      stderr,
    };
  } catch (err) {
    if (child && child.exitCode === null && !child.killed) {
      try {
        child.kill("SIGKILL");
      } catch {
        // ignore
      }
    }
    await fs.rm(homeDir, { recursive: true, force: true });
    throw err;
  }
}

export async function stopSecurityGateway(inst: SecurityGatewayInstance): Promise<void> {
  if (inst.child.exitCode === null && !inst.child.killed) {
    try {
      inst.child.kill("SIGTERM");
    } catch {
      // ignore
    }
  }
  const exited = await Promise.race([
    new Promise<boolean>((resolve) => {
      if (inst.child.exitCode !== null) {
        return resolve(true);
      }
      inst.child.once("exit", () => resolve(true));
    }),
    sleep(5_000).then(() => false),
  ]);
  if (!exited && inst.child.exitCode === null && !inst.child.killed) {
    try {
      inst.child.kill("SIGKILL");
    } catch {
      // ignore
    }
  }
  await fs.rm(inst.homeDir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

export async function postWebhook(
  inst: SecurityGatewayInstance,
  hookPath: string,
  body: unknown,
  headers?: Record<string, string>,
): Promise<WebhookResponse> {
  const payload = JSON.stringify(body);
  const url = `http://127.0.0.1:${inst.port}${hookPath}`;
  const parsed = new URL(url);

  return await new Promise<WebhookResponse>((resolve, reject) => {
    const req = httpRequest(
      {
        method: "POST",
        hostname: parsed.hostname,
        port: Number(parsed.port),
        path: `${parsed.pathname}${parsed.search}`,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
          ...headers,
        },
      },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          let json: unknown = null;
          if (data.trim()) {
            try {
              json = JSON.parse(data);
            } catch {
              json = data;
            }
          }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}
