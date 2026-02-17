import { afterAll, describe, expect, it } from "vitest";
import type { AnyAgentTool } from "../../src/agents/pi-tools.types.js";
import { filterToolsByPolicy } from "../../src/agents/pi-tools.policy.js";
import { SANDBOX_MODES, TOOL_PROFILES, EXEC_APPROVAL_MODES, crossMatrix } from "./config-matrix.js";
import { genericJsonWebhook } from "./fixtures/webhook-payloads.js";
import {
  type SecurityGatewayInstance,
  postWebhook,
  spawnSecurityGateway,
  stopSecurityGateway,
} from "./harness.js";

const E2E_TIMEOUT_MS = 120_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTool(name: string): AnyAgentTool {
  return {
    name,
    description: `mock ${name}`,
    parameters: { type: "object", properties: {} },
    execute: async () => ({ result: "ok" }),
  } as unknown as AnyAgentTool;
}

const EXEC_TOOLS = ["exec", "apply_patch", "read", "write", "edit", "browser"].map(makeTool);

describe("security harness", () => {
  const instances: SecurityGatewayInstance[] = [];

  afterAll(async () => {
    for (const inst of instances) {
      await stopSecurityGateway(inst);
    }
  });

  it(
    "smoke: boot gateway, POST webhook with auth, assert 200",
    { timeout: E2E_TIMEOUT_MS },
    async () => {
      const inst = await spawnSecurityGateway({ name: "smoke" });
      instances.push(inst);

      const res = await postWebhook(inst, genericJsonWebhook.path, genericJsonWebhook.body, {
        ...genericJsonWebhook.headers,
        "x-openclaw-token": inst.hookToken,
      });
      expect(res.status).toBe(200);
      expect((res.json as { ok?: boolean } | undefined)?.ok).toBe(true);
    },
  );

  it(
    "auth rejection: POST webhook without token returns 401 or 403",
    { timeout: E2E_TIMEOUT_MS },
    async () => {
      const inst = await spawnSecurityGateway({ name: "auth-reject" });
      instances.push(inst);

      const res = await postWebhook(
        inst,
        genericJsonWebhook.path,
        genericJsonWebhook.body,
        genericJsonWebhook.headers,
      );
      expect([401, 403]).toContain(res.status);
    },
  );

  describe.each(SANDBOX_MODES)("config matrix: $label", (matrixEntry) => {
    it(
      `boots gateway and accepts authenticated hooks (${matrixEntry.label})`,
      { timeout: E2E_TIMEOUT_MS },
      async () => {
        const inst = await spawnSecurityGateway({
          name: `matrix-${matrixEntry.label.replace(/[^a-z0-9]/gi, "-")}`,
          configOverrides: matrixEntry.config,
        });
        instances.push(inst);

        const res = await postWebhook(inst, genericJsonWebhook.path, genericJsonWebhook.body, {
          ...genericJsonWebhook.headers,
          "x-openclaw-token": inst.hookToken,
        });
        expect(res.status).toBe(200);
        expect((res.json as { ok?: boolean } | undefined)?.ok).toBe(true);
      },
    );
  });

  // -- Full cross-matrix: sandbox x tools x exec (12 combos) ----------------

  describe("cross-matrix: all axes", () => {
    const matrix = crossMatrix(SANDBOX_MODES, TOOL_PROFILES, EXEC_APPROVAL_MODES);

    it("crossMatrix generates expected number of permutations", () => {
      expect(matrix.length).toBe(
        SANDBOX_MODES.length * TOOL_PROFILES.length * EXEC_APPROVAL_MODES.length,
      );
      expect(matrix.length).toBe(12);
    });

    it.each(matrix.map((e) => [e.label, e]))(
      "%s: boots gateway and accepts authenticated webhook",
      { timeout: E2E_TIMEOUT_MS },
      async (_label, entry) => {
        const inst = await spawnSecurityGateway({
          name: `cross-${entry.label.replace(/[^a-z0-9]/gi, "-").slice(0, 40)}`,
          configOverrides: entry.config,
        });
        instances.push(inst);

        const res = await postWebhook(inst, genericJsonWebhook.path, genericJsonWebhook.body, {
          ...genericJsonWebhook.headers,
          "x-openclaw-token": inst.hookToken,
        });
        expect(res.status).toBe(200);
      },
    );
  });
});

// ---------------------------------------------------------------------------
// Tool profile enforcement (unit-level, no gateway needed)
// ---------------------------------------------------------------------------

describe("security harness: tool profile enforcement", () => {
  it("minimal profile blocks exec tool", () => {
    const minimalPolicy = {
      allow: ["read", "sessions_list", "sessions_history"],
      deny: ["exec", "write", "browser", "nodes", "cron", "gateway"],
    };
    const filtered = filterToolsByPolicy(EXEC_TOOLS, minimalPolicy);
    const names = filtered.map((t) => t.name);
    expect(names).not.toContain("exec");
    expect(names).not.toContain("write");
    expect(names).not.toContain("browser");
    expect(names).toContain("read");
  });

  it("coding profile allows read/write/edit but denies browser/nodes", () => {
    const codingPolicy = {
      allow: ["read", "write", "edit", "exec", "sessions_list", "sessions_history"],
      deny: ["browser", "nodes"],
    };
    const filtered = filterToolsByPolicy(EXEC_TOOLS, codingPolicy);
    const names = filtered.map((t) => t.name);
    expect(names).toContain("read");
    expect(names).toContain("write");
    expect(names).toContain("edit");
    expect(names).not.toContain("browser");
  });

  it("full profile allows all tools (no deny)", () => {
    const fullPolicy = {
      allow: ["*"],
      deny: [],
    };
    const filtered = filterToolsByPolicy(EXEC_TOOLS, fullPolicy);
    expect(filtered.length).toBe(EXEC_TOOLS.length);
  });
});

// ---------------------------------------------------------------------------
// Exec approval mode propagation (unit-level)
// ---------------------------------------------------------------------------

describe("security harness: exec approval mode config", () => {
  it("deny config is well-formed", () => {
    const denyEntry = EXEC_APPROVAL_MODES.find((e) => e.label === "exec=deny");
    expect(denyEntry).toBeDefined();
    const approvals = denyEntry!.config.approvals as { exec?: { mode?: string } } | undefined;
    expect(approvals?.exec?.mode).toBe("deny");
  });

  it("allowlist config is well-formed with allowed commands", () => {
    const allowlistEntry = EXEC_APPROVAL_MODES.find((e) => e.label === "exec=allowlist");
    expect(allowlistEntry).toBeDefined();
    const approvals = allowlistEntry!.config.approvals as
      | {
          exec?: { mode?: string; allow?: string[] };
        }
      | undefined;
    expect(approvals?.exec?.mode).toBe("allowlist");
    expect(approvals?.exec?.allow).toContain("echo");
    expect(approvals?.exec?.allow).toContain("ls");
  });

  it("crossMatrix preserves exec approval mode across combinations", () => {
    const matrix = crossMatrix(SANDBOX_MODES.slice(0, 1), EXEC_APPROVAL_MODES);
    for (const entry of matrix) {
      const approvals = entry.config.approvals as { exec?: { mode?: string } } | undefined;
      expect(approvals?.exec?.mode).toBeDefined();
      expect(["deny", "allowlist"]).toContain(approvals?.exec?.mode);
    }
  });
});
