import { describe, expect, it, afterAll, beforeAll } from "vitest";
import type { AnyAgentTool } from "../../src/agents/pi-tools.types.js";
import {
  filterToolsByPolicy,
  resolveSubagentToolPolicy,
} from "../../src/agents/pi-tools.policy.js";
import { isSubagentSessionKey } from "../../src/routing/session-key.js";
import {
  GITHUB_SIGNED_SECRET,
  githubSignedWebhookBody,
  computeGitHubSignature,
} from "./fixtures/webhook-payloads.js";
import {
  spawnSecurityGateway,
  stopSecurityGateway,
  postWebhook,
  type SecurityGatewayInstance,
} from "./harness.js";

// ---------------------------------------------------------------------------
// Fake tool factory for tool-policy tests
// ---------------------------------------------------------------------------

function makeTool(name: string): AnyAgentTool {
  return {
    name,
    description: `mock ${name}`,
    parameters: { type: "object", properties: {} },
    execute: async () => ({ result: "ok" }),
  } as unknown as AnyAgentTool;
}

// ---------------------------------------------------------------------------
// Gateway-level trust-tier tests
// ---------------------------------------------------------------------------

describe("trust-tier: webhook auth", () => {
  let gw: SecurityGatewayInstance;

  beforeAll(async () => {
    gw = await spawnSecurityGateway({
      name: "trust-tier",
      configOverrides: {
        hooks: {
          enabled: true,
          mappings: [
            {
              id: "github-signed",
              match: { path: "github" },
              action: "agent",
              messageTemplate: "GitHub push to {{ref}}",
              webhookSignature: {
                type: "hmac-sha256",
                header: "x-hub-signature-256",
                secret: GITHUB_SIGNED_SECRET,
                prefix: "sha256=",
              },
            },
          ],
        },
      },
    });
  }, 60_000);

  afterAll(async () => {
    if (gw) {
      await stopSecurityGateway(gw);
    }
  });

  it("rejects unauthenticated POST to /hooks/wake", async () => {
    const res = await postWebhook(
      gw,
      "/hooks/wake",
      { text: "hello", mode: "now" },
      {}, // no auth header
    );
    expect(res.status).toBe(401);
  });

  it("accepts HMAC-authenticated webhook to signed mapping", async () => {
    const body = githubSignedWebhookBody;
    const rawBody = JSON.stringify(body);
    const signature = computeGitHubSignature(rawBody, GITHUB_SIGNED_SECRET);

    const res = await postWebhook(gw, "/hooks/github", body, {
      "X-Hub-Signature-256": signature,
      Authorization: "", // no global token
    });
    expect(res.status).toBe(202);
  });

  it("rejects HMAC-authenticated webhook with wrong signature", async () => {
    const body = githubSignedWebhookBody;
    const rawBody = JSON.stringify(body);
    const wrongSig = computeGitHubSignature(rawBody, "wrong-secret");

    const res = await postWebhook(gw, "/hooks/github", body, {
      "X-Hub-Signature-256": wrongSig,
      Authorization: "", // no global token
    });
    expect(res.status).toBe(401);
  });

  it("rejects HMAC-authenticated webhook with missing signature header", async () => {
    const res = await postWebhook(gw, "/hooks/github", githubSignedWebhookBody, {
      Authorization: "", // no global token, no signature header
    });
    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// Tool-policy: reader agent enforcement
// ---------------------------------------------------------------------------

describe("trust-tier: reader agent tool policy", () => {
  const readerPolicy = {
    allow: ["read", "sessions_list", "sessions_history"],
    deny: ["exec", "write", "browser", "nodes", "cron", "gateway"],
  };

  const allTools = [
    "read",
    "write",
    "edit",
    "exec",
    "browser",
    "sessions_list",
    "sessions_history",
    "sessions_send",
    "sessions_spawn",
    "cron",
    "gateway",
    "nodes",
    "web_search",
    "message",
  ].map(makeTool);

  it("allows only read, sessions_list, sessions_history", () => {
    const filtered = filterToolsByPolicy(allTools, readerPolicy);
    const names = filtered.map((t) => t.name).toSorted();
    expect(names).toEqual(["read", "sessions_history", "sessions_list"]);
  });

  it("blocks exec tool", () => {
    const filtered = filterToolsByPolicy(allTools, readerPolicy);
    expect(filtered.find((t) => t.name === "exec")).toBeUndefined();
  });

  it("blocks write tool", () => {
    const filtered = filterToolsByPolicy(allTools, readerPolicy);
    expect(filtered.find((t) => t.name === "write")).toBeUndefined();
  });

  it("blocks browser tool", () => {
    const filtered = filterToolsByPolicy(allTools, readerPolicy);
    expect(filtered.find((t) => t.name === "browser")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Subagent escalation prevention
// ---------------------------------------------------------------------------

describe("trust-tier: subagent escalation prevention", () => {
  it("isSubagentSessionKey identifies subagent session keys", () => {
    expect(isSubagentSessionKey("subagent:task-123")).toBe(true);
    expect(isSubagentSessionKey("agent:main:subagent:task-456")).toBe(true);
  });

  it("isSubagentSessionKey rejects non-subagent session keys", () => {
    expect(isSubagentSessionKey("main")).toBe(false);
    expect(isSubagentSessionKey("agent:main:main")).toBe(false);
    expect(isSubagentSessionKey("")).toBe(false);
    expect(isSubagentSessionKey(null)).toBe(false);
    expect(isSubagentSessionKey(undefined)).toBe(false);
  });

  it("resolveSubagentToolPolicy denies session management tools", () => {
    const policy = resolveSubagentToolPolicy();
    const sessionTools = [
      "sessions_spawn",
      "sessions_list",
      "sessions_history",
      "sessions_send",
    ].map(makeTool);

    const filtered = filterToolsByPolicy(sessionTools, policy);
    expect(filtered.length).toBe(0);
  });

  it("resolveSubagentToolPolicy denies admin and scheduling tools", () => {
    const policy = resolveSubagentToolPolicy();
    const adminTools = ["gateway", "cron", "agents_list"].map(makeTool);

    const filtered = filterToolsByPolicy(adminTools, policy);
    expect(filtered.length).toBe(0);
  });

  it("resolveSubagentToolPolicy allows basic work tools", () => {
    const policy = resolveSubagentToolPolicy();
    const workTools = ["read", "write", "edit", "exec", "browser", "web_search"].map(makeTool);

    const filtered = filterToolsByPolicy(workTools, policy);
    const names = filtered.map((t) => t.name).toSorted();
    expect(names).toEqual(["browser", "edit", "exec", "read", "web_search", "write"]);
  });

  it("subagent session key + sessions_spawn = forbidden", () => {
    // Verify that if we know it's a subagent, the default policy blocks sessions_spawn
    const key = "agent:main:subagent:task-789";
    expect(isSubagentSessionKey(key)).toBe(true);

    const policy = resolveSubagentToolPolicy();
    const spawnTool = [makeTool("sessions_spawn")];
    const filtered = filterToolsByPolicy(spawnTool, policy);
    expect(filtered.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Cross-tier tool inheritance: DEFAULT_SUBAGENT_TOOL_DENY coverage
// ---------------------------------------------------------------------------

describe("trust-tier: cross-tier tool inheritance", () => {
  const subagentPolicy = resolveSubagentToolPolicy();

  const denyList = [
    "sessions_list",
    "sessions_history",
    "sessions_send",
    "sessions_spawn",
    "gateway",
    "agents_list",
    "whatsapp_login",
    "session_status",
    "cron",
    "memory_search",
    "memory_get",
  ];

  it.each(denyList.map((name) => [name]))("subagent deny list blocks %s", (toolName) => {
    const tools = [makeTool(toolName)];
    const filtered = filterToolsByPolicy(tools, subagentPolicy);
    expect(filtered.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Reader-tier cannot access coding-tier tools
// ---------------------------------------------------------------------------

describe("trust-tier: reader cannot access coding-tier tools", () => {
  const readerPolicy = {
    allow: ["read", "sessions_list", "sessions_history"],
    deny: ["exec", "write", "edit", "browser", "nodes", "cron", "gateway"],
  };

  const codingTools = ["exec", "write", "edit", "browser", "nodes", "cron"];

  it.each(codingTools.map((name) => [name]))(
    "reader policy blocks coding-tier tool: %s",
    (toolName) => {
      const tools = [makeTool(toolName)];
      const filtered = filterToolsByPolicy(tools, readerPolicy);
      expect(filtered.length).toBe(0);
    },
  );

  it("reader policy allows read-only tools", () => {
    const readTools = ["read", "sessions_list", "sessions_history"].map(makeTool);
    const filtered = filterToolsByPolicy(readTools, readerPolicy);
    expect(filtered.length).toBe(3);
  });
});
