import { describe, expect, it, afterAll, beforeAll } from "vitest";
import type { AnyAgentTool } from "../../src/agents/pi-tools.types.js";
import { filterToolsByPolicy } from "../../src/agents/pi-tools.policy.js";
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
