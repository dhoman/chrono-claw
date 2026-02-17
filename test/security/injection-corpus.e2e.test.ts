/**
 * E2E prompt-injection corpus tests.
 *
 * These tests spawn a real gateway process and send injection payloads
 * through the webhook ingress. They verify:
 *  1. Unauthenticated injection payloads are rejected (401/403).
 *  2. Authenticated injection payloads are accepted but processed safely (200).
 *  3. Injection payloads with secrets are accepted (DLP applies at outbound).
 *  4. Detection verification: detectSuspiciousPatterns flags detectable payloads.
 *  5. Content-wrapping verification: wrapExternalContent applies boundaries.
 *  6. DLP redaction verification: redactSensitiveText removes embedded secrets.
 *  7. SSRF blocking verification: private IPs and blocked hostnames are rejected.
 *  8. Tool-denied verification: filterToolsByPolicy blocks target tools.
 *
 * NOTE: These tests require `pnpm build` first:
 *   pnpm build && pnpm vitest run --config vitest.e2e.config.ts test/security/injection-corpus.e2e.test.ts
 */

import { afterAll, describe, expect, it } from "vitest";
import type { AnyAgentTool } from "../../src/agents/pi-tools.types.js";
import type { InjectionCorpusEntry } from "./injection-corpus/types.js";
import { filterToolsByPolicy } from "../../src/agents/pi-tools.policy.js";
import { isPrivateIpAddress, isBlockedHostname } from "../../src/infra/net/ssrf.js";
import { redactSensitiveText } from "../../src/logging/redact.js";
import {
  detectSuspiciousPatterns,
  wrapExternalContent,
} from "../../src/security/external-content.js";
import {
  type SecurityGatewayInstance,
  postWebhook,
  spawnSecurityGateway,
  stopSecurityGateway,
} from "./harness.js";
import {
  DIRECT_INJECTIONS,
  INDIRECT_INJECTIONS,
  POLYGLOT_INJECTIONS,
  EXFILTRATION_INJECTIONS,
  SSRF_INJECTIONS,
  TOOL_CONFUSION_INJECTIONS,
  API_INGRESS_INJECTIONS,
  HOOK_INGRESS_INJECTIONS,
  WEBCHAT_INGRESS_INJECTIONS,
  CLI_INGRESS_INJECTIONS,
  ALL_INJECTION_PAYLOADS,
  DETECTABLE_PAYLOADS,
} from "./injection-corpus/payloads.js";

const E2E_TIMEOUT_MS = 120_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildWebhookBody(entry: InjectionCorpusEntry): Record<string, unknown> {
  // If the payload is valid JSON (e.g. indirect injections), parse and use it
  try {
    const parsed = JSON.parse(entry.payload);
    if (typeof parsed === "object" && parsed !== null) {
      // Ensure it has the required text and mode fields for webhook dispatch
      return {
        ...parsed,
        text: parsed.text ?? entry.payload.slice(0, 200),
        mode: parsed.mode ?? "now",
      };
    }
  } catch {
    // Not JSON — wrap the raw payload text
  }

  return {
    text: entry.payload,
    mode: "now",
  };
}

function makeTool(name: string): AnyAgentTool {
  return {
    name,
    description: `mock ${name}`,
    parameters: { type: "object", properties: {} },
    execute: async () => ({ result: "ok" }),
  } as unknown as AnyAgentTool;
}

const ALL_TOOL_NAMES = [
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
];

const ALL_TOOLS = ALL_TOOL_NAMES.map(makeTool);

const MINIMAL_POLICY = {
  allow: ["read", "sessions_list", "sessions_history"],
  deny: ["exec", "write", "browser", "nodes", "cron", "gateway"],
};

const READER_POLICY = {
  allow: ["read", "sessions_list", "sessions_history"],
  deny: ["exec", "write", "edit", "browser", "nodes", "cron", "gateway"],
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("injection corpus E2E: gateway webhook", () => {
  let gw: SecurityGatewayInstance;

  afterAll(async () => {
    if (gw) {
      await stopSecurityGateway(gw);
    }
  });

  // -- Auth enforcement tests -----------------------------------------------

  describe("auth enforcement: injection payloads without token are rejected", () => {
    // Pick one representative payload from each category
    const representatives: InjectionCorpusEntry[] = [
      DIRECT_INJECTIONS[0],
      INDIRECT_INJECTIONS[0],
      POLYGLOT_INJECTIONS[0],
      TOOL_CONFUSION_INJECTIONS[0],
      EXFILTRATION_INJECTIONS[0],
      SSRF_INJECTIONS[0],
    ];

    it("boots gateway for auth tests", { timeout: E2E_TIMEOUT_MS }, async () => {
      gw = await spawnSecurityGateway({ name: "injection-auth" });
    });

    it.each(representatives.map((e) => [e.id, e]))(
      "%s: unauthenticated injection payload is rejected",
      async (_id, entry) => {
        const body = buildWebhookBody(entry);
        const res = await postWebhook(gw, "/hooks/wake", body, {
          "Content-Type": "application/json",
          // No auth token
        });
        expect([401, 403]).toContain(res.status);
      },
    );
  });

  // -- Authenticated injection tests (payload accepted, processed safely) ---

  describe("authenticated: injection payloads are accepted but safely handled", () => {
    const directSample = DIRECT_INJECTIONS.slice(0, 2);
    const indirectSample = INDIRECT_INJECTIONS.slice(0, 2);
    const polyglotSample = POLYGLOT_INJECTIONS.slice(0, 2);
    const toolSample = TOOL_CONFUSION_INJECTIONS.slice(0, 2);
    const exfilSample = EXFILTRATION_INJECTIONS.slice(0, 2);
    const ssrfSample = SSRF_INJECTIONS.slice(0, 2);

    const allSamples = [
      ...directSample,
      ...indirectSample,
      ...polyglotSample,
      ...toolSample,
      ...exfilSample,
      ...ssrfSample,
    ];

    it.each(allSamples.map((e) => [e.id, e]))(
      "%s: authenticated injection payload is accepted (200)",
      async (_id, entry) => {
        const body = buildWebhookBody(entry);
        const res = await postWebhook(gw, "/hooks/wake", body, {
          "Content-Type": "application/json",
          "x-openclaw-token": gw.hookToken,
        });
        // Gateway accepts the webhook — security enforcement happens at
        // the agent/tool layer, not at ingress acceptance.
        expect(res.status).toBe(200);
      },
    );
  });

  // -- Category-specific E2E assertions ------------------------------------

  describe("category coverage: at least one E2E test per category", () => {
    const categories = [
      { name: "direct", entry: DIRECT_INJECTIONS[0] },
      { name: "indirect", entry: INDIRECT_INJECTIONS[0] },
      { name: "polyglot", entry: POLYGLOT_INJECTIONS[0] },
      { name: "tool-confusion", entry: TOOL_CONFUSION_INJECTIONS[0] },
      { name: "exfiltration", entry: EXFILTRATION_INJECTIONS[0] },
      { name: "ssrf", entry: SSRF_INJECTIONS[0] },
    ];

    it.each(categories.map((c) => [c.name, c.entry]))(
      "%s: gateway processes injection payload without crash",
      async (_name, entry) => {
        const body = buildWebhookBody(entry);
        const res = await postWebhook(gw, "/hooks/wake", body, {
          "Content-Type": "application/json",
          "x-openclaw-token": gw.hookToken,
        });
        // Verify gateway is still healthy and responding
        expect(res.status).toBe(200);
        expect(gw.child.exitCode).toBeNull();
      },
    );
  });

  // -- All-ingress coverage: include API, hook, webchat, CLI payloads ------

  describe("all-ingress: additional ingress payloads accepted via webhook", () => {
    const additionalIngress = [
      ...API_INGRESS_INJECTIONS,
      ...HOOK_INGRESS_INJECTIONS,
      ...WEBCHAT_INGRESS_INJECTIONS,
      ...CLI_INGRESS_INJECTIONS,
    ];

    it.each(additionalIngress.map((e) => [e.id, e]))(
      "%s: additional ingress payload accepted with auth (200)",
      async (_id, entry) => {
        const body = buildWebhookBody(entry);
        const res = await postWebhook(gw, "/hooks/wake", body, {
          "Content-Type": "application/json",
          "x-openclaw-token": gw.hookToken,
        });
        expect(res.status).toBe(200);
      },
    );

    it("gateway remains healthy after all ingress payloads", async () => {
      expect(gw.child.exitCode).toBeNull();
    });
  });
});

// ---------------------------------------------------------------------------
// Security function verification suites (no gateway needed)
// ---------------------------------------------------------------------------

describe("injection corpus E2E: detection verification", () => {
  const detectablePayloads = ALL_INJECTION_PAYLOADS.filter((e) => e.shouldDetect);

  it("has detectable payloads to test", () => {
    expect(detectablePayloads.length).toBeGreaterThan(0);
    expect(DETECTABLE_PAYLOADS.length).toBe(detectablePayloads.length);
  });

  it.each(detectablePayloads.map((e) => [e.id, e]))(
    "%s: detectSuspiciousPatterns returns non-empty results",
    (_id, entry) => {
      const matches = detectSuspiciousPatterns(entry.payload);
      expect(matches.length).toBeGreaterThan(0);
    },
  );

  it("non-detectable payloads are correctly marked", () => {
    const nonDetectable = ALL_INJECTION_PAYLOADS.filter((e) => !e.shouldDetect);
    expect(nonDetectable.length).toBeGreaterThan(0);
  });
});

describe("injection corpus E2E: content-wrapping verification", () => {
  const wrappablePayloads = ALL_INJECTION_PAYLOADS.filter((e) =>
    e.expectations.includes("content-wrapped"),
  );

  it("has content-wrapped payloads to test", () => {
    expect(wrappablePayloads.length).toBeGreaterThan(0);
  });

  it.each(wrappablePayloads.map((e) => [e.id, e]))(
    "%s: wrapExternalContent adds security boundaries",
    (_id, entry) => {
      const wrapped = wrapExternalContent(entry.payload, { source: "webhook" });
      expect(wrapped).toContain("<<<EXTERNAL_UNTRUSTED_CONTENT>>>");
      expect(wrapped).toContain("<<<END_EXTERNAL_UNTRUSTED_CONTENT>>>");
      expect(wrapped).toContain("SECURITY NOTICE");
    },
  );

  it("marker-sanitized payloads have homoglyphs neutralized", () => {
    const markerPayloads = ALL_INJECTION_PAYLOADS.filter((e) =>
      e.expectations.includes("marker-sanitized"),
    );
    expect(markerPayloads.length).toBeGreaterThan(0);

    for (const entry of markerPayloads) {
      const wrapped = wrapExternalContent(entry.payload, { source: "webhook" });
      // The fullwidth Unicode markers should be sanitized to [[MARKER_SANITIZED]]
      expect(wrapped).toContain("[[MARKER_SANITIZED]]");
    }
  });
});

describe("injection corpus E2E: DLP redaction verification", () => {
  const dlpPayloads = ALL_INJECTION_PAYLOADS.filter(
    (e) => e.expectations.includes("secret-redacted") && e.embeddedSecrets?.length,
  );

  it("has DLP payloads to test", () => {
    expect(dlpPayloads.length).toBeGreaterThan(0);
  });

  it.each(dlpPayloads.map((e) => [e.id, e]))(
    "%s: redactSensitiveText removes embedded secrets",
    (_id, entry) => {
      const redacted = redactSensitiveText(entry.payload);
      for (const secret of entry.embeddedSecrets!) {
        expect(redacted).not.toContain(secret);
      }
    },
  );

  it("clean text is not altered by DLP", () => {
    const clean = "This is a normal message with no secrets.";
    expect(redactSensitiveText(clean)).toBe(clean);
  });
});

describe("injection corpus E2E: SSRF blocking verification", () => {
  const ssrfPayloads = ALL_INJECTION_PAYLOADS.filter(
    (e) => e.expectations.includes("ssrf-blocked") && e.ssrfTargets?.length,
  );

  it("has SSRF payloads to test", () => {
    expect(ssrfPayloads.length).toBeGreaterThan(0);
  });

  it.each(ssrfPayloads.map((e) => [e.id, e]))("%s: SSRF targets are blocked", (_id, entry) => {
    for (const target of entry.ssrfTargets!) {
      const url = new URL(target);
      const hostname = url.hostname;
      const blocked = isPrivateIpAddress(hostname) || isBlockedHostname(hostname);
      expect(blocked).toBe(true);
    }
  });
});

describe("injection corpus E2E: tool-denied verification", () => {
  const toolDeniedPayloads = ALL_INJECTION_PAYLOADS.filter(
    (e) => e.expectations.includes("tool-denied") && e.targetTools?.length,
  );

  it("has tool-denied payloads to test", () => {
    expect(toolDeniedPayloads.length).toBeGreaterThan(0);
  });

  it.each(toolDeniedPayloads.map((e) => [e.id, e]))(
    "%s: targetTools blocked under minimal policy",
    (_id, entry) => {
      const filtered = filterToolsByPolicy(ALL_TOOLS, MINIMAL_POLICY);
      const allowedNames = new Set(filtered.map((t) => t.name));
      for (const tool of entry.targetTools!) {
        expect(allowedNames.has(tool)).toBe(false);
      }
    },
  );

  it.each(toolDeniedPayloads.map((e) => [e.id, e]))(
    "%s: targetTools blocked under reader policy",
    (_id, entry) => {
      const filtered = filterToolsByPolicy(ALL_TOOLS, READER_POLICY);
      const allowedNames = new Set(filtered.map((t) => t.name));
      for (const tool of entry.targetTools!) {
        expect(allowedNames.has(tool)).toBe(false);
      }
    },
  );
});
