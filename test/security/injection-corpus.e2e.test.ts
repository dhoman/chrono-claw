/**
 * E2E prompt-injection corpus tests.
 *
 * These tests spawn a real gateway process and send injection payloads
 * through the webhook ingress. They verify:
 *  1. Unauthenticated injection payloads are rejected (401/403).
 *  2. Authenticated injection payloads are accepted but processed safely (200).
 *  3. Injection payloads with secrets are accepted (DLP applies at outbound).
 *
 * NOTE: These tests require `pnpm build` first:
 *   pnpm build && pnpm vitest run --config vitest.e2e.config.ts test/security/injection-corpus.e2e.test.ts
 */

import { afterAll, describe, expect, it } from "vitest";
import type { InjectionCorpusEntry } from "./injection-corpus/types.js";
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
} from "./injection-corpus/payloads.js";

const E2E_TIMEOUT_MS = 120_000;

// ---------------------------------------------------------------------------
// Helper to build webhook body from a corpus entry
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
});
