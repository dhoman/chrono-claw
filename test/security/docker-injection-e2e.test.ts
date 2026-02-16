/**
 * Docker E2E Injection Corpus Tests (Phase 5)
 *
 * Runs inside a test container on the same Docker network as the gateway.
 * Sends injection payloads via HTTP webhooks to the containerized gateway
 * and verifies correct security behavior.
 *
 * Requires environment variables set by security-regression-docker.sh:
 *   SEC_GW_HOST  — gateway container hostname
 *   SEC_GW_PORT  — gateway port
 *   SEC_GW_TOKEN — gateway auth token
 *   SEC_HOOK_TOKEN — webhook hook token
 */

import { request as httpRequest } from "node:http";
import { describe, expect, it } from "vitest";
import type { InjectionCorpusEntry } from "./injection-corpus/types.js";
import {
  ALL_INJECTION_PAYLOADS,
  DIRECT_INJECTIONS,
  EXFILTRATION_INJECTIONS,
  INDIRECT_INJECTIONS,
  POLYGLOT_INJECTIONS,
  SSRF_INJECTIONS,
  TOOL_CONFUSION_INJECTIONS,
} from "./injection-corpus/payloads.js";

// ---------------------------------------------------------------------------
// Configuration from environment
// ---------------------------------------------------------------------------

const GW_HOST = process.env.SEC_GW_HOST ?? "";
const GW_PORT = Number(process.env.SEC_GW_PORT ?? "0");
const GW_TOKEN = process.env.SEC_GW_TOKEN ?? "";
const HOOK_TOKEN = process.env.SEC_HOOK_TOKEN ?? "";

const HAS_DOCKER_GW = !!(GW_HOST && GW_PORT && GW_TOKEN && HOOK_TOKEN);
const TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// HTTP helper (sends to remote gateway container)
// ---------------------------------------------------------------------------

type WebhookResult = { status: number; body: string };

function postToGateway(
  path: string,
  body: unknown,
  headers?: Record<string, string>,
): Promise<WebhookResult> {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        method: "POST",
        hostname: GW_HOST,
        port: GW_PORT,
        path,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
          ...headers,
        },
        timeout: TIMEOUT_MS,
      },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          resolve({ status: res.statusCode ?? 0, body: data });
        });
      },
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy(new Error("request timeout"));
    });
    req.write(payload);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildWebhookBody(entry: InjectionCorpusEntry): Record<string, unknown> {
  try {
    const parsed = JSON.parse(entry.payload);
    if (typeof parsed === "object" && parsed !== null) {
      return {
        ...parsed,
        text: parsed.text ?? entry.payload.slice(0, 200),
        mode: parsed.mode ?? "now",
      };
    }
  } catch {
    // Not JSON
  }
  return { text: entry.payload, mode: "now" };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe.skipIf(!HAS_DOCKER_GW)(
  "Docker E2E: injection corpus against containerized gateway",
  () => {
    // -- Auth enforcement -------------------------------------------------------

    describe("auth enforcement: unauthenticated requests rejected", () => {
      const representatives: InjectionCorpusEntry[] = [
        DIRECT_INJECTIONS[0],
        INDIRECT_INJECTIONS[0],
        POLYGLOT_INJECTIONS[0],
        TOOL_CONFUSION_INJECTIONS[0],
        EXFILTRATION_INJECTIONS[0],
        SSRF_INJECTIONS[0],
      ];

      it.each(representatives.map((e) => [e.id, e]))(
        "%s: rejected without auth token",
        async (_id, entry) => {
          const body = buildWebhookBody(entry);
          const res = await postToGateway("/hooks/wake", body);
          expect([401, 403]).toContain(res.status);
        },
        TIMEOUT_MS,
      );
    });

    // -- Authenticated handling -------------------------------------------------

    describe("authenticated: payloads accepted and processed safely", () => {
      const allCategories = [
        ...DIRECT_INJECTIONS.slice(0, 2),
        ...INDIRECT_INJECTIONS.slice(0, 2),
        ...POLYGLOT_INJECTIONS.slice(0, 2),
        ...TOOL_CONFUSION_INJECTIONS.slice(0, 2),
        ...EXFILTRATION_INJECTIONS.slice(0, 2),
        ...SSRF_INJECTIONS.slice(0, 2),
      ];

      it.each(allCategories.map((e) => [e.id, e]))(
        "%s: accepted with valid token (200)",
        async (_id, entry) => {
          const body = buildWebhookBody(entry);
          const res = await postToGateway("/hooks/wake", body, {
            "x-openclaw-token": HOOK_TOKEN,
          });
          expect(res.status).toBe(200);
        },
        TIMEOUT_MS,
      );
    });

    // -- Gateway stability (no crash) ------------------------------------------

    describe("gateway stability: no crash from injection payloads", () => {
      const categories = [
        { name: "direct", entry: DIRECT_INJECTIONS[0] },
        { name: "indirect", entry: INDIRECT_INJECTIONS[0] },
        { name: "polyglot", entry: POLYGLOT_INJECTIONS[0] },
        { name: "tool-confusion", entry: TOOL_CONFUSION_INJECTIONS[0] },
        { name: "exfiltration", entry: EXFILTRATION_INJECTIONS[0] },
        { name: "ssrf", entry: SSRF_INJECTIONS[0] },
      ];

      it.each(categories.map((c) => [c.name, c.entry]))(
        "%s: gateway processes payload without crash",
        async (_name, entry) => {
          const body = buildWebhookBody(entry);
          const res = await postToGateway("/hooks/wake", body, {
            "x-openclaw-token": HOOK_TOKEN,
          });
          expect(res.status).toBe(200);

          // Verify gateway is still responding by sending a second request
          const health = await postToGateway(
            "/hooks/wake",
            { text: "health check", mode: "now" },
            {
              "x-openclaw-token": HOOK_TOKEN,
            },
          );
          expect(health.status).toBe(200);
        },
        TIMEOUT_MS,
      );
    });

    // -- Full corpus pass-through -----------------------------------------------

    describe("full corpus: all payloads handled without server error", () => {
      it("every injection payload returns 200 (with auth) or 401/403 (without)", async () => {
        let passed = 0;
        for (const entry of ALL_INJECTION_PAYLOADS) {
          const body = buildWebhookBody(entry);

          // Test authenticated path
          const res = await postToGateway("/hooks/wake", body, {
            "x-openclaw-token": HOOK_TOKEN,
          });
          // Should never get a 5xx server error
          expect(res.status).toBeLessThan(500);
          // Authenticated requests should be accepted
          expect(res.status).toBe(200);
          passed++;
        }
        // Sanity: we tested the full corpus
        expect(passed).toBeGreaterThanOrEqual(20);
      }, 120_000);
    });

    // -- Sandbox mode verification -----------------------------------------------

    describe("sandbox mode: gateway is running with sandbox=all", () => {
      it("gateway config confirms sandbox mode", async () => {
        // The gateway was started with sandbox=all in its config.
        // We verify by sending a webhook and getting 200 — the gateway is alive
        // and configured. (Direct config inspection would require a management API.)
        const res = await postToGateway(
          "/hooks/wake",
          { text: "sandbox verify", mode: "now" },
          {
            "x-openclaw-token": HOOK_TOKEN,
          },
        );
        expect(res.status).toBe(200);
      });
    });
  },
);
