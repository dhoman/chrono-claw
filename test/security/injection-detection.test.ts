/**
 * Prompt-injection corpus: unit tests for detection, tool policy, DLP, and SSRF.
 *
 * These tests verify each security layer independently without spawning a gateway.
 * They exercise:
 *  1. detectSuspiciousPatterns — catches injection attempts
 *  2. wrapExternalContent — sanitizes content with security boundaries
 *  3. filterToolsByPolicy — blocks disallowed tools under injection
 *  4. redactSensitiveText — redacts secrets in exfiltration payloads
 *  5. isPrivateIpAddress / isBlockedHostname — blocks SSRF targets
 *  6. Coverage matrix — verifies no empty cells
 */

import { describe, expect, it } from "vitest";
import type { AnyAgentTool } from "../../src/agents/pi-tools.types.js";
import { filterToolsByPolicy } from "../../src/agents/pi-tools.policy.js";
import { isPrivateIpAddress, isBlockedHostname } from "../../src/infra/net/ssrf.js";
import { redactSensitiveText } from "../../src/logging/redact.js";
import {
  detectSuspiciousPatterns,
  wrapExternalContent,
} from "../../src/security/external-content.js";
import { computeCoverageReport } from "./injection-corpus/matrix.js";
import {
  ALL_INJECTION_PAYLOADS,
  DETECTABLE_PAYLOADS,
  DIRECT_INJECTIONS,
  INDIRECT_INJECTIONS,
  POLYGLOT_INJECTIONS,
} from "./injection-corpus/payloads.js";

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
  "web_fetch",
  "message",
  "apply_patch",
  "canvas",
  "image",
  "memory_search",
  "memory_get",
  "session_status",
  "agents_list",
];

const ALL_TOOLS = ALL_TOOL_NAMES.map(makeTool);

// ---------------------------------------------------------------------------
// 1. Detection tests — detectSuspiciousPatterns
// ---------------------------------------------------------------------------

describe("injection corpus: detection", () => {
  it("corpus has at least 20 entries", () => {
    expect(ALL_INJECTION_PAYLOADS.length).toBeGreaterThanOrEqual(20);
  });

  it("has at least 3 entries per category (direct, indirect, polyglot)", () => {
    expect(DIRECT_INJECTIONS.length).toBeGreaterThanOrEqual(3);
    expect(INDIRECT_INJECTIONS.length).toBeGreaterThanOrEqual(3);
    expect(POLYGLOT_INJECTIONS.length).toBeGreaterThanOrEqual(3);
  });

  describe("detectable payloads are flagged", () => {
    it.each(DETECTABLE_PAYLOADS.map((e) => [e.id, e]))("%s is detected", (_id, entry) => {
      const patterns = detectSuspiciousPatterns(entry.payload);
      expect(patterns.length).toBeGreaterThan(0);
    });
  });

  describe("direct injections", () => {
    it.each(DIRECT_INJECTIONS.map((e) => [e.id, e]))(
      "%s: all direct injections are detected",
      (_id, entry) => {
        const patterns = detectSuspiciousPatterns(entry.payload);
        expect(patterns.length).toBeGreaterThan(0);
      },
    );
  });

  describe("indirect injections with known patterns", () => {
    const detectableIndirect = INDIRECT_INJECTIONS.filter((e) => e.shouldDetect);
    it.each(detectableIndirect.map((e) => [e.id, e]))(
      "%s: indirect injection with known pattern is detected",
      (_id, entry) => {
        const patterns = detectSuspiciousPatterns(entry.payload);
        expect(patterns.length).toBeGreaterThan(0);
      },
    );
  });

  describe("polyglot injections", () => {
    const detectablePolyglot = POLYGLOT_INJECTIONS.filter((e) => e.shouldDetect);
    it.each(detectablePolyglot.map((e) => [e.id, e]))(
      "%s: polyglot injection is detected",
      (_id, entry) => {
        const patterns = detectSuspiciousPatterns(entry.payload);
        expect(patterns.length).toBeGreaterThan(0);
      },
    );
  });
});

// ---------------------------------------------------------------------------
// 2. Content wrapping — wrapExternalContent
// ---------------------------------------------------------------------------

describe("injection corpus: content wrapping", () => {
  const wrappableEntries = ALL_INJECTION_PAYLOADS.filter((e) =>
    e.expectations.includes("content-wrapped"),
  );

  it.each(wrappableEntries.map((e) => [e.id, e]))(
    "%s: payload is wrapped with security boundaries",
    (_id, entry) => {
      const wrapped = wrapExternalContent(entry.payload, {
        source: entry.ingress === "email" ? "email" : "webhook",
      });

      // Verify security boundaries are present
      expect(wrapped).toContain("<<<EXTERNAL_UNTRUSTED_CONTENT>>>");
      expect(wrapped).toContain("<<<END_EXTERNAL_UNTRUSTED_CONTENT>>>");

      // The original payload content should be inside the boundaries
      // (may be sanitized if it contains markers)
      const startIdx = wrapped.indexOf("<<<EXTERNAL_UNTRUSTED_CONTENT>>>");
      const endIdx = wrapped.indexOf("<<<END_EXTERNAL_UNTRUSTED_CONTENT>>>");
      expect(startIdx).toBeLessThan(endIdx);
    },
  );

  describe("marker sanitization", () => {
    const markerEntries = ALL_INJECTION_PAYLOADS.filter((e) =>
      e.expectations.includes("marker-sanitized"),
    );

    it.each(markerEntries.map((e) => [e.id, e]))(
      "%s: boundary marker injection is sanitized",
      (_id, entry) => {
        const wrapped = wrapExternalContent(entry.payload, { source: "webhook" });

        // Should have exactly one start and one end marker
        const startMarkers = wrapped.match(/<<<EXTERNAL_UNTRUSTED_CONTENT>>>/g) ?? [];
        const endMarkers = wrapped.match(/<<<END_EXTERNAL_UNTRUSTED_CONTENT>>>/g) ?? [];
        expect(startMarkers).toHaveLength(1);
        expect(endMarkers).toHaveLength(1);

        // Injected markers should be sanitized
        expect(wrapped).toContain("[[MARKER_SANITIZED]]");
      },
    );
  });
});

// ---------------------------------------------------------------------------
// 3. Tool policy enforcement — filterToolsByPolicy
// ---------------------------------------------------------------------------

describe("injection corpus: tool policy enforcement", () => {
  // Minimal profile: only session_status allowed
  const minimalPolicy = {
    allow: ["session_status"],
  };

  // Reader profile: read-only
  const readerPolicy = {
    allow: ["read", "sessions_list", "sessions_history"],
    deny: ["exec", "write", "browser", "nodes", "cron", "gateway"],
  };

  // Coding profile: fs + runtime, no browser/nodes
  const codingPolicy = {
    allow: [
      "read",
      "write",
      "edit",
      "apply_patch",
      "exec",
      "sessions_list",
      "sessions_history",
      "sessions_send",
      "sessions_spawn",
      "session_status",
      "memory_search",
      "memory_get",
      "image",
    ],
  };

  const toolConfusionEntries = ALL_INJECTION_PAYLOADS.filter(
    (e) => e.targetTools && e.targetTools.length > 0,
  );

  describe("minimal profile blocks all dangerous tools", () => {
    it.each(toolConfusionEntries.map((e) => [e.id, e]))(
      "%s: target tool %s is blocked under minimal profile",
      (_id, entry) => {
        const filtered = filterToolsByPolicy(ALL_TOOLS, minimalPolicy);
        const allowedNames = new Set(filtered.map((t) => t.name));
        for (const tool of entry.targetTools!) {
          expect(allowedNames.has(tool)).toBe(false);
        }
      },
    );
  });

  describe("reader profile blocks write/exec/browser tools", () => {
    it.each(toolConfusionEntries.map((e) => [e.id, e]))(
      "%s: target tool is blocked under reader profile",
      (_id, entry) => {
        const filtered = filterToolsByPolicy(ALL_TOOLS, readerPolicy);
        const allowedNames = new Set(filtered.map((t) => t.name));
        for (const tool of entry.targetTools!) {
          expect(allowedNames.has(tool)).toBe(false);
        }
      },
    );
  });

  describe("coding profile blocks browser/cron/gateway tools", () => {
    it("browser is not in coding profile", () => {
      const filtered = filterToolsByPolicy(ALL_TOOLS, codingPolicy);
      expect(filtered.find((t) => t.name === "browser")).toBeUndefined();
    });

    it("cron is not in coding profile", () => {
      const filtered = filterToolsByPolicy(ALL_TOOLS, codingPolicy);
      expect(filtered.find((t) => t.name === "cron")).toBeUndefined();
    });

    it("gateway is not in coding profile", () => {
      const filtered = filterToolsByPolicy(ALL_TOOLS, codingPolicy);
      expect(filtered.find((t) => t.name === "gateway")).toBeUndefined();
    });
  });
});

// ---------------------------------------------------------------------------
// 4. DLP / secret redaction — redactSensitiveText
// ---------------------------------------------------------------------------

describe("injection corpus: DLP redaction", () => {
  const exfilEntries = ALL_INJECTION_PAYLOADS.filter(
    (e) => e.embeddedSecrets && e.embeddedSecrets.length > 0,
  );

  it.each(exfilEntries.map((e) => [e.id, e]))("%s: embedded secrets are redacted", (_id, entry) => {
    const redacted = redactSensitiveText(entry.payload);
    for (const secret of entry.embeddedSecrets!) {
      expect(redacted).not.toContain(secret);
    }
    // Verify original payload had the secret
    for (const secret of entry.embeddedSecrets!) {
      expect(entry.payload).toContain(secret);
    }
  });

  it("sk-* tokens are redacted", () => {
    const text = "API key: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz";
    const redacted = redactSensitiveText(text);
    expect(redacted).not.toContain("sk-proj-1234567890abcdefghijklmnopqrstuvwxyz");
  });

  it("ghp_* tokens are redacted", () => {
    const text = "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh";
    const redacted = redactSensitiveText(text);
    expect(redacted).not.toContain("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh");
  });

  it("Bearer tokens are redacted", () => {
    const text =
      "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const redacted = redactSensitiveText(text);
    expect(redacted).not.toContain(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    );
  });

  it("PEM private keys are redacted", () => {
    const text =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF5PBz2VUV\nbase64encodedkeydata1234567890abcdefghijklmnop\n-----END RSA PRIVATE KEY-----";
    const redacted = redactSensitiveText(text);
    expect(redacted).not.toContain("MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn");
    expect(redacted).toContain("-----BEGIN RSA PRIVATE KEY-----");
    expect(redacted).toContain("redacted");
  });

  it("clean text is not altered", () => {
    const text = "Hello, this is a normal message about project planning.";
    const redacted = redactSensitiveText(text);
    expect(redacted).toBe(text);
  });
});

// ---------------------------------------------------------------------------
// 5. SSRF blocking — isPrivateIpAddress / isBlockedHostname
// ---------------------------------------------------------------------------

describe("injection corpus: SSRF blocking", () => {
  describe("private IP addresses are blocked", () => {
    const privateIPs = [
      "127.0.0.1",
      "10.0.0.1",
      "192.168.1.1",
      "169.254.169.254",
      "172.16.0.1",
      "::1",
      "0.0.0.0",
    ];

    it.each(privateIPs)("%s is identified as private", (ip) => {
      expect(isPrivateIpAddress(ip)).toBe(true);
    });
  });

  describe("blocked hostnames are rejected", () => {
    const blockedHosts = [
      "localhost",
      "metadata.google.internal",
      "something.localhost",
      "service.local",
    ];

    it.each(blockedHosts)("%s is blocked", (hostname) => {
      expect(isBlockedHostname(hostname)).toBe(true);
    });
  });

  describe("SSRF targets from corpus are blocked", () => {
    const ssrfEntries = ALL_INJECTION_PAYLOADS.filter(
      (e) => e.ssrfTargets && e.ssrfTargets.length > 0,
    );

    it.each(ssrfEntries.map((e) => [e.id, e]))("%s: all SSRF targets are blocked", (_id, entry) => {
      for (const target of entry.ssrfTargets!) {
        const url = new URL(target);
        const hostname = url.hostname;
        const isBlocked = isPrivateIpAddress(hostname) || isBlockedHostname(hostname);
        expect(isBlocked).toBe(true);
      }
    });
  });

  describe("public addresses are not blocked", () => {
    const publicIPs = ["8.8.8.8", "1.1.1.1", "93.184.216.34"];

    it.each(publicIPs)("%s is not private", (ip) => {
      expect(isPrivateIpAddress(ip)).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// 6. Coverage matrix validation
// ---------------------------------------------------------------------------

describe("injection corpus: coverage matrix", () => {
  const report = computeCoverageReport();

  it("has at least 20 total entries", () => {
    expect(report.totalEntries).toBeGreaterThanOrEqual(20);
  });

  it("covers webhook ingress", () => {
    expect(report.coveredIngress).toContain("webhook");
  });

  it("covers email ingress", () => {
    expect(report.coveredIngress).toContain("email");
  });

  it("covers channel ingress", () => {
    expect(report.coveredIngress).toContain("channel");
  });

  it("covers api ingress", () => {
    expect(report.coveredIngress).toContain("api");
  });

  it("covers hook ingress", () => {
    expect(report.coveredIngress).toContain("hook");
  });

  it("covers webchat ingress", () => {
    expect(report.coveredIngress).toContain("webchat");
  });

  it("covers cli ingress", () => {
    expect(report.coveredIngress).toContain("cli");
  });

  it("has no uncovered ingress sources", () => {
    expect(report.uncoveredIngress).toEqual([]);
  });

  it("covers detection expectation", () => {
    expect(report.coveredExpectations).toContain("detection");
  });

  it("covers content-wrapped expectation", () => {
    expect(report.coveredExpectations).toContain("content-wrapped");
  });

  it("covers tool-denied expectation", () => {
    expect(report.coveredExpectations).toContain("tool-denied");
  });

  it("covers secret-redacted expectation", () => {
    expect(report.coveredExpectations).toContain("secret-redacted");
  });

  it("covers ssrf-blocked expectation", () => {
    expect(report.coveredExpectations).toContain("ssrf-blocked");
  });

  it("covers marker-sanitized expectation", () => {
    expect(report.coveredExpectations).toContain("marker-sanitized");
  });

  it("has at least 3 entries in each primary category", () => {
    expect(report.categoryCounts.direct).toBeGreaterThanOrEqual(3);
    expect(report.categoryCounts.indirect).toBeGreaterThanOrEqual(3);
    expect(report.categoryCounts.polyglot).toBeGreaterThanOrEqual(3);
    expect(report.categoryCounts["tool-confusion"]).toBeGreaterThanOrEqual(3);
    expect(report.categoryCounts.exfiltration).toBeGreaterThanOrEqual(3);
    expect(report.categoryCounts.ssrf).toBeGreaterThanOrEqual(3);
  });
});
