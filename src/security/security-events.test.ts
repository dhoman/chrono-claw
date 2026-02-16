import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockWarn = vi.fn();
const mockInfo = vi.fn();

vi.mock("../logging/subsystem.js", () => ({
  createSubsystemLogger: (name: string) => ({
    subsystem: name,
    warn: mockWarn,
    info: mockInfo,
    error: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
    fatal: vi.fn(),
    raw: vi.fn(),
    isEnabled: () => true,
    child: vi.fn(),
  }),
}));

// Must import after mock setup
const { emitToolDenied, emitSsrfBlocked, emitDlpRedaction, emitInjectionDetected } =
  await import("./security-events.js");

describe("security-events", () => {
  beforeEach(() => {
    mockWarn.mockClear();
    mockInfo.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("emitToolDenied", () => {
    it("emits structured tool_denied event", () => {
      emitToolDenied({ tool: "exec", reason: "profile:minimal", agent: "agent-1" });

      expect(mockWarn).toHaveBeenCalledOnce();
      const [message, meta] = mockWarn.mock.calls[0];
      expect(message).toBe("tool denied");
      expect(meta).toMatchObject({
        event: "tool_denied",
        tool: "exec",
        reason: "profile:minimal",
        agent: "agent-1",
      });
      expect(meta.consoleMessage).toContain("exec");
    });

    it("omits optional fields when not provided", () => {
      emitToolDenied({ tool: "write", reason: "denied" });

      const [, meta] = mockWarn.mock.calls[0];
      expect(meta.agent).toBeUndefined();
      expect(meta.session).toBeUndefined();
    });
  });

  describe("emitSsrfBlocked", () => {
    it("emits structured ssrf_blocked event", () => {
      emitSsrfBlocked({
        target: "http://169.254.169.254",
        reason: "link-local",
        auditContext: "web_fetch",
      });

      expect(mockWarn).toHaveBeenCalledOnce();
      const [message, meta] = mockWarn.mock.calls[0];
      expect(message).toBe("SSRF blocked");
      expect(meta).toMatchObject({
        event: "ssrf_blocked",
        target: "http://169.254.169.254",
        reason: "link-local",
        auditContext: "web_fetch",
      });
    });
  });

  describe("emitDlpRedaction", () => {
    it("emits structured dlp_redaction event", () => {
      emitDlpRedaction({ field: "text", patternCount: 3, location: "outbound" });

      expect(mockInfo).toHaveBeenCalledOnce();
      const [message, meta] = mockInfo.mock.calls[0];
      expect(message).toBe("DLP redaction applied");
      expect(meta).toMatchObject({
        event: "dlp_redaction",
        field: "text",
        patternCount: 3,
        location: "outbound",
      });
    });
  });

  describe("emitInjectionDetected", () => {
    it("emits structured injection_detected event", () => {
      emitInjectionDetected({
        patterns: ["ignore all previous", "system: override"],
        session: "hook:gmail:123",
        source: "email",
      });

      expect(mockWarn).toHaveBeenCalledOnce();
      const [message, meta] = mockWarn.mock.calls[0];
      expect(message).toBe("injection patterns detected");
      expect(meta).toMatchObject({
        event: "injection_detected",
        patternCount: 2,
        patterns: ["ignore all previous", "system: override"],
        session: "hook:gmail:123",
        source: "email",
      });
    });

    it("truncates patterns to 5 in metadata", () => {
      const manyPatterns = Array.from({ length: 10 }, (_, i) => `pattern-${i}`);
      emitInjectionDetected({ patterns: manyPatterns });

      const [, meta] = mockWarn.mock.calls[0];
      expect(meta.patterns).toHaveLength(5);
      expect(meta.patternCount).toBe(10);
    });
  });
});
