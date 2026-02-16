/**
 * Structured security event logging.
 *
 * Provides typed emit functions for security-relevant denial/block events.
 * All events are logged via createSubsystemLogger("security/events") with
 * structured metadata including an `event` field for machine parsing.
 */

import { createSubsystemLogger, type SubsystemLogger } from "../logging/subsystem.js";

let _logger: SubsystemLogger | undefined;

function getLogger(): SubsystemLogger {
  if (!_logger) {
    _logger = createSubsystemLogger("security/events");
  }
  return _logger;
}

export function emitToolDenied(params: {
  tool: string;
  agent?: string;
  session?: string;
  reason: string;
}): void {
  getLogger().warn("tool denied", {
    event: "tool_denied",
    tool: params.tool,
    ...(params.agent ? { agent: params.agent } : {}),
    ...(params.session ? { session: params.session } : {}),
    reason: params.reason,
    consoleMessage: `tool denied: ${params.tool} (${params.reason})`,
  });
}

export function emitSsrfBlocked(params: {
  target: string;
  reason: string;
  auditContext?: string;
}): void {
  getLogger().warn("SSRF blocked", {
    event: "ssrf_blocked",
    target: params.target,
    reason: params.reason,
    ...(params.auditContext ? { auditContext: params.auditContext } : {}),
    consoleMessage: `blocked URL fetch (${params.auditContext ?? "url-fetch"}) target=${params.target} reason=${params.reason}`,
  });
}

export function emitDlpRedaction(params: {
  field: string;
  patternCount: number;
  location: string;
}): void {
  getLogger().info("DLP redaction applied", {
    event: "dlp_redaction",
    field: params.field,
    patternCount: params.patternCount,
    location: params.location,
    consoleMessage: `DLP redaction: ${params.patternCount} pattern(s) in ${params.field} (${params.location})`,
  });
}

export function emitInjectionDetected(params: {
  patterns: string[];
  session?: string;
  source?: string;
}): void {
  getLogger().warn("injection patterns detected", {
    event: "injection_detected",
    patternCount: params.patterns.length,
    patterns: params.patterns.slice(0, 5),
    ...(params.session ? { session: params.session } : {}),
    ...(params.source ? { source: params.source } : {}),
    consoleMessage: `injection patterns detected (${params.patterns.length}): ${params.patterns.slice(0, 3).join(", ")}`,
  });
}
