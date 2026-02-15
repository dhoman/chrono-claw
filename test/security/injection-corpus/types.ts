/**
 * Type definitions for the prompt-injection test corpus.
 *
 * Each corpus entry describes:
 *  - A categorized injection payload
 *  - The ingress path it targets
 *  - The expected security behavior when processed
 */

// ---------------------------------------------------------------------------
// Injection categories
// ---------------------------------------------------------------------------

export type InjectionCategory =
  | "direct" // "Ignore previous instructions and ..."
  | "indirect" // Malicious content embedded in webhook/email bodies
  | "polyglot" // Payloads mixing Markdown, HTML, JSON, shell metacharacters
  | "tool-confusion" // Trick agent into calling disallowed tools
  | "exfiltration" // Attempt to leak secrets via outbound messages or args
  | "ssrf"; // Attempt to fetch internal URLs

// ---------------------------------------------------------------------------
// Ingress sources (from test matrix)
// ---------------------------------------------------------------------------

export type IngressSource =
  | "webhook" // GitHub/GitLab/generic webhook
  | "email" // Gmail Pub/Sub
  | "api" // HTTP API (OpenAI-compat)
  | "channel" // Chat channels (WhatsApp, Telegram, etc.)
  | "hook" // Event-driven hook scripts
  | "webchat" // WebSocket client
  | "cli"; // CLI/system events

// ---------------------------------------------------------------------------
// Security expectations
// ---------------------------------------------------------------------------

export type SecurityExpectation =
  | "detection" // Suspicious pattern is detected by detectSuspiciousPatterns
  | "content-wrapped" // Content is wrapped with security boundaries
  | "tool-denied" // Disallowed tool call is blocked by policy
  | "secret-redacted" // Secret is redacted by DLP
  | "ssrf-blocked" // SSRF attempt is blocked by fetch-guard
  | "auth-enforced" // Auth gate prevents unauthorized access
  | "marker-sanitized"; // Boundary marker injection is sanitized

// ---------------------------------------------------------------------------
// Corpus entry
// ---------------------------------------------------------------------------

export type InjectionCorpusEntry = {
  /** Unique identifier for the test case. */
  id: string;
  /** Human-readable description of the attack scenario. */
  description: string;
  /** Injection category. */
  category: InjectionCategory;
  /** The raw injection payload text. */
  payload: string;
  /** Ingress path this payload targets. */
  ingress: IngressSource;
  /** Expected security behaviors when this payload is processed. */
  expectations: SecurityExpectation[];
  /** Whether detectSuspiciousPatterns should flag this payload. */
  shouldDetect: boolean;
  /** Optional: specific tools the payload tries to invoke. */
  targetTools?: string[];
  /** Optional: secrets embedded in the payload for DLP testing. */
  embeddedSecrets?: string[];
  /** Optional: SSRF target URLs in the payload. */
  ssrfTargets?: string[];
};
