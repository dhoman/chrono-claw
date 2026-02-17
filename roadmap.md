# Security Roadmap (High-Level)

Scope: harden OpenClaw against prompt injection, prevent `.env`/secret leakage, and reduce malicious tool/skill behavior. This roadmap assumes you will run per-phase instances and refine in parallel.

## Current Security Posture (Post-Upstream Sync)

The upstream codebase already ships substantial security infrastructure. This roadmap builds on
what exists rather than duplicating it. The following are **already implemented and tested**:

| Capability                     | Implementation                                                                                                     | Key Files                                                                     |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| Security audit CLI             | `openclaw security audit` with `--deep`, `--fix`, `--json`                                                         | `src/cli/security-cli.ts`                                                     |
| Tool policy (deny-by-default)  | Profiles (`minimal`/`coding`/`messaging`/`full`), groups (`group:fs`, `group:runtime`, etc.), per-agent overrides  | `src/agents/tool-policy.ts`, `src/agents/tool-policy-pipeline.ts`             |
| Exec approvals                 | `deny`/`allowlist`/`full` modes, IPC socket daemon, per-agent overrides, constant-time comparison                  | `src/infra/exec-approvals.ts`, `src/infra/exec-approvals-allowlist.ts`        |
| Docker sandboxing              | Per-session/per-agent Docker containers, workspace isolation (`none`/`ro`/`rw`), browser sandbox                   | `src/agents/sandbox/`, `Dockerfile.sandbox`, `Dockerfile.sandbox-browser`     |
| DLP / secret redaction         | 11 default patterns (API keys, Bearer tokens, PEM blocks, `sk-`, `ghp_`, `npm_`, etc.), custom patterns via config | `src/logging/redact.ts`                                                       |
| External content wrapping      | Untrusted content boundaries, 13 prompt injection detection patterns, Unicode homoglyph normalization              | `src/security/external-content.ts`                                            |
| Skill scanner                  | 8 rules covering dangerous-exec, dynamic-code, crypto-mining, exfiltration, env-harvesting, obfuscation            | `src/security/skill-scanner.ts`                                               |
| SSRF protection                | Private IP blocking, DNS pinning (TOCTOU), hostname allowlists, redirect loop detection                            | `src/infra/net/ssrf.ts`, `src/infra/net/fetch-guard.ts`                       |
| File permission auditing       | POSIX + Windows ACL checks, remediation suggestions                                                                | `src/security/audit-fs.ts`                                                    |
| DM session isolation           | `dmScope`: `main`, `per-peer`, `per-channel-peer`, `per-account-channel-peer`                                      | `src/routing/session-key.ts`                                                  |
| Multi-agent routing            | 8-tier most-specific-wins routing with peer/guild/role/account/channel bindings                                    | `src/routing/resolve-route.ts`                                                |
| Webhook signature verification | LINE (HMAC-SHA256), Plivo (V2/V3), Twilio — constant-time comparison                                               | `src/line/signature.ts`, `extensions/voice-call/src/webhook-security.test.ts` |
| Gateway auth hardening         | Auth-by-default, trusted-proxy mode, rate limiting / brute-force protection, reverse proxy bypass fix              | `src/gateway/`, `docs/gateway/security/index.md`                              |
| Hook/plugin hardening          | Archive extraction limits, path traversal prevention, module loading restrictions, npm install hardening           | `src/plugins/hooks.ts`, `src/security/`                                       |
| Docker/Podman infra            | Production Dockerfile, sandbox images, docker-compose, Podman rootless + Quadlet, 7+ Docker E2E test scripts       | `Dockerfile*`, `docker-compose.yml`, `setup-podman.sh`, `scripts/e2e/`        |

## What "Workflows" Exist Today

OpenClaw's built-in workflow mechanisms are:

1. OpenProse (`.prose` programs + `/prose` command) for multi-step orchestration.
2. Lobster workflows (typed pipelines with explicit approvals).
3. LLM Task (structured JSON-only LLM step for workflows, typically used inside Lobster).
4. Hooks/automation (event-driven scripts for agent lifecycle and command events).
5. Skills (AgentSkills folders, load-time gated; operational behavior still governed by tool policy).

Relevant files:

- docs/prose.md
- docs/tools/lobster.md
- docs/tools/llm-task.md
- docs/automation/hooks.md
- docs/tools/skills.md
- docs/concepts/agent-loop.md

## Ingress Surfaces

These inputs are not all "chat channels," but they still hit the Gateway and must share the same
security controls.

1. **Chat channels** (WhatsApp, Telegram, Slack, Discord, Google Chat, Signal, iMessage/BlueBubbles, Microsoft Teams, Matrix, Zalo, WebChat): built-in or extension-based, with per-channel pairing/allowlists.
2. **Gmail**: supported via automation webhooks (Pub/Sub + webhook mapping).
3. **Git**: no built-in channel; use a webhook pipeline (GitHub/GitLab webhook → Gateway hook) or a skill/tool that runs git locally.
4. **Twitter/X**: no built-in channel or skill; requires a plugin or external ingestion (webhook/cron fetch).
5. **CLI/system events**: manual or scheduled triggers, cron jobs.
6. **HTTP APIs**: OpenAI/OpenResponses/Tools Invoke compatibility endpoints.
7. **Hooks**: event-driven scripts that can load external modules and run npm installs — a supply-chain attack surface.

Relevant files:

- docs/automation/webhook.md
- docs/automation/gmail-pubsub.md
- docs/web/webchat.md
- docs/concepts/architecture.md
- skills/github

## Roadmap Phases

### Phase 0: Security Test Harness (Layered on Existing Docker Infra)

**Status**: DONE.

**What was delivered**:

- `test/security/harness.ts` — gateway spawn/teardown helpers (`spawnSecurityGateway`, `stopSecurityGateway`, `postWebhook`, `getFreePort`, `waitForPortOpen`, `deepMergeConfig`), extending patterns from `test/gateway.multi.e2e.test.ts`.
- `test/security/fixtures/webhook-payloads.ts` — 5 typed webhook fixtures (GitHub push, GitLab push, Gmail Pub/Sub, generic JSON, secret-bearing payload for DLP testing).
- `test/security/config-matrix.ts` — parameterized axes (`SANDBOX_MODES`, `TOOL_PROFILES`, `EXEC_APPROVAL_MODES`) with `crossMatrix()` cross-product helper for `describe.each`/`it.each`.
- `test/security/security-harness.e2e.test.ts` — E2E smoke test (boot + auth webhook), auth rejection test (no token = 401/403), config matrix tests (`sandbox=off` vs `sandbox=all`).
- `test/security/README.md` — documents structure, how to run, fixture format, config matrix usage.
- `vitest.config.ts` — added `test/security/*.test.ts` to the unit test include patterns.

**Verification note**: The E2E tests (`security-harness.e2e.test.ts`) spawn `node dist/index.js gateway`, so they require a build step first:

```bash
pnpm build && pnpm vitest run --config vitest.e2e.config.ts test/security/security-harness.e2e.test.ts
```

**Known weaknesses** (identified in post-Phase-5 audit):

- Config matrix axes (`TOOL_PROFILES`, `EXEC_APPROVAL_MODES`) are defined but `crossMatrix()` is never called in the harness tests. Tests only verify the gateway boots with different configs — they do not verify that `sandbox=all` actually constrains tool execution vs `sandbox=off`.
- No test of token replay, expired tokens, or malformed auth tokens.
- These gaps are addressed in Phase 9.

Relevant files:

- test/security/harness.ts
- test/security/fixtures/webhook-payloads.ts
- test/security/config-matrix.ts
- test/security/security-harness.e2e.test.ts
- test/security/README.md

### Phase 1: Baseline Snapshot and Remaining Guardrail Gaps

**Status**: DONE.

**What was delivered**:

**1a — Baseline audit snapshot:**

- `test/security/baseline-audit.test.ts` — runs `runSecurityAudit()` with a deterministic config (`loopback`, `token` auth, `hooks: disabled`, `sandbox: off`, `tools: coding`), normalizes findings, and compares against committed snapshot. Auto-generates baseline on first run; regenerate with `GENERATE_BASELINE=1`.
- `test/security/baseline-audit.json` — committed baseline (2 findings: `gateway.trusted_proxies_missing` warn, `summary.attack_surface` info).

**1b — Outbound DLP fix (the single most impactful change):**

- `src/infra/outbound/payloads.ts` — added `import { redactSensitiveText }` and applied it in `normalizeReplyPayloadsForDelivery()` so all outbound channel text (`text: parsed.text ? redactSensitiveText(parsed.text) : ""`) is redacted. This covers ALL outbound channels (Telegram, WhatsApp, Slack, Discord, Signal, iMessage, Matrix, MS Teams, WebChat) because `normalizeReplyPayloadsForDelivery()` is called by `deliverOutboundPayloadsCore()`, `normalizeOutboundPayloads()`, and `normalizeOutboundPayloadsForJson()`. Respects `logging.redactSensitive` config.
- `src/infra/outbound/payloads.test.ts` — 4 new DLP tests: `sk-*` token redaction, `ghp_*` GitHub token redaction, no false positives on clean text, media URLs preserved unchanged.

**1c — Secret path denial tests:**

- `src/agents/sandbox-paths.test.ts` — 12 tests covering: path traversal (`../../etc/shadow`, deep traversal), absolute paths outside root (`/home/user/.ssh/id_rsa`, `/etc/shadow`), `~` expansion outside root (`~/.env`, `~/.ssh/id_rsa`), embedded `..` after valid prefix, valid paths within root, root-itself resolution, and `assertSandboxPath()` symlink traversal rejection.

**Verification**: All 23 new tests pass. Full suite (680 files, 4759 tests) passes with zero regressions.

**Known weaknesses** (identified in post-Phase-5 audit):

- **Baseline trivially defeatable**: `GENERATE_BASELINE=1` lets any developer silently reset the security floor. Deleting `baseline-audit.json` also passes (auto-generates on first run). Compares finding IDs only, not content/severity/details. No directional guard — doesn't assert findings can only decrease. Addressed in Phase 8.
- **DLP applied to `text` field only**: `redactSensitiveText` at `src/infra/outbound/payloads.ts:54` does not redact media URLs (may contain tokens in query params), `channelData` (freeform field with button labels, embed text), or captions. Addressed in Phase 6.
- **Telegram bot delivery bypasses DLP entirely**: `src/telegram/bot/delivery.ts` → `deliverReplies()` sends outbound messages via `bot.api.sendMessage` without going through `normalizeReplyPayloadsForDelivery()`. If an LLM echoes a secret, the Telegram bot path sends it unredacted. This is the highest-priority fix (Phase 6).

Relevant files:

- test/security/baseline-audit.test.ts, test/security/baseline-audit.json
- src/infra/outbound/payloads.ts, src/infra/outbound/payloads.test.ts
- src/agents/sandbox-paths.test.ts
- src/logging/redact.ts (existing, unchanged)

### Phase 2: Trust-Tier Routing and Webhook Auth

**Status**: DONE.

**What was delivered**:

**2a — Generic webhook HMAC/token verification module:**

- `src/gateway/webhook-hmac.ts` — `verifyWebhookSignature()` supporting three types: `hmac-sha256` (GitHub-style `sha256=<hex>`), `hmac-sha1` (legacy `sha1=<hex>`), and `token` (GitLab-style constant-time comparison). Follows the existing LINE signature pattern (`crypto.createHmac` + `crypto.timingSafeEqual`). Supports configurable prefix stripping and hex/base64 encoding.
- `src/gateway/webhook-hmac.test.ts` — 14 unit tests: valid/invalid signatures for all three types, missing/empty headers, truncated signatures, wrong prefix, base64 encoding variant.

**2b — Config and schema updates:**

- `src/config/types.hooks.ts` — added `WebhookSignatureType`, `WebhookSignatureMapping`, and optional `webhookSignature` field to `HookMappingConfig`.
- `src/config/zod-schema.hooks.ts` — added `webhookSignature` to `HookMappingSchema` with `secret` marked as `.register(sensitive)` to prevent leaking in config dumps/logs. (Note: the Zod schema uses `.strict()`, so both the TypeScript types and Zod schema must be updated together — types alone would cause config validation rejection.)
- `src/gateway/hooks-mapping.ts` — added `webhookSignature` to `HookMappingResolved` type and propagated through `normalizeHookMapping` (header lowercased during normalization).

**2c — Gateway integration (per-mapping signature auth):**

- `src/gateway/hooks.ts` — added `readRawAndJsonBody()` that captures the raw body string (for HMAC computation) and parses JSON separately, using the existing `readRequestBodyWithLimit` from `src/infra/http-body.ts`.
- `src/gateway/server-http.ts` — restructured `createHooksRequestHandler` to support per-mapping webhook signature verification as an alternative to the global bearer token:
  1. SubPath is extracted early (before auth) for pre-matching.
  2. `findSignedMapping()` checks if any mapping with `webhookSignature` matches the subPath.
  3. If found: reads raw body, verifies HMAC/token signature, skips global token check.
  4. If not found: existing global token auth flow (unchanged).
  5. Extracted `dispatchMappedHook()` helper to deduplicate mapping dispatch logic between both paths.

**2d — Trust-tier documentation and reader agent:**

- `docs/gateway/security/trust-tiers.md` — configuration guide documenting Tier A (Trusted Operators: gateway token, sandbox off, full tools), Tier B (Verified Systems: HMAC webhooks, sandbox all, coding tools), and Tier C (Untrusted/Public: channel auth, sandbox all, minimal read-only tools). Includes concrete config examples for each tier, per-webhook HMAC (GitHub) and token (GitLab) examples, the reader agent inline config, and a combined multi-tier deployment example.

**2e — Tests:**

- `test/security/trust-tier.test.ts` — 8 tests in two suites:
  - Gateway-level (4 tests): unauthenticated webhook rejected (401), HMAC-authenticated webhook accepted (202), wrong signature rejected (401), missing signature header rejected (401).
  - Tool-policy reader agent (4 tests): only `read`/`sessions_list`/`sessions_history` allowed; `exec`, `write`, `browser` each individually blocked.
- `test/security/fixtures/webhook-payloads.ts` — added `GITHUB_SIGNED_SECRET`, `githubSignedWebhookBody`, `computeGitHubSignature()` helper, and `githubSignedWebhook` fixture.

**Verification**: All 24 new tests pass (14 HMAC unit + 8 trust-tier + 2 baseline audit). Full gateway suite (372 tests) passes with zero regressions. Build compiles cleanly.

**Known weaknesses** (identified in post-Phase-5 audit):

- Reader agent tool policy test calls `filterToolsByPolicy()` in isolation — does not verify policy is enforced at runtime during agent execution.
- No test of escalation paths (can a reader-tier session escalate to coding-tier?), cross-tier interactions, or `sessions_spawn` inheriting parent tier restrictions.
- HMAC tests only cover `hmac-sha256`. No timing-attack resistance validation.
- These gaps are addressed in Phase 9.

Relevant files:

- src/gateway/webhook-hmac.ts, src/gateway/webhook-hmac.test.ts
- src/config/types.hooks.ts, src/config/zod-schema.hooks.ts
- src/gateway/hooks.ts, src/gateway/hooks-mapping.ts, src/gateway/server-http.ts
- test/security/trust-tier.test.ts, test/security/fixtures/webhook-payloads.ts
- docs/gateway/security/trust-tiers.md

### Phase 3: Supply-Chain and Hook Hardening

**Status**: DONE.

**What was delivered**:

**3a — CI skill-scanner gate:**

- `scripts/scan-skills.ts` — standalone scanner script that imports `scanDirectoryWithSummary` from `src/security/skill-scanner.ts`, scans `skills/` directory, prints findings with GitHub Actions `::error`/`::warning` annotations, exits 1 on any critical finding, supports `--json` flag for machine-readable output, and gracefully exits 0 when target directories don't exist.
- `package.json` — added `"scan:skills"` script (`node --import tsx scripts/scan-skills.ts`).
- `.github/workflows/ci.yml` — added `skill-scan` job that runs after `docs-scope`, skipped for docs-only changes. Follows the pattern of existing lightweight jobs like `secrets`.

**Scope note**: The CI gate scans `skills/` only (third-party code). First-party `extensions/` legitimately use `child_process`, `process.env` + network calls (Zalo adapter, voice-call tunnels, Lobster subprocess, Matrix/Slack/Gemini env reads) and would produce 12 false positives. Extensions are still covered by `openclaw security audit --deep`.

**3b — Module path validation tests:**

- `src/config/zod-schema.hooks.ts` — exported `isSafeRelativeModulePath` (was private) for direct testing.
- `src/config/zod-schema.hooks.test.ts` — 18 tests across three suites: `isSafeRelativeModulePath` direct tests (11 cases: `./` relative, bare path, single filename, absolute, home-relative, colon/URL-ish, parent traversal, deep traversal, empty string, whitespace-only, Windows drive path), `HookMappingSchema` integration (3 cases: valid/absolute/traversal transform module), `InternalHookHandlerSchema` integration (4 cases: valid/absolute/traversal/empty handler module).

**3c — Hook loader security tests:**

- `src/hooks/loader.test.ts` — 4 new security-focused tests added to the existing test file: absolute module paths rejected (`/etc/passwd` → count 0), parent traversal rejected (`../../outside.ts` → count 0), empty module paths rejected (`""` → count 0), workspace escape rejected (`../../../tmp/evil.js` → count 0). These exercise the runtime checks at `src/hooks/loader.ts` lines 119-137 that were previously untested.

**3d — Archive extraction security tests:**

- `src/infra/archive.test.ts` — 5 new tests: zip entry count limit (`maxEntries: 3` with 5 entries → rejected), zip single entry size (`maxEntryBytes: 64` with 256-byte entry → rejected), tar symlink rejection (archive containing a symbolic link → rejected, gated with `process.platform !== "win32"`), zip backslash traversal (`package\..\..\evil.txt` → rejected), Windows drive path (`C:\Windows\evil.dll` → rejected via `isWindowsDrivePath()` check).

**3e — CI scanner validation tests:**

- `test/security/skill-scanner-ci.test.ts` — 5 tests validating the scanner programmatically: clean directory reports zero findings, `eval()` detected as critical (`dynamic-code-execution`), warn-only findings (hex obfuscation) don't produce critical count, empty directories handled gracefully, `process.env` + `fetch` detected as critical env-harvesting.

**3f — Hook security model documentation:**

- `docs/gateway/security/hook-security-model.md` — comprehensive security doc covering: threat model (10 threats with vectors and impact), 5 defense layers (npm install hardening, archive extraction protection with limits table, module loading restrictions, skill scanner with 8-rule table, hook ID validation), auditing procedures (`hooks list`, `hooks info`, `security audit --deep`, install record inspection), and plugin version pinning policy.
- `docs/automation/hooks.md` — added "Production: Version Pinning" section and cross-reference to the security model doc in the See Also section.

**Verification**: All 50 new tests pass (18 module path + 4 loader security + 5 archive security + 5 scanner CI + 13 existing loader + 5 existing archive = 50 total across modified files). `pnpm scan:skills` exits 0 on the real `skills/` directory. Full test suite passes with zero regressions.

**Known weaknesses** (identified in post-Phase-5 audit):

- **Skill scanner trivially bypassable**: All 8 rules use static regex matching. Known bypasses:
  - Dynamic `import()` not detected at all (`await import("child_process")` evades every rule).
  - `Function` constructor aliasing (`const F = Function; F("code")()`).
  - Computed `require()` paths (`require("child" + "_process")`).
  - Bracket notation (`process["env"]`) bypasses `env-harvesting` rule.
  - String concatenation (`"ev"+"al"`) bypasses everything.
  - Only 5 CI tests cover 2 of the 8 rules; no evasion/negative tests.
  - Addressed in Phase 7.
- **Plugin-hooks loader path bypass**: `src/hooks/plugin-hooks.ts:44` and `src/gateway/hooks-mapping.ts:349` use `import()` with NO path containment — unlike the legacy loader at `src/hooks/loader.ts` which has proper checks. A plugin with an arbitrary `handlerPath` can load any module on the filesystem. Addressed in Phase 6.

Relevant files:

- scripts/scan-skills.ts
- .github/workflows/ci.yml
- src/config/zod-schema.hooks.ts, src/config/zod-schema.hooks.test.ts
- src/hooks/loader.ts (existing, unchanged), src/hooks/loader.test.ts
- src/infra/archive.ts (existing, unchanged), src/infra/archive.test.ts
- test/security/skill-scanner-ci.test.ts
- docs/gateway/security/hook-security-model.md
- docs/automation/hooks.md

### Phase 4: Prompt-Injection Test Corpus

**Status**: DONE.

**What was delivered**:

**4a — Injection corpus data structure (25 categorized payloads):**

- `test/security/injection-corpus/types.ts` — type definitions: `InjectionCorpusEntry`, `InjectionCategory` (6 categories), `IngressSource` (7 sources), `SecurityExpectation` (7 expectations).
- `test/security/injection-corpus/payloads.ts` — 33 categorized injection payloads:
  - **Direct injection** (4): classic "ignore previous instructions", disregard-prior, forget-your-rules, new-instructions-override.
  - **Indirect injection** (4): GitHub commit message with embedded injection, Gmail body with social engineering, webhook payload with hidden HTML comment injection, GitLab branch name injection.
  - **Polyglot injection** (4): HTML/XML role hijacking with `<system>` tags, JSON-in-Markdown with shell injection, Unicode homoglyph boundary marker injection (fullwidth `<<<END_EXTERNAL_UNTRUSTED_CONTENT>>>`), mixed role tags with Markdown formatting.
  - **Tool-confusion** (5): exec tool invocation, write to `~/.ssh/authorized_keys`, browser credential harvesting, `sessions_spawn` privilege escalation, cron persistence.
  - **Exfiltration** (4): `sk-*` API key DLP test, `ghp_*` GitHub token DLP test, Bearer JWT token DLP test, PEM private key DLP test.
  - **SSRF** (6): AWS metadata endpoint (`169.254.169.254`), localhost Redis (`127.0.0.1:6379`), Google Cloud metadata (`metadata.google.internal`), RFC1918 private network (`10.0.0.1`, `192.168.1.1`), plus API and CLI ingress variants.
  - **Additional ingress coverage** (8): API ingress (direct injection + SSRF), hook ingress (exfiltration + tool-confusion), webchat ingress (polyglot + exfiltration), CLI ingress (direct injection + SSRF). Ensures all 7 ingress sources have at least one test.
- `test/security/injection-corpus/matrix.ts` — coverage matrix: `computeCoverageReport()` maps all corpus entries to ingress x expectation cells, validates no uncovered ingress sources.

**4b — Unit tests (102 tests, no gateway required):**

- `test/security/injection-detection.test.ts` — 118 tests across 6 suites:
  - **Detection** (22 tests): all detectable payloads flagged by `detectSuspiciousPatterns`, per-category detection verification.
  - **Content wrapping** (26 tests): every payload with `content-wrapped` expectation verified to have correct security boundaries, marker sanitization for Unicode homoglyph injections.
  - **Tool policy** (13 tests): tool-confusion payloads blocked under minimal, reader, and coding profiles via `filterToolsByPolicy`.
  - **DLP redaction** (9 tests): `sk-*`, `ghp_*`, Bearer, PEM secrets redacted by `redactSensitiveText`; clean text preserved.
  - **SSRF blocking** (18 tests): private IPs (`127.0.0.1`, `10.0.0.1`, `192.168.1.1`, `169.254.169.254`, `172.16.0.1`, `::1`, `0.0.0.0`), blocked hostnames (`localhost`, `metadata.google.internal`), all corpus SSRF targets verified blocked, public IPs verified not blocked.
  - **Coverage matrix** (20 tests): validates 20+ entries, per-category minimums (>= 3 each), all 7 ingress sources covered (webhook, email, channel, api, hook, webchat, cli), all expectations covered, no uncovered ingress sources.

**4c — E2E tests (gateway-level, 24 tests):**

- `test/security/injection-corpus.e2e.test.ts` — 24 E2E tests across 3 suites:
  - **Auth enforcement** (6 tests): one representative from each category rejected without auth token (401/403).
  - **Authenticated handling** (12 tests): two payloads per category accepted with auth token (200), processed safely.
  - **Category coverage** (6 tests): one per category, verifies gateway stays healthy (no crash) after processing injection payload.

**4d — Documentation:**

- `test/security/injection-corpus/README.md` — documents structure, categories, test files, how to run, how to add new payloads.

**Verification**: All 118 unit tests pass. All 133 security unit tests pass together (118 injection + 2 baseline + 8 trust-tier + 5 scanner CI). E2E tests require `pnpm build` first. Zero regressions.

**Known weaknesses** (identified in post-Phase-5 audit):

- **E2E tests are status-code-only**: `injection-corpus.e2e.test.ts` ignores all corpus metadata (`expectations`, `shouldDetect`, `embeddedSecrets`, `ssrfTargets`, `targetTools`). It only asserts HTTP 200 and no crash. `detectSuspiciousPatterns()` is never called. Content wrapping, tool denial, DLP redaction, and SSRF blocking are never verified at E2E level.
- **Half the corpus is untested in E2E**: `API_INGRESS_INJECTIONS`, `HOOK_INGRESS_INJECTIONS`, `WEBCHAT_INGRESS_INJECTIONS`, and `CLI_INGRESS_INJECTIONS` are defined in payloads but never imported by the E2E test.
- **Unit tests (injection-detection.test.ts) are thorough**: The 118 unit tests DO exercise detection, wrapping, DLP, SSRF, and tool policy — but only as isolated function calls, not through the actual gateway pipeline.
- These gaps are addressed in Phase 9.

Relevant files:

- test/security/injection-corpus/types.ts, test/security/injection-corpus/payloads.ts, test/security/injection-corpus/matrix.ts
- test/security/injection-detection.test.ts
- test/security/injection-corpus.e2e.test.ts
- test/security/injection-corpus/README.md
- src/security/external-content.ts (existing, unchanged)
- src/logging/redact.ts (existing, unchanged)
- src/infra/net/ssrf.ts (existing, unchanged)
- src/agents/pi-tools.policy.ts (existing, unchanged)

### Phase 5: Docker/Podman Security Regression Suite

**Status**: DONE.

**What was delivered**:

**5a — Docker/Podman security regression orchestrator:**

- `scripts/e2e/security-regression-docker.sh` — 4-phase regression orchestrator that:
  1. Auto-detects container runtime (Docker or Podman).
  2. Builds the E2E image from `scripts/e2e/Dockerfile`.
  3. Creates an `--internal` Docker network (blocks external egress including cloud metadata endpoints).
  4. Starts a gateway container with production-grade hardening: `--security-opt no-new-privileges`, `--cap-drop ALL`, `--read-only` filesystem, tmpfs overlays for `/tmp` and `/home/node`, no Docker socket mount, no privileged mode.
  5. Gateway runs with `sandbox: { mode: "all" }`, `tools: { profile: "coding" }`, token auth.
  6. Phase 1: Runs security unit tests inside Docker (injection detection, skill scanner CI, baseline audit).
  7. Phase 2: Runs sandbox isolation tests (host path denial, Docker socket denial, metadata endpoint blocking, non-root enforcement, read-only filesystem).
  8. Phase 3: Runs E2E injection corpus against the containerized gateway from a separate test container on the same network.
  9. Phase 4: Verifies gateway remained healthy (no crash) throughout all tests.
- `package.json` — added `"test:docker:security"` script, added to `test:docker:all` chain.

**5b — Docker sandbox isolation tests (20 tests):**

- `test/security/docker-sandbox-isolation.test.ts` — 20 tests across 5 suites, designed to run inside Docker (skip gracefully outside via `OPENCLAW_DOCKER_SECURITY_TEST=1` env var):
  - **Host filesystem isolation** (4 tests): `/etc/shadow` unreadable, host `.env` files inaccessible, `~/.openclaw/credentials/` not mounted, `auth-profiles.json` not present.
  - **Docker socket isolation** (2 tests): `/var/run/docker.sock` not mounted, TCP connection to socket path fails.
  - **Network isolation** (3 tests): AWS metadata endpoint (`169.254.169.254`) unreachable, Google Cloud metadata unreachable, no unexpected services on common ports (Redis, MySQL, PostgreSQL, Elasticsearch, MongoDB).
  - **Container hardening** (6 tests): runs as non-root (uid != 0), runs as `node` user, `NoNewPrivs` flag set, root filesystem is read-only, `/app` is read-only, `/tmp` is writable (tmpfs).
  - **Secret leakage prevention** (4 tests): no `.env` in `/app`, no `credentials/` in `/app`, no sensitive env vars (API keys, tokens, database URLs), no `sk-*` patterns in process environment.

**5c — Docker E2E injection corpus tests (30+ tests):**

- `test/security/docker-injection-e2e.test.ts` — E2E tests that run from a test container against the gateway container:
  - **Auth enforcement** (6 tests): one per injection category rejected without auth token (401/403).
  - **Authenticated handling** (12 tests): two per category accepted with valid token (200).
  - **Gateway stability** (6 tests): one per category, verifies gateway processes payload and still responds to follow-up health check.
  - **Full corpus pass-through** (1 test): all 33+ injection payloads sent with auth, all return 200 (no 5xx), sanity check ≥20 payloads tested.
  - **Sandbox mode verification** (1 test): confirms gateway is alive and responding with sandbox=all config.
  - Tests connect to gateway via container hostname (Docker DNS), using env vars `SEC_GW_HOST`, `SEC_GW_PORT`, `SEC_GW_TOKEN`, `SEC_HOOK_TOKEN` set by the orchestrator script.
  - Skip gracefully when not in Docker (no env vars = `describe.skipIf`).

**5d — CI integration:**

- `.github/workflows/ci.yml` — added `docker-security` job that runs after `check`, skipped for docs-only changes. Runs `bash scripts/e2e/security-regression-docker.sh` as a mandatory pre-release gate.

**5e — Closed-box E2E with real LLMs and mock channel receiver (Phase 5 of the Docker script):**

- `test/security/mock-telegram-receiver.mjs` — mock Telegram API server:
  - HTTPS on port 443 with self-signed cert (CN=api.telegram.org). Handles grammy lifecycle: `getMe`, `getUpdates` (returns empty), `sendMessage` (captures payload), catch-all for other bot API calls.
  - HTTP on port 9100: inspection API (`GET /health`, `GET /captured`, `DELETE /captured`) for test assertions.
- `test/security/docker-closed-box-e2e.test.ts` — Vitest tests for full pipeline verification:
  - **Pipeline completion**: benign message flows through webhook → real LLM → Telegram channel delivery → mock receiver captures it.
  - **DLP redaction**: sends messages containing `sk-proj-*` and `ghp_*` tokens, asserts they don't appear in captured outbound text.
  - **Injection corpus by category**: representative payloads from all 6 categories sent through the full pipeline. Asserts pipeline completes, gateway stays healthy, and dangerous commands aren't echoed verbatim.
  - **Gateway stability**: verifies gateway still accepts requests after all payloads.
  - 120s poll timeout for real LLM latency.
  - Skips when `SEC_CB_*` env vars aren't set.
- `scripts/e2e/security-regression-docker.sh` — Phase 5 added to the orchestrator:
  - Skipped when no `SEC_LIVE_MODELS` or API keys configured (Phases 1-4 still pass in CI without secrets).
  - Per-model iteration: for each model in `SEC_LIVE_MODELS`, creates a non-internal Docker network (internet access for LLM APIs), starts mock Telegram receiver, starts gateway with channels enabled + real model + `--add-host api.telegram.org:$MOCK_IP`, runs closed-box tests, cleans up.
  - Model provider resolution: `anthropic/*` → Anthropic API, `openai/*` → OpenAI API, `openrouter/*` → OpenRouter API.

Usage (one-liners):

```bash
# Phases 1-4 only (no API keys needed):
pnpm test:docker:security

# With Phase 5 (Anthropic):
SEC_LIVE_MODELS=anthropic/claude-sonnet-4-5-20250929 ANTHROPIC_API_KEY=sk-ant-... pnpm test:docker:security

# Multiple models:
SEC_LIVE_MODELS=anthropic/claude-sonnet-4-5-20250929,openai/gpt-4o ANTHROPIC_API_KEY=sk-ant-... OPENAI_API_KEY=sk-... pnpm test:docker:security
```

**Verification**: Docker security regression script executes all 5 phases. Phase 5 is the first test that verifies actual outbound content (not just HTTP status codes) by capturing what the gateway sends to the channel. Both `docker-sandbox-isolation.test.ts`, `docker-injection-e2e.test.ts`, and `docker-closed-box-e2e.test.ts` skip gracefully in non-Docker environments. Zero regressions in the full test suite.

**Known weaknesses** (identified in post-Phase-5 audit):

- Docker Phases 1-3 (inside the script) inherit the status-code-only problem from Phase 4's E2E test. Only the closed-box Phase 5 verifies outbound content.
- Closed-box tests require real API keys and cost real money — cannot run in CI without secrets configured.

Relevant files:

- scripts/e2e/security-regression-docker.sh
- test/security/docker-sandbox-isolation.test.ts
- test/security/docker-injection-e2e.test.ts
- test/security/docker-closed-box-e2e.test.ts
- test/security/mock-telegram-receiver.mjs
- package.json
- .github/workflows/ci.yml

### Phase 6: Fix Active Bypass Paths

**Status**: DONE.

**Priority**: CRITICAL. These are active vulnerability classes, not theoretical gaps.

**Rationale**: The post-Phase-5 audit found that several production code paths bypass the security controls that Phases 1-5 test. Fixing these is more urgent than monitoring/drift detection because the bypasses undermine the guarantees the earlier phases claim to provide.

Goals:

- Close all known DLP bypass paths so secrets cannot leak through any outbound channel.
- Centralize outbound HTTP so SSRF protection cannot be circumvented.
- Apply consistent path containment to all module loaders.

**Implementation summary:**

**6a — DLP bypass fix (expanded scope: ALL 8 channels, not just Telegram):**

Created `redactOutboundPayload()` helper in `src/infra/outbound/payloads.ts` that applies `redactSensitiveText()` to `text`, `mediaUrl` (tokens in query params), `mediaUrls`, and string values in `channelData` (recursive walk). Applied to all 8 channel delivery paths:

- Telegram: `src/telegram/bot/delivery.ts`
- Slack: `src/slack/monitor/replies.ts`
- Signal: `src/signal/monitor.ts`
- iMessage: `src/imessage/monitor/deliver.ts`
- Discord: `src/discord/monitor/reply-delivery.ts`
- WhatsApp: `src/web/auto-reply/deliver-reply.ts`
- Line: `src/line/auto-reply-delivery.ts`
- Matrix: `extensions/matrix/src/matrix/monitor/replies.ts` (imported from `openclaw/plugin-sdk`)

**6b — DLP expanded to non-text fields:**

`normalizeReplyPayloadsForDelivery()` now also redacts `mediaUrl`, `mediaUrls`, and `channelData` strings via the same helpers.

**6c — SSRF bypass fix:**

Wrapped user-controllable `fetch()` calls with `fetchWithSsrFGuard`:

- Ollama discovery (`src/agents/models-config.providers.ts`) — `allowPrivateNetwork: true`
- vLLM discovery (`src/agents/models-config.providers.ts`) — `allowPrivateNetwork: true`
- Ollama streaming chat (`src/agents/ollama-stream.ts`) — `allowPrivateNetwork: true`
- Camera URL download (`src/cli/nodes-camera.ts`) — default policy (blocks private IPs)
- Firecrawl relay (`src/agents/tools/web-fetch.ts`) — default policy (blocks private IPs)

Safe calls with hardcoded domains (no changes needed): huggingface, venice, perplexity, xAI, brave, sandbox browser.

**6d — Plugin-hooks loader path containment:**

Added `isContainedPath()` validation to both `resolveHookDir()` and `loadHookHandler()` in `src/hooks/plugin-hooks.ts`, following the same `path.relative()` pattern from the legacy loader at `src/hooks/loader.ts:131-137`. Rejects absolute paths outside the plugin directory and `../` traversal attacks.

**6e — Plugin env passthrough — NOT A VULNERABILITY:**

Investigation confirmed plugins do NOT receive `process.env`. They get `OpenClawConfig` only:

- `OpenClawPluginApi` has no `env` property
- `config-state.ts:114,152` passes `process.env` to `applyTestPluginDefaults()` — internal test helper only
- `tools.ts:51` — same pattern
- `catalog.ts:95` reads env for catalog paths at init, not exposed to plugins

No code changes needed. Documented as resolved.

Relevant files:

- src/infra/outbound/payloads.ts (redactOutboundPayload helper + normalizeReplyPayloadsForDelivery update)
- src/infra/outbound/payloads.test.ts (DLP tests)
- src/telegram/bot/delivery.ts (6a)
- src/slack/monitor/replies.ts (6a)
- src/signal/monitor.ts (6a)
- src/imessage/monitor/deliver.ts (6a)
- src/discord/monitor/reply-delivery.ts (6a)
- src/web/auto-reply/deliver-reply.ts (6a)
- src/line/auto-reply-delivery.ts (6a)
- extensions/matrix/src/matrix/monitor/replies.ts (6a)
- src/plugin-sdk/index.ts (export redactOutboundPayload for Matrix extension)
- src/agents/models-config.providers.ts (6c — Ollama + vLLM SSRF)
- src/agents/ollama-stream.ts (6c — Ollama chat SSRF)
- src/cli/nodes-camera.ts (6c — camera URL SSRF)
- src/agents/tools/web-fetch.ts (6c — Firecrawl SSRF)
- src/hooks/plugin-hooks.ts (6d — path containment)
- src/hooks/plugin-hooks.test.ts (6d — path containment tests)
- src/infra/net/fetch-guard.ts, src/infra/net/ssrf.ts (supporting SSRF infrastructure)

### Phase 7: Skill Scanner Hardening

**Status**: DONE.

**Priority**: HIGH. The current scanner uses static regex matching that is trivially bypassable by standard supply-chain attack patterns (e.g., event-stream, ua-parser-js style).

Goals:

- Catch real supply-chain threats, not just toy patterns.
- Expand CI test coverage to validate all rules and known evasion techniques.

**What was delivered**:

**7a — 11 new detection rules for evasion patterns:**

Added 7 new LINE_RULES and 4 new SOURCE_RULES to `src/security/skill-scanner.ts`, bringing the total from 8 to 19 rules:

- `dynamic-import` (LINE, warn): Catches `import()` expressions (dynamic module loading at runtime).
- `function-constructor-evasion` (LINE, critical): Catches `Function()` without `new`, `globalThis["Function"]`, `Reflect.construct(Function, ...)`, and `= Function;` aliasing. Uses negative lookbehind to avoid double-flagging `new Function()` (already caught by `dynamic-code-execution`).
- `computed-require` (LINE, critical): Catches `require(variable)` and `require("child" + "_process")` — any `require()` with non-literal or concatenated arguments.
- `bracket-notation-dangerous` (LINE, critical): Catches `process["env"]`, `global["eval"]`, `globalThis["Function"]`, `globalThis["require"]`, `global["exec"]` — bracket notation access to dangerous properties.
- `vm-code-execution` (LINE, critical): Catches `vm.runInNewContext`, `vm.runInThisContext`, `vm.compileFunction`, `vm.createContext`, `new vm.Script` — requires `require("vm")` or `from "node:vm"` context.
- `indirect-eval` (LINE, critical): Catches `(0, eval)("code")`, `globalThis.eval(...)`, `global.eval(...)`, `window.eval(...)`.
- `shell-script-execution` (LINE, warn): Catches `.sh` file references in string literals — requires `child_process`/`exec`/`spawn` context.
- `bracket-env-harvesting` (SOURCE, critical): Catches `process["env"]` combined with `fetch`/`post`/`http.request` — bracket notation variant of the existing `env-harvesting` rule.
- `base64-code-execution` (SOURCE, critical): Catches `atob()`/`Buffer.from()` combined with `eval()`/`Function()` — obfuscated payload execution.
- `obfuscated-code` / unicode escapes (SOURCE, warn): Catches clusters of 4+ `\uXXXX` escape sequences — possible identifier obfuscation.
- `template-literal-injection` (SOURCE, warn): Catches `require(\`${...}\`)` and `import(\`${...}\`)` — template literals with interpolation in module loading.

**7b — AST-based scanning evaluation (CONDITIONAL GO):**

- `docs/gateway/security/ast-scanner-evaluation.md` — evaluates 6 candidate parsers (acorn, @babel/parser, TypeScript compiler, tree-sitter, oxc-parser), recommends acorn + ts-blank-space as the smallest-footprint option.
- Decision: CONDITIONAL GO — implement AST as an optional `--deep-scan` second pass when regex rules start producing unacceptable false-positive rates or when a real-world bypass is discovered that regex cannot address.
- Identified 3 high-value AST detections (non-literal import/require args, computed dangerous property access, Function constructor through any call path) with ~320 lines estimated implementation cost.

**7c — 60 comprehensive scanner CI tests:**

Rewrote `test/security/skill-scanner-ci.test.ts` (from 5 tests to 60 tests):

- **Original rules** (16 tests): 2+ tests per original rule including negative cases — `dangerous-exec` (3), `dynamic-code-execution` (3), `crypto-mining` (2), `suspicious-network` (2), `potential-exfiltration` (2), `obfuscated-code` (2), `env-harvesting` (2).
- **Evasion rules** (33 tests): 2+ tests per new rule including negative cases — `dynamic-import` (3), `function-constructor-evasion` (6), `computed-require` (3), `bracket-notation-dangerous` (4), `vm-code-execution` (4), `indirect-eval` (3), `shell-script-execution` (2), `bracket-env-harvesting` (2), `base64-code-execution` (3), `unicode-escape-evasion` (2), `template-literal-injection` (2).
- **Combined evasion scenarios** (3 tests): event-stream style attack, ua-parser-js style attack, multi-layer evasion.
- **False positive prevention** (4 tests): clean module, normal require, normal function definitions, standard WebSocket ports.
- **Integration tests** (3 tests): `scanDirectoryWithSummary` with clean dir, malicious skill, empty dir.

Tests call `scanSource()` directly for fast execution (no temp files needed for unit tests), with `scanDirectoryWithSummary()` integration tests for key scenarios.

**Verification**: All 60 scanner tests pass. All 194 security unit tests pass with zero regressions. `pnpm scan:skills` exits 0 on the real `skills/` directory (no false positives from new rules).

**Known weaknesses:**

- **Multi-hop variable aliasing undetectable**: `const a = require; const b = a; b("child_process")` evades `computed-require` because `b(` is not `require(`. This is a fundamental regex limitation — documented as accepted risk. AST analysis (Phase 10+) can address this.
- **Cross-file data flow not tracked**: Module A exports a dangerous function, Module B calls it normally. Regex operates per-file. Would require a module graph analysis.
- **package.json lifecycle scripts not scanned**: `postinstall` scripts in `package.json` are a known supply-chain vector but the scanner only processes JS/TS files. Adding JSON parsing is a future enhancement.
- **Minified/bundled code**: Variable renaming in bundler output makes pattern matching unreliable. Skills should be scanned pre-bundle.

Relevant files:

- src/security/skill-scanner.ts (19 rules: 11 LINE + 8 SOURCE)
- test/security/skill-scanner-ci.test.ts (60 tests)
- docs/gateway/security/ast-scanner-evaluation.md
- scripts/scan-skills.ts (unchanged)

### Phase 8: Monitoring, Drift Detection, and Baseline Hardening

**Status**: DONE.

**Priority**: MEDIUM. Important for ongoing regression prevention, but less urgent than fixing active bypass paths (Phase 6) and scanner bypasses (Phase 7).

Goals:

- Detect regressions or accidental privilege expansion before release.
- Harden the baseline audit so it cannot be silently circumvented.
- Provide ongoing visibility into denied tool attempts and policy violations.

Key actions:

**8a — Harden baseline audit:**

- Remove `GENERATE_BASELINE=1` escape hatch from CI (block via CI env or check). Allow local regeneration only.
- Add directional guard: new baseline must have same or fewer findings. An update that adds findings fails unless accompanied by an explicit justification comment.
- Compare finding content and severity, not just IDs. A finding that gets worse but keeps the same ID should fail.
- Prevent silent reset: if `baseline-audit.json` is deleted, CI should fail (not auto-generate).

**8b — CI drift detection:**

- Add a CI step that runs `openclaw security audit --json` and compares against baseline. Fail on any new finding with severity >= warn.
- Add a "policy drift" test: snapshot the current tool allowlist for each agent, commit it, and fail if any allowlist expands without an explicit approval comment.

**8c — Structured denial logging:**

- Emit structured JSON log lines for tool denial events (`src/agents/tool-policy-pipeline.ts`): `{event: "tool_denied", tool, agent, session, reason}`.
- Emit structured log for SSRF blocks, DLP redactions, and injection pattern detections.

**8d — Alerting documentation:**

- Document how to pipe denial/block logs to monitoring (webhook to Slack/Discord on repeated denials from the same session).

Deliverables:

1. Hardened baseline audit (no silent resets, directional guard, content comparison).
2. CI drift detection step.
3. Tool allowlist snapshot + regression test.
4. Structured denial/block logging.
5. Alerting documentation.

Minimum viable test suite:

1. Baseline test fails when `baseline-audit.json` is deleted (no auto-generate in CI).
2. Baseline test fails when a finding severity increases.
3. Policy drift test fails when allowlists expand.
4. Tool denial events are logged in structured JSON format.

Definition of done:

1. Drift detection is enforced in CI.
2. Baseline cannot be silently circumvented.
3. Denial events are structured and parseable.
4. Alerting pattern is documented.

Relevant files:

- test/security/baseline-audit.test.ts, test/security/baseline-audit.json (hardened — 8a)
- test/security/policy-drift.test.ts, test/security/policy-drift-snapshot.json (new — 8c)
- src/security/security-events.ts, src/security/security-events.test.ts (new — 8d)
- src/agents/tool-policy-pipeline.ts (modified — tool denial logging)
- src/infra/net/fetch-guard.ts (modified — structured SSRF logging)
- src/cron/isolated-agent/run.ts (modified — structured injection logging)
- .github/workflows/ci.yml (modified — security-drift job)
- docs/gateway/security/alerting.md (new — 8e)

### Phase 9: Test Depth — Make Existing Tests Actually Test Security

**Status**: DONE.

**Priority**: MEDIUM. The test infrastructure from Phases 0-5 exists but many tests verify plumbing (HTTP status codes, gateway boot) rather than security behavior. This phase upgrades existing tests to verify the actual security guarantees.

**What was delivered**:

**9a — Upgraded injection corpus E2E tests:**

`test/security/injection-corpus.e2e.test.ts` — added 6 new test suites alongside existing gateway tests:

- **Detection verification**: all `shouldDetect: true` payloads verified through `detectSuspiciousPatterns()` returning non-empty results.
- **Content-wrapping verification**: all `content-wrapped` payloads verified through `wrapExternalContent()` — boundary markers and security notice present. Marker-sanitized payloads verified homoglyph neutralization (`[[MARKER_SANITIZED]]`).
- **DLP redaction verification**: all `secret-redacted` payloads with `embeddedSecrets[]` verified through `redactSensitiveText()` — each secret absent from redacted output.
- **SSRF blocking verification**: all `ssrf-blocked` payloads with `ssrfTargets[]` verified through `isPrivateIpAddress()` / `isBlockedHostname()`.
- **Tool-denied verification**: all `tool-denied` payloads with `targetTools[]` verified blocked under both minimal and reader policies via `filterToolsByPolicy()`.
- **All-ingress coverage**: `API_INGRESS_INJECTIONS`, `HOOK_INGRESS_INJECTIONS`, `WEBCHAT_INGRESS_INJECTIONS`, `CLI_INGRESS_INJECTIONS` imported and tested through authenticated webhook path.

**9b — Config matrix runtime enforcement:**

`test/security/security-harness.e2e.test.ts` — added cross-matrix and enforcement tests:

- **Full cross-matrix (12 combos)**: `crossMatrix(SANDBOX_MODES, TOOL_PROFILES, EXEC_APPROVAL_MODES)` generates all permutations. Each combo boots a gateway and verifies authenticated webhook acceptance.
- **Tool profile enforcement**: minimal policy blocks `exec`/`write`/`browser`; coding policy allows `read`/`write`/`edit` but denies `browser`/`nodes`; full profile allows all tools.
- **Exec approval mode config**: deny config verified well-formed, allowlist config verified with `echo`/`ls` commands, `crossMatrix` verified to preserve exec approval mode across combinations.

**9c — Trust-tier runtime enforcement:**

`test/security/trust-tier.test.ts` — added 3 new test suites (24 new tests):

- **Subagent escalation prevention** (6 tests): `isSubagentSessionKey()` identifies subagent keys, rejects non-subagent keys. `resolveSubagentToolPolicy()` denies `sessions_spawn`, `sessions_list`, `sessions_history`, `sessions_send`, `gateway`, `cron`, `agents_list`. Subagent key + `sessions_spawn` = forbidden.
- **Cross-tier tool inheritance** (11 tests): every tool in `DEFAULT_SUBAGENT_TOOL_DENY` verified blocked individually — `sessions_list`, `sessions_history`, `sessions_send`, `sessions_spawn`, `gateway`, `agents_list`, `whatsapp_login`, `session_status`, `cron`, `memory_search`, `memory_get`.
- **Reader cannot access coding-tier tools** (7 tests): reader policy blocks `exec`, `write`, `edit`, `browser`, `nodes`, `cron` individually; allows `read`, `sessions_list`, `sessions_history`.

**9d — SSRF edge-case coverage:**

`src/infra/net/fetch-guard.ssrf.test.ts` — expanded from 4 to 18 tests:

- **IP encoding variants** (4 new): `0.0.0.0`, `[::]`, `::ffff:127.0.0.1`, `::ffff:192.168.1.1`.
- **Protocol injection** (2 new): `file:///etc/passwd`, `data:` protocol.
- **DNS-based attacks** (3 new): redirect to `file://` scheme, DNS resolving to private IP via mock `lookupFn`, redirect chain where second hop resolves to `169.254.169.254`.
- **URL parsing edge cases** (3 new): `[::1]` IPv6 loopback, redirect loop detection (A → B → A), max redirect limit enforcement.
- **Allowlist edge cases** (2 new): `allowPrivateNetwork: true` permits `127.0.0.1`, non-matching allowlist blocks hosts.

**Verification**: All 18 SSRF tests pass. All 32 trust-tier tests pass. All 124 injection detection unit tests pass. Full test suite (837 files, 6454 tests) passes with zero regressions from Phase 9 changes.

Relevant files:

- test/security/injection-corpus.e2e.test.ts (9a — 6 new suites)
- test/security/security-harness.e2e.test.ts (9b — cross-matrix + enforcement)
- test/security/trust-tier.test.ts (9c — escalation + cross-tier + reader isolation)
- src/infra/net/fetch-guard.ssrf.test.ts (9d — 18 tests)

## Test Matrix (Ingress x Security Expectations)

Use this as a coverage grid. Each cell becomes one or more tests that assert the expected
behavior is enforced for that ingress path.

Ingress sources:

1. WebChat (WebSocket client)
2. Chat channels (WhatsApp, Telegram, Slack, Discord, etc.)
3. Gmail Pub/Sub → webhook
4. GitHub/GitLab webhook
5. Twitter/X ingestion (custom plugin or external fetch → webhook)
6. CLI/system events
7. HTTP APIs (OpenAI/OpenResponses/Tools Invoke)
8. Hooks (event-driven scripts, npm-installed modules)
9. Cron jobs

Security expectations:

1. Sender/auth gate enforced (allowlist/pairing/auth token/webhook HMAC)
2. Tool allowlist enforced (deny `exec/read/write/browser/web_fetch` unless allowed)
3. Sandbox enforced for untrusted inputs (no host exec)
4. `.env`/secret path access denied (read/write)
5. Skill mutation blocked (no writes to `skills/` or `SKILL.md`)
6. Approval gate enforced for side effects (exec approvals / Lobster approvals)
7. SSRF blocked (no fetch to private IPs, metadata endpoints, or localhost)
8. Outbound DLP enforced (secrets redacted in replies, not just logs)

| Ingress \ Expectation | Auth | Tools | Sandbox | Secrets | Skills | Approvals | SSRF | DLP |
| --------------------- | ---- | ----- | ------- | ------- | ------ | --------- | ---- | --- |
| WebChat               | ✓    | ✓     | ✓       | ✓       | ✓      | ✓         | ✓    | ✓   |
| Chat channels         | ✓    | ✓     | ✓       | ✓       | ✓      | ✓         | ✓    | ✓   |
| Gmail Pub/Sub         | ✓    | ✓     | ✓       | ✓       | ✓      | ✓         | ✓    | ✓   |
| Git webhook           | ✓    | ✓     | ✓       | ✓       | ✓      | ✓         | ✓    | ✓   |
| Twitter/X             | ✓    | ✓     | ✓       | ✓       | ✓      | ✓         | ✓    | ✓   |
| CLI/system            | ✓    | ✓     | ✓       | ✓       | ✓      | ✓         | ✓    | ✓   |
| HTTP APIs             | ✓    | ✓     | ✓       | ✓       | ✓      | ✓         | ✓    | ✓   |
| Hooks                 | ✓    | ✓     | ✓       | ✓       | ✓      | ✓         | ✓    | ✓   |
| Cron                  | ✓    | ✓     | ✓       | ✓       | ✓      | ✓         | ✓    | ✓   |

Relevant files:

- docs/automation/webhook.md
- docs/automation/gmail-pubsub.md
- docs/automation/hooks.md
- docs/cli/cron.md
- docs/gateway/openai-http-api.md
- docs/gateway/openresponses-http-api.md
- docs/gateway/tools-invoke-http-api.md

## Trust Tier Routing (Configuration Pattern)

Use trust tiers to route ingress into different agents with distinct tool policies.
This avoids duplicating policy across channels and keeps "deny by default" consistent.

The building blocks already exist: `bindings` for routing, `agents.list[]` for per-agent config,
`tools.*` for policy, `sandbox.*` for isolation. The tiers below are a recommended
configuration pattern, not new code.

### Tier A: Trusted Operators

- Only explicit allowlisted senders or authenticated operator clients (CLI, main session).
- Sandbox: `off` (host exec allowed with approvals).
- Tool policy: `full` profile with exec approvals (`security: "allowlist"`, `ask: "on-miss"`).
- DM scope: `main` (shared context is fine for the operator).

Example:

```json5
{
  agents: { list: [{ id: "main", sandbox: { mode: "off" } }] },
  bindings: [
    { agentId: "main", match: { channel: "whatsapp", peer: { kind: "direct", id: "+1OPERATOR" } } },
  ],
}
```

### Tier B: Verified Systems

- Authenticated webhooks (GitHub/GitLab, Gmail Pub/Sub, internal services).
- Sandbox: `all` (always containerized).
- Tool policy: `coding` profile — read/write/edit but no browser/exec/nodes.
- DM scope: `per-channel-peer` (isolated per source).

Example:

```json5
{
  agents: {
    list: [
      {
        id: "systems",
        sandbox: { mode: "all", scope: "session" },
        tools: {
          allow: ["read", "write", "edit", "sessions_list"],
          deny: ["exec", "browser", "nodes"],
        },
      },
    ],
  },
  bindings: [{ agentId: "systems", match: { channel: "webhook" } }],
}
```

### Tier C: Untrusted / Public

- Public or external content (Twitter/X ingestion, web fetch, unknown senders).
- Sandbox: `all` (always containerized).
- Tool policy: `minimal` profile — read-only, no exec/fs/browser/nodes.
- DM scope: `per-account-channel-peer` (maximum isolation).

Example:

```json5
{
  agents: {
    list: [
      {
        id: "reader",
        sandbox: { mode: "all", scope: "session" },
        tools: {
          allow: ["read", "sessions_list", "sessions_history"],
          deny: ["exec", "write", "browser", "nodes", "cron", "gateway"],
        },
      },
    ],
  },
  bindings: [
    { agentId: "reader", match: { channel: "telegram" } }, // Public bot
  ],
}
```

## Phase Dependency Graph

```
Phase 0 (Security Harness)
   │
   ├── Phase 1 (Baseline Snapshot)
   │
   ├── Phase 2 (Trust Tiers + Webhook Auth)
   │
   ├── Phase 3 (Supply-Chain + Hook Hardening)
   │      │
   │      └── Phase 7 (Scanner Hardening) ─── fixes scanner bypasses from Phase 3
   │
   └── Phase 4 (Injection Corpus)
          │
          └── Phase 5 (Docker Regression + Closed-Box) ─── runs corpus from Phase 4
                 │
                 └── Phase 6 (Fix Active Bypasses) ─── fixes DLP/SSRF/loader bypasses found by Phase 5 audit
                        │
                        ├── Phase 8 (Drift Detection) ─── uses hardened baseline from Phase 1 + fixes from Phase 6
                        │
                        └── Phase 9 (Test Depth) ─── upgrades tests from Phases 0-5 to verify actual security behavior
```

Phases 1-4 can run in parallel once Phase 0 is complete.
Phase 5 depends on Phase 4 (injection corpus).
Phase 6 is the next critical step — fixes active vulnerability classes found during the Phase 5 audit.
Phase 7 can run in parallel with Phase 6 (independent: scanner rules vs runtime bypasses).
Phase 8 depends on Phase 6 (baseline hardening is more effective after bypass paths are closed).
Phase 9 depends on Phase 6 (tests should verify the fixed behavior, not the broken behavior).
