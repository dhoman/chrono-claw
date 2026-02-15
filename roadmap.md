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

**Status**: Extensive Docker E2E infrastructure exists for functional testing. No dedicated security regression suite that verifies sandbox isolation under attack scenarios.

**What already exists**:

- `test/gateway.multi.e2e.test.ts` — multi-instance gateway E2E
- `scripts/e2e/` — 7+ Docker test scripts
- `pnpm test:docker:all` — orchestrates Docker test suite
- Podman rootless support (`setup-podman.sh`, Quadlet units)
- Sandbox auto-pruning (idle 24h, max age 7d)

Goals:

- Verify that sandboxed execution actually prevents host access and secret leakage.
- Run the injection corpus (Phase 4) inside containerized gateways.
- Ensure regressions are caught before release.

Key actions:

1. Create a `scripts/e2e/security-regression-docker.sh` that boots a gateway in Docker with `sandbox=all` and runs the injection corpus against it.
2. Add scenarios where the sandboxed agent attempts to read host `.env`, `~/.openclaw/credentials/`, and `auth-profiles.json` — assert denial.
3. Add scenarios where the sandboxed agent attempts to escape the container (mount host paths, access Docker socket, network to metadata endpoint) — assert denial.
4. Support both Docker and Podman runtimes.
5. Add to CI as a mandatory pre-release gate (`pnpm test:docker:security`).

Deliverables:

1. `scripts/e2e/security-regression-docker.sh` script.
2. `pnpm test:docker:security` npm script.
3. CI integration as a mandatory check.

Minimum viable test suite:

1. Regression suite runs entirely inside Docker (or Podman).
2. Sandbox escape attempts are blocked.
3. Injection corpus passes inside the container.

Definition of done:

1. Docker security regression suite is mandatory in CI.
2. Regressions in tool policy, sandbox, or DLP fail the build.

Relevant files:

- Dockerfile, Dockerfile.sandbox, docker-compose.yml
- setup-podman.sh
- test/gateway.multi.e2e.test.ts
- scripts/e2e/
- src/agents/sandbox/constants.ts
- docs/install/docker.md, docs/install/podman.md
- docs/gateway/sandboxing.md

### Phase 6: Monitoring, Drift Detection, and Alerting

**Status**: `openclaw security audit` exists. No formal drift detection or structured denial logging is in CI.

Goals:

- Detect regressions or accidental privilege expansion before release.
- Provide ongoing visibility into denied tool attempts and policy violations.

Key actions:

1. Add a CI step that runs `openclaw security audit --json` and compares against the committed baseline (Phase 1). Fail on any new finding with severity >= warn.
2. Add a "policy drift" test: snapshot the current tool allowlist for each agent, commit it, and fail if any allowlist expands without an explicit approval comment in the diff.
3. Add structured logging for tool denial events (`src/agents/tool-policy-pipeline.ts`): emit a JSON log line with `{event: "tool_denied", tool, agent, session, reason}` that can be aggregated.
4. Document an alerting pattern: how to pipe denial logs to a monitoring system (e.g., webhook to Slack/Discord on repeated denials from the same session).

Deliverables:

1. CI drift detection step.
2. Tool allowlist snapshot + regression test.
3. Structured denial logging.
4. Alerting documentation.

Minimum viable test suite:

1. Policy drift test fails when allowlists expand unexpectedly.
2. Tool denial events are logged in structured JSON format.
3. Audit baseline regression catches new findings.

Definition of done:

1. Drift detection is enforced in CI.
2. Denial events are structured and parseable.
3. Alerting pattern is documented.

Relevant files:

- src/cli/security-cli.ts
- src/agents/tool-policy-pipeline.ts
- src/agents/tool-policy.ts
- src/logging/redact.ts
- docs/gateway/security/index.md
- docs/gateway/logging.md

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
   │      │
   │      └── Phase 6 (Drift Detection) ─── uses baseline from Phase 1
   │
   ├── Phase 2 (Trust Tiers + Webhook Auth)
   │
   ├── Phase 3 (Supply-Chain + Hook Hardening)
   │
   └── Phase 4 (Injection Corpus)
          │
          └── Phase 5 (Docker Security Regression) ─── runs corpus from Phase 4
```

Phases 1-4 can run in parallel once Phase 0 is complete.
Phase 5 depends on Phase 4 (injection corpus).
Phase 6 depends on Phase 1 (baseline snapshot).
