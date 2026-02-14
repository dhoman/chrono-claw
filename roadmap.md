# Security Roadmap (High-Level)

Scope: harden OpenClaw against prompt injection, prevent `.env`/secret leakage, and reduce malicious tool/skill behavior. This roadmap assumes you will run per-phase instances and refine in parallel.

## What “Workflows” Exist Today

OpenClaw’s built-in workflow mechanisms are:

1. OpenProse (`.prose` programs + `/prose` command) for multi-step orchestration.
2. Lobster workflows (typed pipelines with explicit approvals).
3. LLM Task (structured JSON-only LLM step for workflows, typically used inside Lobster).
4. Hooks/automation (event-driven scripts for agent lifecycle and command events).
5. Skills (AgentSkills folders, load-time gated; operational behavior still governed by tool policy).

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/prose.md
- /Users/dhoman/Source/chrono-claw/docs/tools/lobster.md
- /Users/dhoman/Source/chrono-claw/docs/tools/llm-task.md
- /Users/dhoman/Source/chrono-claw/docs/automation/hooks.md
- /Users/dhoman/Source/chrono-claw/docs/tools/skills.md
- /Users/dhoman/Source/chrono-claw/docs/concepts/agent-loop.md

## Ingress Surfaces You Mentioned (Twitter, Gmail, Git, Web)

These inputs are not all “chat channels,” but they still hit the Gateway and must share the same
security controls.

1. Twitter/X: no built-in channel or skill in this repo. You would need a plugin or external
   ingestion (webhook/cron fetch) that forwards messages into the Gateway.
2. Gmail: supported via automation webhooks (Pub/Sub + webhook mapping) and can dispatch
   inbound events into the agent pipeline.
3. Git: no built-in channel; use a webhook pipeline (GitHub/GitLab webhook → Gateway hook)
   or a skill/tool that runs git locally (separate from inbound events).
4. Web: WebChat is built-in and connects over the Gateway WebSocket.

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/automation/webhook.md
- /Users/dhoman/Source/chrono-claw/docs/automation/gmail-pubsub.md
- /Users/dhoman/Source/chrono-claw/docs/web/webchat.md
- /Users/dhoman/Source/chrono-claw/docs/concepts/architecture.md
- /Users/dhoman/Source/chrono-claw/skills/github

## Roadmap Phases (Reprioritized: Docker Harness First)

### Phase 0: Docker Test Harness (Foundational)

Goals:
- Make every security change testable in a repeatable container environment.
- Ensure all ingress paths can be simulated in CI (webhooks, HTTP APIs, CLI/system).

Key actions:
1. Stand up a minimal Docker-based gateway harness for tests, including a consistent config fixture and seeded state dir.
2. Add ingress fixtures for webhook payloads (Gmail Pub/Sub, GitHub/GitLab, generic JSON), plus a baseline WebChat/WS client stub.
3. Ensure the harness can call `/hooks/*`, the OpenAI/OpenResponses HTTP APIs, and Tools Invoke endpoints locally.
4. Make it easy to toggle sandbox mode, tool policy, and trust-tier routing per test run.

Deliverables:
1. A Docker harness entrypoint and README explaining how to run the security suite locally and in CI.
2. A fixtures folder with canonical webhook payloads and expected behaviors.

Minimum viable test suite:
1. Harness boots a gateway in Docker and exposes `/hooks/*`.
2. At least one webhook fixture triggers an agent run successfully.
3. At least one HTTP API request succeeds locally (OpenAI/OpenResponses).

Definition of done:
1. CI can run the harness end-to-end without manual steps.
2. Fixtures are versioned and documented with expected outcomes.

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/install/docker.md
- /Users/dhoman/Source/chrono-claw/docs/automation/webhook.md
- /Users/dhoman/Source/chrono-claw/docs/automation/gmail-pubsub.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/openai-http-api.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/openresponses-http-api.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/tools-invoke-http-api.md
- /Users/dhoman/Source/chrono-claw/test/gateway.multi.e2e.test.ts

### Phase 1: Baseline Inventory and Guardrails

Goals:
- Identify what can execute (tools, skills, plugins) and where secrets reside.
- Lock down access and surface area before adding new ingestion paths.

Key actions:
1. Run and document `openclaw security audit` output as the baseline snapshot.
2. Define a minimal tool allowlist for the default agent, with deny-by-default for `exec/read/write/browser/web_fetch`.
3. Document all secret locations and explicitly forbid access paths (`.env`, `~/.openclaw`, agent auth profiles).
4. Decide which ingress sources are trusted vs untrusted, based on verification strength and provenance.

Deliverables:
1. A baseline security report (audit output + config diff).
2. A written inventory of secrets and disallowed paths to be enforced in tests.

Minimum viable test suite:
1. Security audit runs and produces a stable baseline report.
2. A test fails if any forbidden secret path is accessed.

Definition of done:
1. Baseline report is committed and referenced by the test suite.
2. Tool policy defaults are “deny by default” for high-risk tools.

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/gateway/security/index.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/sandbox-vs-tool-policy-vs-elevated.md
- /Users/dhoman/Source/chrono-claw/docs/tools/exec-approvals.md
- /Users/dhoman/Source/chrono-claw/docs/tools/skills.md

### Phase 2: Ingress and Sender Hardening (Channels + Webhooks + Pub/Sub)

Goals:
- Ensure only trusted senders can trigger workflows.
- Route untrusted inputs into read-only agents and prevent side effects.

Key actions:
1. Enforce pairing/allowlists for any inbound chat channel.
2. For Gmail/Git/Twitter/Web ingestion, route into a “reader” agent with no exec/fs tools.
3. Treat webhook and Pub/Sub payloads as untrusted content unless explicitly verified.
4. Enable secure DM mode (per-sender session scoping) if multiple senders are allowed.

Deliverables:
1. A routing plan mapping ingress sources to trust tiers and agents.
2. A configuration baseline for webhook access control and token policy.

Minimum viable test suite:
1. Unauthenticated webhook requests are rejected.
2. Allowed webhooks route into the correct agent tier.

Definition of done:
1. Every ingress path is mapped to a trust tier.
2. Reader agent runs are isolated from tool escalation.

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/gateway/security/index.md
- /Users/dhoman/Source/chrono-claw/docs/concepts/multi-agent.md
- /Users/dhoman/Source/chrono-claw/src/routing/resolve-route.ts
- /Users/dhoman/Source/chrono-claw/docs/channels/groups.md
- /Users/dhoman/Source/chrono-claw/docs/automation/webhook.md
- /Users/dhoman/Source/chrono-claw/docs/automation/gmail-pubsub.md

### Phase 3: Tool Policy, Sandboxing, and Data Loss Prevention

Goals:
- Prevent tool escalation and secret leakage even under prompt injection.
- Ensure untrusted workflows never run host exec or read secret paths.

Key actions:
1. Turn on sandboxing for non-main (or all) sessions and enforce strict sandbox tool allowlists.
2. Require exec approvals on host and node execution, with deny-by-default rules.
3. Add explicit data-loss prevention rules for outbound replies and logs to block `.env` or sensitive content leakage.

Deliverables:
1. A documented tool policy matrix by trust tier.
2. A DLP policy checklist aligned with the test corpus.

Minimum viable test suite:
1. Any attempt to run `exec` in a Tier B/C agent is denied.
2. Any attempt to read `.env` or `~/.openclaw` is denied.
3. Any attempt to emit secret content is blocked or redacted.

Definition of done:
1. Tool policy is enforced for all trust tiers.
2. DLP tests fail on any secret leakage.

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/gateway/sandboxing.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/sandbox-vs-tool-policy-vs-elevated.md
- /Users/dhoman/Source/chrono-claw/docs/tools/exec-approvals.md
- /Users/dhoman/Source/chrono-claw/docs/tools/elevated.md

### Phase 4: Skill and Plugin Trust Pipeline

Goals:
- Block malicious skills and prevent unreviewed skill changes.

Key actions:
1. Add a CI gate using Cisco `skill-scanner` for all `skills/` directories.
2. Require manual review for any new or modified `SKILL.md`.
3. Pin plugin versions and avoid automatic installs in production.

Deliverables:
1. CI checks that fail on unsafe skill patterns.
2. A documented review workflow for skill/plugin changes.

Minimum viable test suite:
1. Skill scanner runs in CI and produces a report.
2. Unsafe skills fail the build.

Definition of done:
1. Skill updates require explicit review/approval.
2. No new skills can be enabled without passing scan + review.

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/tools/skills.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/security/index.md
- /Users/dhoman/Source/chrono-claw/skills
- /Users/dhoman/Source/chrono-claw/extensions

### Phase 5: Prompt-Injection Test Suite

Goals:
- Add tests that verify tool policy, sandboxing, and DLP under hostile prompts.

Key actions:
1. Create a prompt-injection test corpus (direct, indirect, polyglot).
2. Tests that assert disallowed tools are never called.
3. Tests that assert secret paths are not read or emitted.
4. Tests for “reader agent” isolation (no escalation).

Deliverables:
1. A repeatable injection corpus with expected outcomes.
2. A test index mapping corpus entries to the test matrix.

Minimum viable test suite:
1. Direct, indirect, and polyglot prompt injections are covered.
2. Tests assert no disallowed tool calls are made.

Definition of done:
1. The corpus is part of CI and blocks regressions.
2. Each ingress source has at least one injection test.

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/concepts/agent-loop.md
- /Users/dhoman/Source/chrono-claw/src/auto-reply/reply/dispatch-from-config.ts
- /Users/dhoman/Source/chrono-claw/src/plugins/hooks.ts
- /Users/dhoman/Source/chrono-claw/src/config/group-policy.ts
- /Users/dhoman/Source/chrono-claw/src/agents
- /Users/dhoman/Source/chrono-claw/src/sessions
- /Users/dhoman/Source/chrono-claw/test

## Test Matrix (Ingress x Security Expectations)

Use this as a coverage grid. Each cell becomes one or more tests that assert the expected
behavior is enforced for that ingress path.

Ingress sources:
1. WebChat (WebSocket client)
2. Gmail Pub/Sub → webhook
3. GitHub/GitLab webhook
4. Twitter/X ingestion (custom plugin or external fetch → webhook)
5. CLI/system events
6. HTTP APIs (OpenAI/OpenResponses/Tools Invoke)

Security expectations:
1. Sender/auth gate enforced (allowlist/pairing/auth token)
2. Tool allowlist enforced (deny `exec/read/write/browser/web_fetch` unless allowed)
3. Sandbox enforced for untrusted inputs (no host exec)
4. `.env`/secret path access denied (read/write)
5. Skill mutation blocked (no writes to `skills/` or `SKILL.md`)
6. Approval gate enforced for side effects (exec approvals / Lobster approvals)

Example matrix (high-level):

| Ingress \ Expectation | Auth Gate | Tool Allowlist | Sandbox | Secret Deny | Skill Mutation | Approval Gate |
| --- | --- | --- | --- | --- | --- | --- |
| WebChat | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Gmail Pub/Sub | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Git webhook | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Twitter/X ingestion | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CLI/system | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| HTTP APIs | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/automation/webhook.md
- /Users/dhoman/Source/chrono-claw/docs/automation/gmail-pubsub.md
- /Users/dhoman/Source/chrono-claw/docs/cli/system.md
- /Users/dhoman/Source/chrono-claw/docs/cli/cron.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/openai-http-api.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/openresponses-http-api.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/tools-invoke-http-api.md

## Trust Tier Routing (Conceptual)

Use trust tiers to route ingress into different agents with distinct tool policies.
This avoids duplicating policy across channels and keeps “deny by default” consistent.

Suggested tiers:

1. Tier A (Trusted Operators)
   - Only explicit allowlisted senders or authenticated operator clients.
   - Allowed tools: read/write/exec with approvals, limited browser/web as needed.

2. Tier B (Verified Systems)
   - Authenticated webhooks (GitHub/GitLab, Gmail Pub/Sub, internal services).
   - Allowed tools: read-only + limited network fetch; no exec by default.

3. Tier C (Untrusted/Public)
   - Public or external content (Twitter/X ingestion, web fetch, unknown sources).
   - Allowed tools: summarization only; no exec/fs/browser by default.

Routing intent:
- Map ingress source → trust tier → dedicated agent.
- Enforce tool policy at the agent level (deny by default), then allow only what the tier needs.

### Phase 6: Docker-First Security Regression Runs

Goals:
- Verify that sandboxed execution actually prevents host access and secret leakage.
- Ensure regressions are caught before release.

Key actions:
1. Run the full security suite inside Docker with realistic ingress fixtures.
2. Add scenarios where the agent attempts to read host `.env` or `~/.openclaw`.
3. Verify that sandbox-only tool policy denies those accesses and that DLP rules prevent leakage.

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/install/docker.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/sandboxing.md
- /Users/dhoman/Source/chrono-claw/scripts/sandbox-setup.sh

Minimum viable test suite:
1. Regression suite runs entirely inside Docker.
2. Sandbox escape attempts are blocked.

Definition of done:
1. Docker regression suite is mandatory in CI.
2. Regressions in tool policy or DLP fail the build.

### Phase 7: Monitoring and Drift Detection

Goals:
- Detect regressions or accidental privilege expansion.
- Provide ongoing visibility into denied tool attempts and policy violations.

Key actions:
1. Make `openclaw security audit` part of CI and release checks.
2. Add a “policy drift” test that fails if allowlists expand unexpectedly.
3. Track tool invocation logs for denied attempts and emit alerts for repeated abuse patterns.

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/gateway/security/index.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/logging.md

Minimum viable test suite:
1. Policy drift test fails when allowlists expand unexpectedly.
2. Tool denial events are logged in a structured format.

Definition of done:
1. Drift detection is enforced in CI.
2. Alerting is configured for repeated policy violations.

## Other Ingress Methods to Consider

Beyond chat channels and webhooks, OpenClaw can ingest from:

1. CLI/system events (manual or scheduled triggers).
2. Cron jobs and hooks (automation entry points).
3. HTTP API endpoints that proxy “chat-like” input (OpenAI/OpenResponses compatibility).

Relevant files:
- /Users/dhoman/Source/chrono-claw/docs/cli/system.md
- /Users/dhoman/Source/chrono-claw/docs/cli/cron.md
- /Users/dhoman/Source/chrono-claw/docs/automation/hooks.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/openai-http-api.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/openresponses-http-api.md
- /Users/dhoman/Source/chrono-claw/docs/gateway/tools-invoke-http-api.md

## Optional Future Item

1. Webhook signature verification (HMAC or provider-specific signing):
   - Reject spoofed webhook payloads by verifying signatures from GitHub/GitLab/etc.
