# Security Tests

Security test harness and regression tests for OpenClaw.

## Structure

```
test/security/
  harness.ts                       # Gateway spawn/teardown helpers
  config-matrix.ts                 # Vitest-parameterized config matrix
  fixtures/
    webhook-payloads.ts            # Typed webhook payload fixtures
  security-harness.e2e.test.ts     # E2E smoke + auth + config-matrix tests
  baseline-audit.test.ts           # Baseline audit snapshot regression test
  baseline-audit.json              # Committed baseline snapshot
```

## Running

### E2E tests (require built gateway)

```bash
pnpm vitest run --config vitest.e2e.config.ts test/security/
```

### Unit tests (baseline audit)

```bash
pnpm vitest run test/security/baseline-audit.test.ts
```

## Fixture format

Each fixture in `fixtures/webhook-payloads.ts` exports a `WebhookFixture`:

```typescript
type WebhookFixture = {
  name: string;
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  expectedStatus?: number;
};
```

## Config matrix

The config matrix (`config-matrix.ts`) provides pre-defined axes:

- **SANDBOX_MODES** — sandbox=off vs sandbox=all
- **TOOL_PROFILES** — minimal / coding / full
- **EXEC_APPROVAL_MODES** — deny / allowlist

Use `crossMatrix(...axes)` to generate cross-product test permutations
for `describe.each` / `it.each`.

## Baseline audit

The baseline audit test (`baseline-audit.test.ts`) runs `runSecurityAudit()`
with a deterministic config and compares against `baseline-audit.json`.

To regenerate the baseline after intentional changes:

```bash
GENERATE_BASELINE=1 pnpm vitest run test/security/baseline-audit.test.ts
```
