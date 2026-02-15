# Prompt-Injection Test Corpus

End-to-end prompt injection test corpus for OpenClaw security hardening (Phase 4).

## Structure

```
injection-corpus/
  types.ts      — Type definitions (InjectionCorpusEntry, categories, expectations)
  payloads.ts   — 25 categorized injection payloads across 6 categories
  matrix.ts     — Coverage matrix mapping (ingress x expectation)
  README.md     — This file
```

## Categories (25 payloads)

| Category       | Count | Description                                                |
| -------------- | ----- | ---------------------------------------------------------- |
| Direct         | 4     | "Ignore previous instructions" and variants                |
| Indirect       | 4     | Injections embedded in webhook/email/commit bodies         |
| Polyglot       | 4     | Mixed Markdown, HTML, JSON, shell, Unicode homoglyphs      |
| Tool-confusion | 5     | Tricks to invoke disallowed tools (exec, write, browser)   |
| Exfiltration   | 4     | Secrets embedded for DLP testing (sk-_, ghp\__, PEM)       |
| SSRF           | 4     | Internal URL fetch attempts (metadata, localhost, RFC1918) |

## Test Files

### Unit tests (fast, no gateway required)

`test/security/injection-detection.test.ts` — 102 tests covering:

- **Detection**: `detectSuspiciousPatterns` catches known injection patterns
- **Content wrapping**: `wrapExternalContent` applies security boundaries
- **Tool policy**: `filterToolsByPolicy` blocks disallowed tools (minimal, reader, coding profiles)
- **DLP redaction**: `redactSensitiveText` redacts embedded secrets
- **SSRF blocking**: `isPrivateIpAddress` / `isBlockedHostname` catches private targets
- **Coverage matrix**: Validates all ingress sources and expectations are covered

```bash
pnpm vitest run test/security/injection-detection.test.ts
```

### E2E tests (require build + gateway spawn)

`test/security/injection-corpus.e2e.test.ts` — Gateway-level tests:

- **Auth enforcement**: Unauthenticated injection payloads rejected (401/403)
- **Safe handling**: Authenticated payloads accepted (200), processed safely
- **Category coverage**: One E2E test per category, gateway stays healthy

```bash
pnpm build && pnpm vitest run --config vitest.e2e.config.ts test/security/injection-corpus.e2e.test.ts
```

## Coverage Matrix

The matrix maps each corpus entry to the ingress x expectation grid from the roadmap.
Run `computeCoverageReport()` from `matrix.ts` to verify coverage:

- Covered ingress sources: webhook, email, channel
- Covered expectations: detection, content-wrapped, tool-denied, secret-redacted, ssrf-blocked, marker-sanitized
- Each category has >= 3 test cases

## Adding New Payloads

1. Add the entry to the appropriate array in `payloads.ts`
2. Set `shouldDetect: true` if `detectSuspiciousPatterns` should flag it
3. Add `targetTools`, `embeddedSecrets`, or `ssrfTargets` as appropriate
4. Run both test files to verify
