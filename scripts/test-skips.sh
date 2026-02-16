#!/usr/bin/env bash
# Show all skipping and failing tests with reasons.
# Usage:
#   pnpm test:skips          # show only skipped tests (default)
#   pnpm test:skips --fails  # show only failing tests
#   pnpm test:skips --all    # show both skipped and failing tests
set -euo pipefail

MODE="${1:-skips}"

run_tests() {
  NO_COLOR=1 pnpm vitest run --reporter=verbose 2>&1
}

case "$MODE" in
  --fails|fails)
    echo "==> Failing tests:"
    run_tests | grep -E "^ *[×✕x] |FAIL " || echo "(none)"
    ;;
  --all|all)
    echo "==> Skipped tests:"
    run_tests | tee /tmp/openclaw-test-out.txt | grep -E "^ *↓ " || echo "(none)"
    echo ""
    echo "==> Failing tests:"
    grep -E "^ *[×✕x] |FAIL " /tmp/openclaw-test-out.txt || echo "(none)"
    echo ""
    echo "==> Summary:"
    tail -5 /tmp/openclaw-test-out.txt
    rm -f /tmp/openclaw-test-out.txt
    ;;
  --skips|skips|*)
    echo "==> Skipped tests:"
    run_tests | grep -E "↓ " || echo "(none)"
    echo ""
    echo "==> Skip reasons (from source):"
    echo ""
    echo "  Docker-only tests (45 tests) - need: pnpm test:docker:security"
    echo "    OPENCLAW_DOCKER_SECURITY_TEST=1  (19 sandbox isolation tests)"
    echo "    SEC_GW_HOST + SEC_GW_PORT + SEC_GW_TOKEN + SEC_HOOK_TOKEN  (26 injection E2E tests)"
    echo ""
    echo "  Live API tests - need: OPENCLAW_LIVE_TEST=1 + provider API keys"
    echo "    memory-lancedb: OPENAI_API_KEY + OPENCLAW_LIVE_TEST=1"
    echo ""
    echo "  Platform-specific skips (non-issue on macOS/Linux):"
    echo "    ports-inspect.test.ts: skips on Windows (process.platform === 'win32')"
    echo "    gmail-setup-utils.test.ts: skips on Windows (process.platform === 'win32')"
    ;;
esac
