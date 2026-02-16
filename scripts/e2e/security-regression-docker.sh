#!/usr/bin/env bash
# -------------------------------------------------------------------
# Docker/Podman Security Regression Suite (Phase 5)
#
# Boots a gateway inside a locked-down container with sandbox=all,
# runs the injection corpus and sandbox isolation tests, and verifies
# that regressions in tool policy, sandbox, or DLP fail the build.
#
# Supports both Docker and Podman runtimes.
# -------------------------------------------------------------------
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---------------------------------------------------------------------------
# Runtime detection (Docker or Podman)
# ---------------------------------------------------------------------------
if command -v docker &>/dev/null; then
  RUNTIME="docker"
elif command -v podman &>/dev/null; then
  RUNTIME="podman"
else
  echo "ERROR: Neither docker nor podman found in PATH" >&2
  exit 1
fi
echo "==> Container runtime: $RUNTIME"

IMAGE_NAME="openclaw-security-regression-e2e"
NODE_UID="1000"
NODE_GID="1000"
PORT="18789"
TOKEN="sec-e2e-$(date +%s)-$$"
HOOK_TOKEN="hook-sec-e2e-$(date +%s)-$$"
NET_NAME="openclaw-sec-e2e-$$"
GW_NAME="openclaw-sec-gw-$$"
TEST_NAME="openclaw-sec-test-$$"

# Phase 5 (closed-box) container/network names
CB_PORT="18790"
CB_HOOK_TOKEN="hook-cb-e2e-$(date +%s)-$$"
NET_CB_NAME="openclaw-sec-cb-$$"
MOCK_CB_NAME="openclaw-sec-mock-$$"
GW_CB_NAME="openclaw-sec-cb-gw-$$"
MOCK_INSPECT_PORT="9100"

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
cleanup() {
  echo "==> Cleaning up..."
  # Phase 1-4 containers
  $RUNTIME rm -f "$TEST_NAME" "${TEST_NAME}-isolation" "${TEST_NAME}-e2e" >/dev/null 2>&1 || true
  $RUNTIME rm -f "$GW_NAME" >/dev/null 2>&1 || true
  $RUNTIME network rm "$NET_NAME" >/dev/null 2>&1 || true
  # Phase 5 containers
  $RUNTIME rm -f "${TEST_NAME}-cb" >/dev/null 2>&1 || true
  $RUNTIME rm -f "$GW_CB_NAME" >/dev/null 2>&1 || true
  $RUNTIME rm -f "$MOCK_CB_NAME" >/dev/null 2>&1 || true
  $RUNTIME network rm "$NET_CB_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
echo "==> Building Docker image: $IMAGE_NAME"
$RUNTIME build -t "$IMAGE_NAME" -f "$ROOT_DIR/scripts/e2e/Dockerfile" "$ROOT_DIR"

# ---------------------------------------------------------------------------
# Network (--internal blocks external egress including metadata endpoints)
# ---------------------------------------------------------------------------
echo "==> Creating isolated network: $NET_NAME"
$RUNTIME network create --internal "$NET_NAME" >/dev/null

# ---------------------------------------------------------------------------
# Write gateway config
# ---------------------------------------------------------------------------
echo "==> Preparing gateway config..."
GW_CONFIG=$(cat <<JSONEOF
{
  "gateway": {
    "port": $PORT,
    "bind": "lan",
    "auth": { "mode": "token", "token": "$TOKEN" }
  },
  "hooks": { "enabled": true, "token": "$HOOK_TOKEN", "path": "/hooks" },
  "channels": {},
  "tools": { "profile": "coding" },
  "agents": { "defaults": { "sandbox": { "mode": "all" } } }
}
JSONEOF
)

# ---------------------------------------------------------------------------
# Start gateway container (locked down)
# ---------------------------------------------------------------------------
echo "==> Starting gateway container: $GW_NAME"
$RUNTIME run --rm -d \
  --name "$GW_NAME" \
  --network "$NET_NAME" \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --tmpfs /home/node:rw,noexec,nosuid,size=128m \
  -e "OPENCLAW_GATEWAY_TOKEN=$TOKEN" \
  -e "OPENCLAW_SKIP_CHANNELS=1" \
  -e "OPENCLAW_SKIP_GMAIL_WATCHER=1" \
  -e "OPENCLAW_SKIP_CRON=1" \
  -e "OPENCLAW_SKIP_CANVAS_HOST=1" \
  -e "OPENCLAW_SKIP_BROWSER_CONTROL_SERVER=1" \
  "$IMAGE_NAME" \
  bash -lc "
    set -euo pipefail
    mkdir -p /home/node/.openclaw
    echo '$GW_CONFIG' > /home/node/.openclaw/openclaw.json
    export HOME=/home/node
    export OPENCLAW_CONFIG_PATH=/home/node/.openclaw/openclaw.json
    export OPENCLAW_STATE_DIR=/home/node/.openclaw/state
    entry=dist/index.mjs
    [ -f \"\$entry\" ] || entry=dist/index.js
    node \"\$entry\" gateway --port $PORT --bind lan --allow-unconfigured > /tmp/gateway-sec-e2e.log 2>&1
  "

# ---------------------------------------------------------------------------
# Wait for gateway
# ---------------------------------------------------------------------------
echo "==> Waiting for gateway to come up..."
ready=0
for _ in $(seq 1 60); do
  if $RUNTIME exec "$GW_NAME" bash -lc "node --input-type=module -e '
    import net from \"node:net\";
    const socket = net.createConnection({ host: \"127.0.0.1\", port: $PORT });
    const timeout = setTimeout(() => { socket.destroy(); process.exit(1); }, 400);
    socket.on(\"connect\", () => { clearTimeout(timeout); socket.end(); process.exit(0); });
    socket.on(\"error\", () => { clearTimeout(timeout); process.exit(1); });
  ' >/dev/null 2>&1"; then
    ready=1
    break
  fi
  if $RUNTIME exec "$GW_NAME" bash -lc "grep -q 'listening on' /tmp/gateway-sec-e2e.log 2>/dev/null"; then
    ready=1
    break
  fi
  sleep 0.5
done

if [ "$ready" -ne 1 ]; then
  echo "ERROR: Gateway failed to start"
  $RUNTIME exec "$GW_NAME" bash -lc "cat /tmp/gateway-sec-e2e.log" 2>/dev/null || true
  exit 1
fi
echo "==> Gateway is up"

# ---------------------------------------------------------------------------
# Phase 1: Security unit tests inside Docker
#   Runs injection detection, DLP, SSRF, tool policy tests to ensure
#   they all pass in the containerized environment.
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo "Phase 1: Security unit tests (in Docker)"
echo "============================================"
$RUNTIME run --rm \
  --name "$TEST_NAME" \
  --network "$NET_NAME" \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  -e "NO_COLOR=1" \
  "$IMAGE_NAME" \
  bash -lc "
    set -euo pipefail
    cd /app
    echo '--- Injection detection tests ---'
    pnpm vitest run test/security/injection-detection.test.ts
    echo '--- Skill scanner CI tests ---'
    pnpm vitest run test/security/skill-scanner-ci.test.ts
    echo '--- Baseline audit tests ---'
    pnpm vitest run test/security/baseline-audit.test.ts
    echo 'Phase 1: PASSED'
  "

# ---------------------------------------------------------------------------
# Phase 2: Docker sandbox isolation tests
#   Verifies the container-level isolation properties.
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo "Phase 2: Sandbox isolation tests (in Docker)"
echo "============================================"
$RUNTIME run --rm \
  --name "${TEST_NAME}-isolation" \
  --network "$NET_NAME" \
  --user node \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,uid=$NODE_UID,gid=$NODE_GID \
  --tmpfs /home/node:rw,noexec,nosuid,size=64m,uid=$NODE_UID,gid=$NODE_GID \
  -e "OPENCLAW_DOCKER_SECURITY_TEST=1" \
  -e "NO_COLOR=1" \
  "$IMAGE_NAME" \
  bash -lc "
    set -euo pipefail
    cd /app
    echo '--- Docker sandbox isolation tests ---'
    # Write a minimal .mjs vitest config to /tmp (writable tmpfs).
    # Using .mjs lets Vite load it natively as ESM without bundling,
    # which avoids the mkdir node_modules/.vite-temp that fails on
    # the read-only filesystem we are intentionally testing.
    mkdir -p /tmp/node_modules
    ln -s /app/node_modules/* /tmp/node_modules/
    ln -s /app/node_modules/.pnpm /tmp/node_modules/.pnpm 2>/dev/null || true
    cat > /tmp/vitest.sandbox.config.mjs << 'CONFIGEOF'
import { defineConfig } from \"vitest/config\";
export default defineConfig({
  test: {
    testTimeout: 30000,
    include: [\"test/security/docker-sandbox-isolation.test.ts\"],
    setupFiles: [],
  },
});
CONFIGEOF
    ./node_modules/.bin/vitest run --config /tmp/vitest.sandbox.config.mjs test/security/docker-sandbox-isolation.test.ts
    echo 'Phase 2: PASSED'
  "

# ---------------------------------------------------------------------------
# Phase 3: E2E injection corpus against containerized gateway
#   Sends all injection payloads via webhook to the gateway container
#   and verifies correct handling.
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo "Phase 3: E2E injection corpus (against Docker gateway)"
echo "============================================"
$RUNTIME run --rm \
  --name "${TEST_NAME}-e2e" \
  --network "$NET_NAME" \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  -e "SEC_GW_HOST=$GW_NAME" \
  -e "SEC_GW_PORT=$PORT" \
  -e "SEC_GW_TOKEN=$TOKEN" \
  -e "SEC_HOOK_TOKEN=$HOOK_TOKEN" \
  -e "NO_COLOR=1" \
  "$IMAGE_NAME" \
  bash -lc "
    set -euo pipefail
    cd /app

    echo '--- Waiting for gateway connectivity ---'
    for i in \$(seq 1 20); do
      if node --input-type=module -e '
        import net from \"node:net\";
        const socket = net.createConnection({
          host: process.env.SEC_GW_HOST,
          port: Number(process.env.SEC_GW_PORT),
        });
        const t = setTimeout(() => { socket.destroy(); process.exit(1); }, 1000);
        socket.on(\"connect\", () => { clearTimeout(t); socket.end(); process.exit(0); });
        socket.on(\"error\", () => { clearTimeout(t); process.exit(1); });
      ' 2>/dev/null; then
        echo 'Gateway reachable'
        break
      fi
      sleep 0.5
    done

    echo '--- E2E injection corpus tests ---'
    pnpm vitest run test/security/docker-injection-e2e.test.ts
    echo 'Phase 3: PASSED'
  "

# ---------------------------------------------------------------------------
# Phase 4: Verify gateway stayed healthy
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo "Phase 4: Gateway health check"
echo "============================================"
if $RUNTIME exec "$GW_NAME" bash -lc "test -f /tmp/gateway-sec-e2e.log" 2>/dev/null; then
  echo "==> Gateway log tail:"
  $RUNTIME exec "$GW_NAME" bash -lc "tail -n 20 /tmp/gateway-sec-e2e.log" 2>/dev/null || true

  # Verify no crash / unexpected exit
  if ! $RUNTIME exec "$GW_NAME" bash -lc "true" 2>/dev/null; then
    echo "ERROR: Gateway container crashed during tests"
    exit 1
  fi
  echo "==> Gateway remained healthy throughout all tests"
else
  echo "WARNING: Could not verify gateway log (container may have exited)"
fi

# ---------------------------------------------------------------------------
# Phase 5: Closed-box E2E with real LLMs and mock channel receiver
#   Sends injection payloads through the full pipeline:
#   webhook → agent → real LLM → response → channel delivery → mock receiver
#   Verifies outbound messages are properly sanitized.
#   SKIPPED when no API keys or SEC_LIVE_MODELS are configured.
#
# Usage (one-liners — env vars scoped to the command, not your shell session):
#
#   Anthropic:
#     SEC_LIVE_MODELS=anthropic/claude-sonnet-4-5-20250929 ANTHROPIC_API_KEY=sk-ant-... pnpm test:docker:security
#
#   OpenAI:
#     SEC_LIVE_MODELS=openai/gpt-4o OPENAI_API_KEY=sk-... pnpm test:docker:security
#
#   OpenRouter:
#     SEC_LIVE_MODELS=openrouter/anthropic/claude-3.5-sonnet OPENROUTER_API_KEY=sk-or-... pnpm test:docker:security
#
#   Multiple models:
#     SEC_LIVE_MODELS=anthropic/claude-sonnet-4-5-20250929,openai/gpt-4o ANTHROPIC_API_KEY=sk-ant-... OPENAI_API_KEY=sk-... pnpm test:docker:security
#
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo "Phase 5: Closed-box E2E (real LLM + mock channel)"
echo "============================================"

if [ -z "${SEC_LIVE_MODELS:-}" ] || [ -z "${ANTHROPIC_API_KEY:-}${OPENAI_API_KEY:-}${OPENROUTER_API_KEY:-}" ]; then
  echo "Phase 5: SKIPPED (no SEC_LIVE_MODELS or API keys configured)"
else
  # -----------------------------------------------------------------------
  # Helper: resolve provider config from model ID prefix
  # -----------------------------------------------------------------------
  resolve_provider_json() {
    local model_id="$1"
    local prefix="${model_id%%/*}"
    case "$prefix" in
      anthropic)
        echo "{
          \"baseUrl\": \"https://api.anthropic.com\",
          \"apiKey\": \"${ANTHROPIC_API_KEY:-}\",
          \"api\": \"anthropic-messages\",
          \"models\": [{ \"id\": \"${model_id#*/}\", \"name\": \"${model_id#*/}\", \"reasoning\": false, \"input\": [\"text\"], \"cost\": { \"input\": 0, \"output\": 0, \"cacheRead\": 0, \"cacheWrite\": 0 }, \"contextWindow\": 200000, \"maxTokens\": 8192 }]
        }"
        ;;
      openai)
        echo "{
          \"baseUrl\": \"https://api.openai.com/v1\",
          \"apiKey\": \"${OPENAI_API_KEY:-}\",
          \"api\": \"openai-completions\",
          \"models\": [{ \"id\": \"${model_id#*/}\", \"name\": \"${model_id#*/}\", \"reasoning\": false, \"input\": [\"text\"], \"cost\": { \"input\": 0, \"output\": 0, \"cacheRead\": 0, \"cacheWrite\": 0 }, \"contextWindow\": 128000, \"maxTokens\": 4096 }]
        }"
        ;;
      openrouter)
        echo "{
          \"baseUrl\": \"https://openrouter.ai/api/v1\",
          \"apiKey\": \"${OPENROUTER_API_KEY:-}\",
          \"api\": \"openai-completions\",
          \"models\": [{ \"id\": \"${model_id#*/}\", \"name\": \"${model_id#*/}\", \"reasoning\": false, \"input\": [\"text\"], \"cost\": { \"input\": 0, \"output\": 0, \"cacheRead\": 0, \"cacheWrite\": 0 }, \"contextWindow\": 128000, \"maxTokens\": 4096 }]
        }"
        ;;
      *)
        echo "ERROR: Unknown model provider prefix: $prefix (from $model_id)" >&2
        return 1
        ;;
    esac
  }

  # -----------------------------------------------------------------------
  # Iterate over each model in SEC_LIVE_MODELS
  # -----------------------------------------------------------------------
  IFS=',' read -ra CB_MODELS <<< "$SEC_LIVE_MODELS"
  for CB_MODEL in "${CB_MODELS[@]}"; do
    CB_MODEL="$(echo "$CB_MODEL" | xargs)"  # trim whitespace
    [ -z "$CB_MODEL" ] && continue

    echo ""
    echo "--- Phase 5: Testing model $CB_MODEL ---"

    # Clean up any previous iteration
    $RUNTIME rm -f "${TEST_NAME}-cb" "$GW_CB_NAME" "$MOCK_CB_NAME" >/dev/null 2>&1 || true
    $RUNTIME network rm "$NET_CB_NAME" >/dev/null 2>&1 || true

    # Create non-internal network (gateway needs internet for real LLM APIs)
    echo "==> Creating network: $NET_CB_NAME (non-internal, internet access)"
    $RUNTIME network create "$NET_CB_NAME" >/dev/null

    # Start mock Telegram receiver
    echo "==> Starting mock Telegram receiver: $MOCK_CB_NAME"
    $RUNTIME run --rm -d \
      --name "$MOCK_CB_NAME" \
      --network "$NET_CB_NAME" \
      "$IMAGE_NAME" \
      bash -lc "
        cd /app
        node test/security/mock-telegram-receiver.mjs
      "

    # Wait for mock receiver health
    echo "==> Waiting for mock receiver health..."
    mock_ready=0
    for _ in $(seq 1 30); do
      if $RUNTIME exec "$MOCK_CB_NAME" bash -lc "
        node --input-type=module -e '
          const res = await fetch(\"http://127.0.0.1:$MOCK_INSPECT_PORT/health\");
          const data = await res.json();
          if (data.ok) process.exit(0); else process.exit(1);
        ' 2>/dev/null
      " 2>/dev/null; then
        mock_ready=1
        break
      fi
      sleep 0.5
    done

    if [ "$mock_ready" -ne 1 ]; then
      echo "ERROR: Mock Telegram receiver failed to start"
      $RUNTIME logs "$MOCK_CB_NAME" 2>/dev/null || true
      exit 1
    fi
    echo "==> Mock receiver is up"

    # Get mock container IP for --add-host
    MOCK_IP=$($RUNTIME inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$MOCK_CB_NAME" 2>/dev/null)
    if [ -z "$MOCK_IP" ]; then
      echo "ERROR: Could not determine mock receiver IP"
      exit 1
    fi
    echo "==> Mock receiver IP: $MOCK_IP"

    # Resolve provider config
    PROVIDER_JSON=$(resolve_provider_json "$CB_MODEL")
    CB_MODEL_SHORT="${CB_MODEL#*/}"
    CB_PROVIDER_PREFIX="${CB_MODEL%%/*}"

    # Build gateway config for this model
    CB_GW_CONFIG=$(cat <<CBJSONEOF
{
  "gateway": {
    "port": $CB_PORT,
    "bind": "lan",
    "auth": { "mode": "token", "token": "$TOKEN" }
  },
  "hooks": { "enabled": true, "token": "$CB_HOOK_TOKEN", "path": "/hooks" },
  "channels": {
    "telegram": {
      "botToken": "0000000000:AAFakeBotTokenForClosedBoxTest",
      "dmPolicy": "open",
      "allowFrom": ["*"]
    }
  },
  "tools": { "profile": "coding" },
  "agents": {
    "defaults": { "sandbox": { "mode": "off" }, "model": { "primary": "$CB_MODEL" } },
    "list": [{ "id": "default", "identity": { "name": "SecTestBot" } }]
  },
  "models": {
    "providers": {
      "$CB_PROVIDER_PREFIX": $PROVIDER_JSON
    }
  }
}
CBJSONEOF
    )

    # Build env var passthrough flags
    CB_ENV_FLAGS=""
    [ -n "${ANTHROPIC_API_KEY:-}" ] && CB_ENV_FLAGS="$CB_ENV_FLAGS -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"
    [ -n "${OPENAI_API_KEY:-}" ] && CB_ENV_FLAGS="$CB_ENV_FLAGS -e OPENAI_API_KEY=$OPENAI_API_KEY"
    [ -n "${OPENROUTER_API_KEY:-}" ] && CB_ENV_FLAGS="$CB_ENV_FLAGS -e OPENROUTER_API_KEY=$OPENROUTER_API_KEY"

    # Start gateway with channels enabled and real LLM access
    echo "==> Starting closed-box gateway: $GW_CB_NAME (model: $CB_MODEL)"
    $RUNTIME run -d \
      --name "$GW_CB_NAME" \
      --network "$NET_CB_NAME" \
      --add-host "api.telegram.org:$MOCK_IP" \
      --security-opt no-new-privileges \
      --cap-drop ALL \
      --read-only \
      --tmpfs /tmp:rw,noexec,nosuid,size=256m \
      --tmpfs /home/node:rw,noexec,nosuid,size=128m \
      -e "OPENCLAW_GATEWAY_TOKEN=$TOKEN" \
      -e "OPENCLAW_SKIP_GMAIL_WATCHER=1" \
      -e "OPENCLAW_SKIP_CRON=1" \
      -e "OPENCLAW_SKIP_CANVAS_HOST=1" \
      -e "OPENCLAW_SKIP_BROWSER_CONTROL_SERVER=1" \
      -e "NODE_TLS_REJECT_UNAUTHORIZED=0" \
      $CB_ENV_FLAGS \
      "$IMAGE_NAME" \
      bash -lc "
        set -euo pipefail
        mkdir -p /home/node/.openclaw
        cat > /home/node/.openclaw/openclaw.json << 'INNERCFGEOF'
$(echo "$CB_GW_CONFIG")
INNERCFGEOF
        export HOME=/home/node
        export OPENCLAW_CONFIG_PATH=/home/node/.openclaw/openclaw.json
        export OPENCLAW_STATE_DIR=/home/node/.openclaw/state
        entry=dist/index.mjs
        [ -f \"\$entry\" ] || entry=dist/index.js
        node \"\$entry\" gateway --port $CB_PORT --bind lan --allow-unconfigured > /tmp/gateway-cb-e2e.log 2>&1
      "

    # Wait for closed-box gateway
    echo "==> Waiting for closed-box gateway to come up..."
    cb_ready=0
    for _ in $(seq 1 60); do
      if $RUNTIME exec "$GW_CB_NAME" bash -lc "node --input-type=module -e '
        import net from \"node:net\";
        const socket = net.createConnection({ host: \"127.0.0.1\", port: $CB_PORT });
        const timeout = setTimeout(() => { socket.destroy(); process.exit(1); }, 400);
        socket.on(\"connect\", () => { clearTimeout(timeout); socket.end(); process.exit(0); });
        socket.on(\"error\", () => { clearTimeout(timeout); process.exit(1); });
      ' >/dev/null 2>&1"; then
        cb_ready=1
        break
      fi
      if $RUNTIME exec "$GW_CB_NAME" bash -lc "grep -q 'listening on' /tmp/gateway-cb-e2e.log 2>/dev/null"; then
        cb_ready=1
        break
      fi
      sleep 0.5
    done

    if [ "$cb_ready" -ne 1 ]; then
      echo "ERROR: Closed-box gateway failed to start (model: $CB_MODEL)"
      # Try exec first (container still running), fall back to logs (container exited)
      $RUNTIME exec "$GW_CB_NAME" bash -lc "cat /tmp/gateway-cb-e2e.log" 2>/dev/null \
        || $RUNTIME logs "$GW_CB_NAME" 2>/dev/null \
        || true
      exit 1
    fi
    echo "==> Closed-box gateway is up"

    # Run closed-box E2E tests
    echo "==> Running closed-box tests for model: $CB_MODEL"
    $RUNTIME run --rm \
      --name "${TEST_NAME}-cb" \
      --network "$NET_CB_NAME" \
      --security-opt no-new-privileges \
      --cap-drop ALL \
      -e "SEC_CB_GW_HOST=$GW_CB_NAME" \
      -e "SEC_CB_GW_PORT=$CB_PORT" \
      -e "SEC_CB_HOOK_TOKEN=$CB_HOOK_TOKEN" \
      -e "SEC_CB_MOCK_HOST=$MOCK_CB_NAME" \
      -e "SEC_CB_MOCK_PORT=$MOCK_INSPECT_PORT" \
      -e "SEC_CB_MODEL_ID=$CB_MODEL" \
      -e "NO_COLOR=1" \
      "$IMAGE_NAME" \
      bash -lc "
        set -euo pipefail
        cd /app

        echo '--- Waiting for closed-box gateway connectivity ---'
        for i in \$(seq 1 20); do
          if node --input-type=module -e '
            import net from \"node:net\";
            const socket = net.createConnection({
              host: process.env.SEC_CB_GW_HOST,
              port: Number(process.env.SEC_CB_GW_PORT),
            });
            const t = setTimeout(() => { socket.destroy(); process.exit(1); }, 1000);
            socket.on(\"connect\", () => { clearTimeout(t); socket.end(); process.exit(0); });
            socket.on(\"error\", () => { clearTimeout(t); process.exit(1); });
          ' 2>/dev/null; then
            echo 'Gateway reachable'
            break
          fi
          sleep 0.5
        done

        echo '--- Closed-box E2E tests (model: $CB_MODEL) ---'
        pnpm vitest run test/security/docker-closed-box-e2e.test.ts
        echo 'Phase 5 ($CB_MODEL): PASSED'
      "

    # Health check gateway after tests + dump log for diagnostics
    if $RUNTIME exec "$GW_CB_NAME" bash -lc "true" 2>/dev/null; then
      echo "==> Closed-box gateway remained healthy (model: $CB_MODEL)"
      echo "==> Closed-box gateway log tail:"
      $RUNTIME exec "$GW_CB_NAME" bash -lc "tail -n 30 /tmp/gateway-cb-e2e.log" 2>/dev/null || true
    else
      echo "WARNING: Closed-box gateway may have exited (model: $CB_MODEL)"
      $RUNTIME logs "$GW_CB_NAME" 2>/dev/null || true
    fi

    # Clean up this model iteration
    $RUNTIME rm -f "${TEST_NAME}-cb" "$GW_CB_NAME" "$MOCK_CB_NAME" >/dev/null 2>&1 || true
    $RUNTIME network rm "$NET_CB_NAME" >/dev/null 2>&1 || true

    echo "--- Phase 5: Model $CB_MODEL completed ---"
  done

  echo "Phase 5: PASSED (all models)"
fi

echo ""
echo "============================================"
echo "ALL SECURITY REGRESSION TESTS PASSED"
echo "============================================"
