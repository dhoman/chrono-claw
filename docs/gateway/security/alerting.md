# Security Event Alerting

OpenClaw emits structured security events for tool denials, SSRF blocks, DLP redactions, and injection pattern detection. These events flow through the standard subsystem logger (`security/events`) and can be filtered from logs for monitoring and alerting.

## Enabling JSON Logging

To get machine-parseable log output, set the console style to JSON in your config:

```json
{
  "logging": {
    "console": {
      "style": "json"
    }
  }
}
```

Each log line will be a JSON object with `time`, `level`, `subsystem`, `message`, and structured metadata fields.

## Security Event Types

All security events include an `event` field for filtering:

| Event                | Level | Description                                            |
| -------------------- | ----- | ------------------------------------------------------ |
| `tool_denied`        | warn  | A tool was blocked by the policy pipeline              |
| `ssrf_blocked`       | warn  | A URL fetch was blocked by SSRF protection             |
| `dlp_redaction`      | info  | Sensitive data was redacted from outbound content      |
| `injection_detected` | warn  | Prompt injection patterns detected in external content |

### Event Fields

**tool_denied**

- `tool`: Name of the denied tool
- `agent`: Agent ID (if available)
- `session`: Session ID (if available)
- `reason`: Why the tool was denied

**ssrf_blocked**

- `target`: The blocked URL origin+path
- `reason`: SSRF rule that triggered the block
- `auditContext`: Context label (e.g., `web_fetch`)

**dlp_redaction**

- `field`: Which field was redacted
- `patternCount`: Number of patterns matched
- `location`: Where redaction occurred

**injection_detected**

- `patterns`: List of matched pattern sources (max 5)
- `patternCount`: Total number of matches
- `session`: Session key (if available)
- `source`: Content source type (e.g., `email`, `webhook`)

## Filtering Security Events

### Using jq

Extract all security events from JSON log output:

```bash
openclaw 2>&1 | jq -c 'select(.subsystem == "security/events")'
```

Filter by specific event type:

```bash
openclaw 2>&1 | jq -c 'select(.event == "ssrf_blocked")'
```

Filter warn-level security events only:

```bash
openclaw 2>&1 | jq -c 'select(.subsystem == "security/events" and .level == "warn")'
```

### From Log Files

If logging to a file, filter after the fact:

```bash
cat ~/.openclaw/logs/openclaw.log | jq -c 'select(.event == "tool_denied")' 2>/dev/null
```

## Alerting Examples

### Pipe to Slack Webhook on Repeated Denials

```bash
openclaw 2>&1 | jq -c --unbuffered 'select(.event == "ssrf_blocked" or .event == "injection_detected")' | while read -r line; do
  curl -s -X POST "$SLACK_WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"text\": \"Security event: $(echo "$line" | jq -r '.event') - $(echo "$line" | jq -r '.message')\"}"
done
```

### Pipe to Discord Webhook

```bash
openclaw 2>&1 | jq -c --unbuffered 'select(.subsystem == "security/events" and .level == "warn")' | while read -r line; do
  curl -s -X POST "$DISCORD_WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"content\": \"[security] $(echo "$line" | jq -r '.message')\"}"
done
```

### Count Events Over Time

```bash
# Count security events in the last hour
cat ~/.openclaw/logs/openclaw.log \
  | jq -c 'select(.subsystem == "security/events")' 2>/dev/null \
  | jq -r '.event' \
  | sort | uniq -c | sort -rn
```
