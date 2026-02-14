# Trust-Tier Configuration Guide

OpenClaw supports layered trust enforcement using existing configuration primitives: agent definitions, tool policies, bindings, sandbox settings, and webhook authentication. This guide documents three canonical tiers and how to configure them.

## Overview

| Tier | Label              | Auth                 | Sandbox | Tool Profile        | Use Case                          |
| ---- | ------------------ | -------------------- | ------- | ------------------- | --------------------------------- |
| A    | Trusted Operators  | Gateway token / CLI  | off     | full                | Admin CLI, operator dashboards    |
| B    | Verified Systems   | Webhook HMAC / token | all     | coding              | CI/CD hooks, GitHub/GitLab events |
| C    | Untrusted / Public | Channel auth (DM)    | all     | minimal + allowlist | Public Telegram/Discord bots      |

## Tier A: Trusted Operators

Trusted operators connect via the gateway WebSocket (CLI) or authenticated HTTP endpoints. They have full tool access and no sandbox restrictions.

```json5
{
  gateway: {
    auth: { mode: "token", token: "<strong-token>" },
  },
  tools: { profile: "full" },
  agents: {
    defaults: { sandbox: { mode: "off" } },
  },
}
```

Tier A is the default for operator CLI sessions. No additional agent configuration is needed.

## Tier B: Verified Systems

Verified systems authenticate via per-webhook HMAC signatures (GitHub, GitLab) or the shared hooks bearer token. They run in a sandboxed environment with the `coding` tool profile.

### Global hooks token (shared secret)

```json5
{
  hooks: {
    enabled: true,
    token: "<hooks-bearer-token>",
    mappings: [
      {
        id: "ci-notify",
        match: { path: "ci" },
        action: "agent",
        messageTemplate: "CI event: {{action}} on {{ref}}",
      },
    ],
  },
  agents: {
    defaults: { sandbox: { mode: "all" } },
  },
  tools: { profile: "coding" },
}
```

### Per-webhook HMAC signature (GitHub example)

```json5
{
  hooks: {
    enabled: true,
    token: "<global-token>", // still required for wake/agent endpoints
    mappings: [
      {
        id: "github",
        match: { path: "github" },
        action: "agent",
        agentId: "ci-agent",
        messageTemplate: "Push to {{ref}} by {{sender.login}}",
        webhookSignature: {
          type: "hmac-sha256",
          header: "x-hub-signature-256",
          secret: "<github-webhook-secret>",
          prefix: "sha256=",
        },
      },
    ],
  },
  agents: {
    list: [
      {
        id: "ci-agent",
        sandbox: { mode: "all", scope: "session" },
        tools: {
          allow: ["read", "exec", "write", "edit", "web_fetch"],
          deny: ["browser", "nodes", "cron", "gateway", "message"],
        },
      },
    ],
  },
}
```

### Per-webhook token (GitLab example)

```json5
{
  hooks: {
    enabled: true,
    token: "<global-token>",
    mappings: [
      {
        id: "gitlab",
        match: { path: "gitlab" },
        action: "agent",
        messageTemplate: "GitLab {{object_kind}}: {{project.path_with_namespace}}",
        webhookSignature: {
          type: "token",
          header: "x-gitlab-token",
          secret: "<gitlab-token-value>",
        },
      },
    ],
  },
}
```

When a mapping includes `webhookSignature`, the per-mapping signature is verified instead of the global hooks bearer token. This allows external services to authenticate directly without sharing the global token.

**Supported signature types:**

| Type          | Algorithm                | Header Example                      | Use Case      |
| ------------- | ------------------------ | ----------------------------------- | ------------- |
| `hmac-sha256` | HMAC-SHA256              | `X-Hub-Signature-256: sha256=<hex>` | GitHub        |
| `hmac-sha1`   | HMAC-SHA1                | `X-Hub-Signature: sha1=<hex>`       | Legacy GitHub |
| `token`       | Constant-time comparison | `X-Gitlab-Token: <secret>`          | GitLab        |

## Tier C: Untrusted / Public

Public channels (Telegram, Discord, etc.) expose the agent to untrusted user input. Use a dedicated agent with minimal tool access and full sandboxing.

### Reader agent configuration

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
  bindings: [{ agentId: "reader", match: { channel: "telegram" } }],
  session: {
    dmScope: "user",
  },
}
```

This configuration:

- **Sandboxes all tool calls** (`sandbox.mode: "all"`) with per-session isolation (`scope: "session"`)
- **Restricts tools** to read-only operations: `read` (file reading), `sessions_list`, and `sessions_history`
- **Denies dangerous tools**: `exec` (command execution), `write` (file writing), `browser`, `nodes`, `cron`, and `gateway`
- **Binds to a specific channel** via `bindings`, so only Telegram users get the restricted agent
- **Isolates DM sessions** per user with `session.dmScope: "user"`

### Combining tiers

A single deployment can serve all three tiers simultaneously. The key primitives:

- **`bindings`** route channels/sources to specific agents
- **`agents.list[].tools`** per-agent tool allow/deny lists
- **`agents.list[].sandbox`** per-agent sandbox mode
- **`webhookSignature`** per-mapping webhook authentication
- **`session.dmScope`** session isolation for DM channels

```json5
{
  // Tier A: operators get full access (default agent)
  tools: { profile: "full" },
  agents: {
    defaults: { sandbox: { mode: "off" } },
    list: [
      // Tier B: CI agent with coding profile
      {
        id: "ci-agent",
        sandbox: { mode: "all", scope: "session" },
        tools: {
          allow: ["read", "exec", "write", "edit", "web_fetch"],
          deny: ["browser", "nodes", "cron", "gateway", "message"],
        },
      },
      // Tier C: public reader agent
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
  hooks: {
    enabled: true,
    token: "<global-token>",
    mappings: [
      {
        id: "github",
        match: { path: "github" },
        action: "agent",
        agentId: "ci-agent",
        messageTemplate: "Push to {{ref}}",
        webhookSignature: {
          type: "hmac-sha256",
          header: "x-hub-signature-256",
          secret: "<github-secret>",
          prefix: "sha256=",
        },
      },
    ],
  },
  bindings: [
    { agentId: "reader", match: { channel: "telegram" } },
    { agentId: "reader", match: { channel: "discord" } },
  ],
  session: { dmScope: "user" },
}
```
