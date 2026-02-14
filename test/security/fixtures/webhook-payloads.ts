/**
 * Typed webhook payload fixtures for security E2E testing.
 *
 * Each fixture provides: name, path, headers, body, and optional expectedStatus.
 */

import crypto from "node:crypto";

export type WebhookFixture = {
  name: string;
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  expectedStatus?: number;
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

export const githubPushWebhook: WebhookFixture = {
  name: "github-push",
  path: "/hooks/wake",
  headers: {
    "X-GitHub-Event": "push",
    "X-GitHub-Delivery": "72d3162e-cc78-11e3-81ab-4c9367dc0958",
    "Content-Type": "application/json",
  },
  body: {
    ref: "refs/heads/main",
    repository: { full_name: "test-org/test-repo" },
    pusher: { name: "test-user" },
    head_commit: { id: "abc123", message: "test commit" },
    text: "GitHub push: test-org/test-repo main",
    mode: "now",
  },
  expectedStatus: 200,
};

export const gitlabPushWebhook: WebhookFixture = {
  name: "gitlab-push",
  path: "/hooks/wake",
  headers: {
    "X-Gitlab-Event": "Push Hook",
    "X-Gitlab-Token": "placeholder-token",
    "Content-Type": "application/json",
  },
  body: {
    object_kind: "push",
    ref: "refs/heads/main",
    project: { path_with_namespace: "test-group/test-project" },
    user_name: "test-user",
    text: "GitLab push: test-group/test-project",
    mode: "now",
  },
  expectedStatus: 200,
};

export const gmailPubSubWebhook: WebhookFixture = {
  name: "gmail-pubsub",
  path: "/hooks/wake",
  headers: {
    "Content-Type": "application/json",
  },
  body: {
    message: {
      data: Buffer.from(
        JSON.stringify({ emailAddress: "user@example.com", historyId: "12345" }),
      ).toString("base64"),
      messageId: "msg-001",
      publishTime: "2025-01-01T00:00:00Z",
    },
    subscription: "projects/test/subscriptions/gmail-push",
    text: "Gmail notification",
    mode: "now",
  },
  expectedStatus: 200,
};

export const genericJsonWebhook: WebhookFixture = {
  name: "generic-json",
  path: "/hooks/wake",
  headers: {
    "Content-Type": "application/json",
  },
  body: {
    text: "generic wake event",
    mode: "now",
  },
  expectedStatus: 200,
};

export const webhookWithSecret: WebhookFixture = {
  name: "webhook-with-secret",
  path: "/hooks/wake",
  headers: {
    "Content-Type": "application/json",
  },
  body: {
    text: "Here is my API key: sk-proj-1234567890abcdefghijklmnop and ghp_abcdefghijklmnopqrstu1234",
    mode: "now",
  },
  expectedStatus: 200,
};

// ---------------------------------------------------------------------------
// Signed webhook fixtures (for HMAC verification testing)
// ---------------------------------------------------------------------------

/**
 * Pre-computed HMAC-SHA256 signed fixture for GitHub-style webhook testing.
 * The secret and signature are deterministic so tests can verify both
 * acceptance (correct signature) and rejection (wrong signature).
 */
export const GITHUB_SIGNED_SECRET = "test-github-webhook-secret-32chars!!";

export const githubSignedWebhookBody = {
  action: "push",
  ref: "refs/heads/main",
  repository: { full_name: "test-org/test-repo" },
  sender: { login: "test-user" },
};

/** Compute GitHub-style sha256= HMAC hex signature for the given body. */
export function computeGitHubSignature(body: string, secret: string): string {
  return `sha256=${crypto.createHmac("sha256", secret).update(body).digest("hex")}`;
}

export const githubSignedWebhook: WebhookFixture = {
  name: "github-signed-push",
  path: "/hooks/github",
  headers: {
    "X-GitHub-Event": "push",
    "Content-Type": "application/json",
  },
  body: githubSignedWebhookBody,
  expectedStatus: 202,
};

export const ALL_FIXTURES: WebhookFixture[] = [
  githubPushWebhook,
  gitlabPushWebhook,
  gmailPubSubWebhook,
  genericJsonWebhook,
  webhookWithSecret,
];
