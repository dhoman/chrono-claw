import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyWebhookSignature, type WebhookSignatureConfig } from "./webhook-hmac.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hmacHex(algorithm: string, secret: string, body: string): string {
  return crypto.createHmac(algorithm, secret).update(body).digest("hex");
}

function hmacBase64(algorithm: string, secret: string, body: string): string {
  return crypto.createHmac(algorithm, secret).update(body).digest("base64");
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 (GitHub-style)
// ---------------------------------------------------------------------------

describe("verifyWebhookSignature — hmac-sha256", () => {
  const secret = "gh-webhook-secret";
  const body = JSON.stringify({ action: "push", ref: "refs/heads/main" });

  const config: WebhookSignatureConfig = {
    type: "hmac-sha256",
    header: "x-hub-signature-256",
    secret,
    prefix: "sha256=",
  };

  it("accepts a valid sha256= prefixed hex signature", () => {
    const sig = `sha256=${hmacHex("sha256", secret, body)}`;
    expect(verifyWebhookSignature({ config, headerValue: sig, rawBody: body })).toBe(true);
  });

  it("rejects a signature computed with the wrong secret", () => {
    const sig = `sha256=${hmacHex("sha256", "wrong-secret", body)}`;
    expect(verifyWebhookSignature({ config, headerValue: sig, rawBody: body })).toBe(false);
  });

  it("rejects a missing header value", () => {
    expect(verifyWebhookSignature({ config, headerValue: undefined, rawBody: body })).toBe(false);
  });

  it("rejects an empty header value", () => {
    expect(verifyWebhookSignature({ config, headerValue: "", rawBody: body })).toBe(false);
  });

  it("rejects a truncated signature", () => {
    const sig = `sha256=${hmacHex("sha256", secret, body).slice(0, 10)}`;
    expect(verifyWebhookSignature({ config, headerValue: sig, rawBody: body })).toBe(false);
  });

  it("rejects a signature without the expected prefix", () => {
    const sig = hmacHex("sha256", secret, body);
    expect(verifyWebhookSignature({ config, headerValue: sig, rawBody: body })).toBe(false);
  });

  it("accepts base64-encoded signature when configured", () => {
    const b64Config: WebhookSignatureConfig = {
      type: "hmac-sha256",
      header: "x-signature",
      secret,
      encoding: "base64",
    };
    const sig = hmacBase64("sha256", secret, body);
    expect(verifyWebhookSignature({ config: b64Config, headerValue: sig, rawBody: body })).toBe(
      true,
    );
  });
});

// ---------------------------------------------------------------------------
// HMAC-SHA1 (legacy GitHub-style)
// ---------------------------------------------------------------------------

describe("verifyWebhookSignature — hmac-sha1", () => {
  const secret = "legacy-secret";
  const body = JSON.stringify({ event: "test" });

  const config: WebhookSignatureConfig = {
    type: "hmac-sha1",
    header: "x-hub-signature",
    secret,
    prefix: "sha1=",
  };

  it("accepts a valid sha1= prefixed hex signature", () => {
    const sig = `sha1=${hmacHex("sha1", secret, body)}`;
    expect(verifyWebhookSignature({ config, headerValue: sig, rawBody: body })).toBe(true);
  });

  it("rejects a signature computed with the wrong secret", () => {
    const sig = `sha1=${hmacHex("sha1", "wrong", body)}`;
    expect(verifyWebhookSignature({ config, headerValue: sig, rawBody: body })).toBe(false);
  });

  it("rejects a missing header", () => {
    expect(verifyWebhookSignature({ config, headerValue: undefined, rawBody: body })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Token (GitLab-style)
// ---------------------------------------------------------------------------

describe("verifyWebhookSignature — token", () => {
  const secret = "gitlab-token-value";

  const config: WebhookSignatureConfig = {
    type: "token",
    header: "x-gitlab-token",
    secret,
  };

  it("accepts a matching token", () => {
    expect(verifyWebhookSignature({ config, headerValue: secret, rawBody: "{}" })).toBe(true);
  });

  it("rejects a wrong token", () => {
    expect(verifyWebhookSignature({ config, headerValue: "wrong-token", rawBody: "{}" })).toBe(
      false,
    );
  });

  it("rejects a missing header", () => {
    expect(verifyWebhookSignature({ config, headerValue: undefined, rawBody: "{}" })).toBe(false);
  });

  it("rejects an empty header", () => {
    expect(verifyWebhookSignature({ config, headerValue: "", rawBody: "{}" })).toBe(false);
  });
});
