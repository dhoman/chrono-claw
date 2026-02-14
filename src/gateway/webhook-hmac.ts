import crypto from "node:crypto";
import { safeEqualSecret } from "../security/secret-equal.js";

export type WebhookSignatureConfig = {
  type: "hmac-sha256" | "hmac-sha1" | "token";
  header: string;
  secret: string;
  /** Prefix to strip from header value before comparison (e.g., "sha256=") */
  prefix?: string;
  /** Encoding of the signature (default: "hex" for HMAC, ignored for token) */
  encoding?: "hex" | "base64";
};

export function verifyWebhookSignature(params: {
  config: WebhookSignatureConfig;
  headerValue: string | undefined;
  rawBody: string;
}): boolean {
  const { config, headerValue, rawBody } = params;

  if (typeof headerValue !== "string" || !headerValue) {
    return false;
  }

  if (config.type === "token") {
    return safeEqualSecret(headerValue, config.secret);
  }

  const algorithm = config.type === "hmac-sha256" ? "sha256" : "sha1";
  const encoding = config.encoding ?? "hex";

  let signatureValue = headerValue;
  if (config.prefix) {
    if (!signatureValue.startsWith(config.prefix)) {
      return false;
    }
    signatureValue = signatureValue.slice(config.prefix.length);
  }

  const expected = crypto.createHmac(algorithm, config.secret).update(rawBody).digest(encoding);

  const expectedBuffer = Buffer.from(expected);
  const providedBuffer = Buffer.from(signatureValue);

  if (expectedBuffer.length !== providedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, providedBuffer);
}
