import { afterAll, describe, expect, it } from "vitest";
import { SANDBOX_MODES } from "./config-matrix.js";
import { genericJsonWebhook } from "./fixtures/webhook-payloads.js";
import {
  type SecurityGatewayInstance,
  postWebhook,
  spawnSecurityGateway,
  stopSecurityGateway,
} from "./harness.js";

const E2E_TIMEOUT_MS = 120_000;

describe("security harness", () => {
  const instances: SecurityGatewayInstance[] = [];

  afterAll(async () => {
    for (const inst of instances) {
      await stopSecurityGateway(inst);
    }
  });

  it(
    "smoke: boot gateway, POST webhook with auth, assert 200",
    { timeout: E2E_TIMEOUT_MS },
    async () => {
      const inst = await spawnSecurityGateway({ name: "smoke" });
      instances.push(inst);

      const res = await postWebhook(inst, genericJsonWebhook.path, genericJsonWebhook.body, {
        ...genericJsonWebhook.headers,
        "x-openclaw-token": inst.hookToken,
      });
      expect(res.status).toBe(200);
      expect((res.json as { ok?: boolean } | undefined)?.ok).toBe(true);
    },
  );

  it(
    "auth rejection: POST webhook without token returns 401 or 403",
    { timeout: E2E_TIMEOUT_MS },
    async () => {
      const inst = await spawnSecurityGateway({ name: "auth-reject" });
      instances.push(inst);

      const res = await postWebhook(
        inst,
        genericJsonWebhook.path,
        genericJsonWebhook.body,
        genericJsonWebhook.headers,
      );
      expect([401, 403]).toContain(res.status);
    },
  );

  describe.each(SANDBOX_MODES)("config matrix: $label", (matrixEntry) => {
    it(
      `boots gateway and accepts authenticated hooks (${matrixEntry.label})`,
      { timeout: E2E_TIMEOUT_MS },
      async () => {
        const inst = await spawnSecurityGateway({
          name: `matrix-${matrixEntry.label.replace(/[^a-z0-9]/gi, "-")}`,
          configOverrides: matrixEntry.config,
        });
        instances.push(inst);

        const res = await postWebhook(inst, genericJsonWebhook.path, genericJsonWebhook.body, {
          ...genericJsonWebhook.headers,
          "x-openclaw-token": inst.hookToken,
        });
        expect(res.status).toBe(200);
        expect((res.json as { ok?: boolean } | undefined)?.ok).toBe(true);
      },
    );
  });
});
