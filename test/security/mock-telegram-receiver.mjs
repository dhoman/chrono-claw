#!/usr/bin/env node
/**
 * Mock Telegram API Receiver for Phase 5 closed-box security testing.
 *
 * HTTPS on port 443 — impersonates api.telegram.org with a self-signed cert.
 * Handles grammy lifecycle calls (getMe, getUpdates) and captures sendMessage payloads.
 *
 * HTTP on port 9100 — inspection API for test assertions.
 *   GET  /health    → { ok: true }
 *   GET  /captured  → JSON array of captured sendMessage payloads
 *   DELETE /captured → clears captured messages
 */

import { execSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Self-signed certificate generation
// ---------------------------------------------------------------------------

const certDir = join(tmpdir(), `mock-tg-cert-${randomUUID()}`);
mkdirSync(certDir, { recursive: true });
const keyPath = join(certDir, "key.pem");
const certPath = join(certDir, "cert.pem");

execSync(
  `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" ` +
    `-days 1 -nodes -subj "/CN=api.telegram.org" 2>/dev/null`,
);

const tlsKey = readFileSync(keyPath);
const tlsCert = readFileSync(certPath);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** @type {Array<{chat_id: unknown, text: string, parse_mode?: string, ts: string}>} */
const captured = [];
let nextMessageId = 1;

// ---------------------------------------------------------------------------
// HTTPS server (mock Telegram Bot API — port 443)
// ---------------------------------------------------------------------------

/**
 * Parse request body as JSON.
 * @param {import("node:http").IncomingMessage} req
 * @returns {Promise<Record<string, unknown>>}
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

/**
 * Send JSON response.
 * @param {import("node:http").ServerResponse} res
 * @param {unknown} data
 * @param {number} [status=200]
 */
function json(res, data, status = 200) {
  const payload = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

const httpsServer = createHttpsServer({ key: tlsKey, cert: tlsCert }, async (req, res) => {
  const url = req.url ?? "/";
  const method = req.method ?? "GET";

  // All Telegram Bot API calls are POST /bot<token>/<method>
  const botMatch = url.match(/^\/bot[^/]+\/(\w+)/);
  if (!botMatch) {
    json(res, { ok: false, description: "Not Found" }, 404);
    return;
  }

  const apiMethod = botMatch[1];

  try {
    if (apiMethod === "getMe") {
      json(res, {
        ok: true,
        result: {
          id: 12345,
          is_bot: true,
          first_name: "SecurityTestBot",
          username: "security_test_bot",
        },
      });
      return;
    }

    if (apiMethod === "getUpdates") {
      json(res, { ok: true, result: [] });
      return;
    }

    if (apiMethod === "sendMessage") {
      const body = method === "POST" ? await readBody(req) : {};
      const entry = {
        chat_id: body.chat_id ?? null,
        text: typeof body.text === "string" ? body.text : String(body.text ?? ""),
        parse_mode: typeof body.parse_mode === "string" ? body.parse_mode : undefined,
        ts: new Date().toISOString(),
      };
      captured.push(entry);
      const msgId = nextMessageId++;
      json(res, {
        ok: true,
        result: {
          message_id: msgId,
          from: { id: 12345, is_bot: true, first_name: "SecurityTestBot" },
          chat: { id: body.chat_id ?? 0, type: "private" },
          date: Math.floor(Date.now() / 1000),
          text: entry.text,
        },
      });
      return;
    }

    // Catch-all for other grammy calls (deleteMessage, editMessageText, etc.)
    json(res, { ok: true, result: {} });
  } catch (err) {
    console.error(`[mock-telegram] Error handling ${apiMethod}:`, err);
    json(res, { ok: false, description: "Internal mock error" }, 500);
  }
});

// ---------------------------------------------------------------------------
// HTTP server (inspection API — port 9100)
// ---------------------------------------------------------------------------

const INSPECT_PORT = Number(process.env.MOCK_INSPECT_PORT ?? "9100");

const httpServer = createHttpServer((req, res) => {
  const url = req.url ?? "/";
  const method = req.method ?? "GET";

  if (url === "/health" && method === "GET") {
    json(res, { ok: true, captured: captured.length });
    return;
  }

  if (url === "/captured" && method === "GET") {
    json(res, captured);
    return;
  }

  if (url === "/captured" && method === "DELETE") {
    const count = captured.length;
    captured.length = 0;
    json(res, { ok: true, cleared: count });
    return;
  }

  json(res, { error: "not found" }, 404);
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

httpsServer.listen(443, "0.0.0.0", () => {
  console.log("[mock-telegram] HTTPS listening on :443 (api.telegram.org mock)");
});

httpServer.listen(INSPECT_PORT, "0.0.0.0", () => {
  console.log(`[mock-telegram] HTTP inspection API listening on :${INSPECT_PORT}`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  httpsServer.close();
  httpServer.close();
  process.exit(0);
});
process.on("SIGINT", () => {
  httpsServer.close();
  httpServer.close();
  process.exit(0);
});
