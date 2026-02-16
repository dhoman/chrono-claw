import { describe, expect, it } from "vitest";
import {
  formatOutboundPayloadLog,
  normalizeOutboundPayloads,
  normalizeOutboundPayloadsForJson,
  normalizeReplyPayloadsForDelivery,
  redactOutboundPayload,
} from "./payloads.js";

describe("normalizeOutboundPayloadsForJson", () => {
  it("normalizes payloads with mediaUrl and mediaUrls", () => {
    expect(
      normalizeOutboundPayloadsForJson([
        { text: "hi" },
        { text: "photo", mediaUrl: "https://x.test/a.jpg" },
        { text: "multi", mediaUrls: ["https://x.test/1.png"] },
      ]),
    ).toEqual([
      { text: "hi", mediaUrl: null, mediaUrls: undefined, channelData: undefined },
      {
        text: "photo",
        mediaUrl: "https://x.test/a.jpg",
        mediaUrls: ["https://x.test/a.jpg"],
        channelData: undefined,
      },
      {
        text: "multi",
        mediaUrl: null,
        mediaUrls: ["https://x.test/1.png"],
        channelData: undefined,
      },
    ]);
  });

  it("keeps mediaUrl null for multi MEDIA tags", () => {
    expect(
      normalizeOutboundPayloadsForJson([
        {
          text: "MEDIA:https://x.test/a.png\nMEDIA:https://x.test/b.png",
        },
      ]),
    ).toEqual([
      {
        text: "",
        mediaUrl: null,
        mediaUrls: ["https://x.test/a.png", "https://x.test/b.png"],
        channelData: undefined,
      },
    ]);
  });
});

describe("normalizeOutboundPayloads", () => {
  it("keeps channelData-only payloads", () => {
    const channelData = { line: { flexMessage: { altText: "Card", contents: {} } } };
    const normalized = normalizeOutboundPayloads([{ channelData }]);
    expect(normalized).toEqual([{ text: "", mediaUrls: [], channelData }]);
  });
});

describe("outbound DLP redaction", () => {
  it("redacts sk-* tokens from outbound text", () => {
    const result = normalizeReplyPayloadsForDelivery([
      { text: "Your key is sk-proj-1234567890abcdefghijklmnop" },
    ]);
    expect(result).toHaveLength(1);
    expect(result[0].text).not.toContain("sk-proj-1234567890abcdefghijklmnop");
    expect(result[0].text).toContain("sk-pro");
  });

  it("redacts ghp_* GitHub tokens from outbound text", () => {
    const result = normalizeReplyPayloadsForDelivery([
      { text: "Token: ghp_abcdefghijklmnopqrstu1234" },
    ]);
    expect(result).toHaveLength(1);
    expect(result[0].text).not.toContain("ghp_abcdefghijklmnopqrstu1234");
    expect(result[0].text).toContain("ghp_ab");
  });

  it("does not alter text without secrets", () => {
    const result = normalizeReplyPayloadsForDelivery([
      { text: "Hello, this is a normal message with no secrets." },
    ]);
    expect(result).toHaveLength(1);
    expect(result[0].text).toBe("Hello, this is a normal message with no secrets.");
  });

  it("preserves media URLs unchanged", () => {
    const result = normalizeReplyPayloadsForDelivery([
      {
        text: "Here is sk-proj-1234567890abcdefghijklmnop",
        mediaUrl: "https://example.com/image.png",
      },
    ]);
    expect(result).toHaveLength(1);
    expect(result[0].mediaUrl).toBe("https://example.com/image.png");
    expect(result[0].text).not.toContain("sk-proj-1234567890abcdefghijklmnop");
  });
});

describe("redactOutboundPayload", () => {
  it("redacts sk-* from text", () => {
    const result = redactOutboundPayload({
      text: "Your key is sk-proj-1234567890abcdefghijklmnop",
    });
    expect(result.text).not.toContain("sk-proj-1234567890abcdefghijklmnop");
    expect(result.text).toContain("sk-pro");
  });

  it("redacts tokens from mediaUrl query params", () => {
    const result = redactOutboundPayload({
      text: "here",
      mediaUrl: "https://example.com/img.png?token=sk-proj-1234567890abcdefghijklmnop",
    });
    expect(result.mediaUrl).not.toContain("sk-proj-1234567890abcdefghijklmnop");
    expect(result.mediaUrl).toContain("example.com/img.png");
  });

  it("redacts tokens from mediaUrls entries", () => {
    const result = redactOutboundPayload({
      text: "media",
      mediaUrls: [
        "https://example.com/a.png?key=sk-proj-1234567890abcdefghijklmnop",
        "https://example.com/b.png",
      ],
    });
    expect(result.mediaUrls![0]).not.toContain("sk-proj-1234567890abcdefghijklmnop");
    expect(result.mediaUrls![1]).toBe("https://example.com/b.png");
  });

  it("redacts string values in channelData (nested)", () => {
    const result = redactOutboundPayload({
      text: "ok",
      channelData: {
        telegram: {
          caption: "key is sk-proj-1234567890abcdefghijklmnop",
          nested: { deep: "ghp_abcdefghijklmnopqrstu1234" },
        },
        count: 42,
      },
    });
    const tg = result.channelData!.telegram as Record<string, unknown>;
    expect(tg.caption).not.toContain("sk-proj-1234567890abcdefghijklmnop");
    const nested = tg.nested as Record<string, unknown>;
    expect(nested.deep).not.toContain("ghp_abcdefghijklmnopqrstu1234");
    expect(result.channelData!.count).toBe(42);
  });

  it("preserves clean content unchanged", () => {
    const payload = {
      text: "Hello world",
      mediaUrl: "https://example.com/img.png",
      mediaUrls: ["https://example.com/a.png"],
      channelData: { telegram: { buttons: [] } },
    };
    const result = redactOutboundPayload(payload);
    expect(result.text).toBe("Hello world");
    expect(result.mediaUrl).toBe("https://example.com/img.png");
    expect(result.mediaUrls).toEqual(["https://example.com/a.png"]);
    expect(result.channelData).toEqual({ telegram: { buttons: [] } });
  });
});

describe("normalizeReplyPayloadsForDelivery mediaUrl redaction", () => {
  it("redacts tokens in mediaUrls", () => {
    const result = normalizeReplyPayloadsForDelivery([
      {
        text: "photo",
        mediaUrl: "https://example.com/img.png?token=sk-proj-1234567890abcdefghijklmnop",
      },
    ]);
    expect(result).toHaveLength(1);
    expect(result[0].mediaUrl).not.toContain("sk-proj-1234567890abcdefghijklmnop");
  });
});

describe("formatOutboundPayloadLog", () => {
  it("trims trailing text and appends media lines", () => {
    expect(
      formatOutboundPayloadLog({
        text: "hello  ",
        mediaUrls: ["https://x.test/a.png", "https://x.test/b.png"],
      }),
    ).toBe("hello\nMEDIA:https://x.test/a.png\nMEDIA:https://x.test/b.png");
  });

  it("logs media-only payloads", () => {
    expect(
      formatOutboundPayloadLog({
        text: "",
        mediaUrls: ["https://x.test/a.png"],
      }),
    ).toBe("MEDIA:https://x.test/a.png");
  });
});
