import type { ReplyPayload } from "../../auto-reply/types.js";
import { parseReplyDirectives } from "../../auto-reply/reply/reply-directives.js";
import { isRenderablePayload } from "../../auto-reply/reply/reply-payloads.js";
import { redactSensitiveText } from "../../logging/redact.js";

export type NormalizedOutboundPayload = {
  text: string;
  mediaUrls: string[];
  channelData?: Record<string, unknown>;
};

export type OutboundPayloadJson = {
  text: string;
  mediaUrl: string | null;
  mediaUrls?: string[];
  channelData?: Record<string, unknown>;
};

function mergeMediaUrls(...lists: Array<Array<string | undefined> | undefined>): string[] {
  const seen = new Set<string>();
  const merged: string[] = [];
  for (const list of lists) {
    if (!list) {
      continue;
    }
    for (const entry of list) {
      const trimmed = entry?.trim();
      if (!trimmed) {
        continue;
      }
      if (seen.has(trimmed)) {
        continue;
      }
      seen.add(trimmed);
      merged.push(trimmed);
    }
  }
  return merged;
}

function redactMediaUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const params = parsed.searchParams;
    let changed = false;
    for (const [key, value] of params.entries()) {
      const redacted = redactSensitiveText(value);
      if (redacted !== value) {
        params.set(key, redacted);
        changed = true;
      }
    }
    return changed ? parsed.toString() : url;
  } catch {
    return redactSensitiveText(url);
  }
}

function redactChannelDataStrings(data: unknown): unknown {
  if (typeof data === "string") {
    return redactSensitiveText(data);
  }
  if (Array.isArray(data)) {
    return data.map(redactChannelDataStrings);
  }
  if (data !== null && typeof data === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      result[key] = redactChannelDataStrings(value);
    }
    return result;
  }
  return data;
}

export function redactOutboundPayload(payload: ReplyPayload): ReplyPayload {
  const next: ReplyPayload = { ...payload };
  if (next.text) {
    next.text = redactSensitiveText(next.text);
  }
  if (next.mediaUrl) {
    next.mediaUrl = redactMediaUrl(next.mediaUrl);
  }
  if (next.mediaUrls) {
    next.mediaUrls = next.mediaUrls.map(redactMediaUrl);
  }
  if (next.channelData) {
    next.channelData = redactChannelDataStrings(next.channelData) as Record<string, unknown>;
  }
  return next;
}

export function normalizeReplyPayloadsForDelivery(payloads: ReplyPayload[]): ReplyPayload[] {
  return payloads.flatMap((payload) => {
    const parsed = parseReplyDirectives(payload.text ?? "");
    const explicitMediaUrls = payload.mediaUrls ?? parsed.mediaUrls;
    const explicitMediaUrl = payload.mediaUrl ?? parsed.mediaUrl;
    const mergedMedia = mergeMediaUrls(
      explicitMediaUrls,
      explicitMediaUrl ? [explicitMediaUrl] : undefined,
    );
    const hasMultipleMedia = (explicitMediaUrls?.length ?? 0) > 1;
    const resolvedMediaUrl = hasMultipleMedia ? undefined : explicitMediaUrl;
    const next: ReplyPayload = {
      ...payload,
      text: parsed.text ? redactSensitiveText(parsed.text) : "",
      mediaUrls: mergedMedia.length ? mergedMedia.map(redactMediaUrl) : undefined,
      mediaUrl: resolvedMediaUrl ? redactMediaUrl(resolvedMediaUrl) : resolvedMediaUrl,
      replyToId: payload.replyToId ?? parsed.replyToId,
      replyToTag: payload.replyToTag || parsed.replyToTag,
      replyToCurrent: payload.replyToCurrent || parsed.replyToCurrent,
      audioAsVoice: Boolean(payload.audioAsVoice || parsed.audioAsVoice),
    };
    if (next.channelData) {
      next.channelData = redactChannelDataStrings(next.channelData) as Record<string, unknown>;
    }
    if (parsed.isSilent && mergedMedia.length === 0) {
      return [];
    }
    if (!isRenderablePayload(next)) {
      return [];
    }
    return [next];
  });
}

export function normalizeOutboundPayloads(payloads: ReplyPayload[]): NormalizedOutboundPayload[] {
  return normalizeReplyPayloadsForDelivery(payloads)
    .map((payload) => {
      const channelData = payload.channelData;
      const normalized: NormalizedOutboundPayload = {
        text: payload.text ?? "",
        mediaUrls: payload.mediaUrls ?? (payload.mediaUrl ? [payload.mediaUrl] : []),
      };
      if (channelData && Object.keys(channelData).length > 0) {
        normalized.channelData = channelData;
      }
      return normalized;
    })
    .filter(
      (payload) =>
        payload.text ||
        payload.mediaUrls.length > 0 ||
        Boolean(payload.channelData && Object.keys(payload.channelData).length > 0),
    );
}

export function normalizeOutboundPayloadsForJson(payloads: ReplyPayload[]): OutboundPayloadJson[] {
  return normalizeReplyPayloadsForDelivery(payloads).map((payload) => ({
    text: payload.text ?? "",
    mediaUrl: payload.mediaUrl ?? null,
    mediaUrls: payload.mediaUrls ?? (payload.mediaUrl ? [payload.mediaUrl] : undefined),
    channelData: payload.channelData,
  }));
}

export function formatOutboundPayloadLog(payload: NormalizedOutboundPayload): string {
  const lines: string[] = [];
  if (payload.text) {
    lines.push(payload.text.trimEnd());
  }
  for (const url of payload.mediaUrls) {
    lines.push(`MEDIA:${url}`);
  }
  return lines.join("\n");
}
