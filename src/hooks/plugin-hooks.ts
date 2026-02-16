import path from "node:path";
import { pathToFileURL } from "node:url";
import type { OpenClawPluginApi } from "../plugins/types.js";
import { shouldIncludeHook } from "./config.js";
import type { InternalHookHandler } from "./internal-hooks.js";
import type { HookEntry } from "./types.js";
import { loadHookEntriesFromDir } from "./workspace.js";

export type PluginHookLoadResult = {
  hooks: HookEntry[];
  loaded: number;
  skipped: number;
  errors: string[];
};

export function isContainedPath(baseDir: string, target: string): boolean {
  const relative = path.relative(baseDir, target);
  return Boolean(relative) && !relative.startsWith("..") && !path.isAbsolute(relative);
}

export function resolveHookDir(api: OpenClawPluginApi, dir: string): string {
  const pluginBaseDir = path.resolve(path.dirname(api.source));
  const resolved = path.isAbsolute(dir) ? path.resolve(dir) : path.resolve(pluginBaseDir, dir);
  if (!isContainedPath(pluginBaseDir, resolved) && resolved !== pluginBaseDir) {
    throw new Error(
      `Hook directory must be within the plugin directory: ${dir} resolves outside ${pluginBaseDir}`,
    );
  }
  return resolved;
}

function normalizePluginHookEntry(api: OpenClawPluginApi, entry: HookEntry): HookEntry {
  return {
    ...entry,
    hook: {
      ...entry.hook,
      source: "openclaw-plugin",
      pluginId: api.id,
    },
    metadata: {
      ...entry.metadata,
      hookKey: entry.metadata?.hookKey ?? `${api.id}:${entry.hook.name}`,
      events: entry.metadata?.events ?? [],
    },
  };
}

async function loadHookHandler(
  entry: HookEntry,
  api: OpenClawPluginApi,
): Promise<InternalHookHandler | null> {
  try {
    const pluginBaseDir = path.resolve(path.dirname(api.source));
    const resolvedHandler = path.resolve(entry.hook.handlerPath);
    if (!isContainedPath(pluginBaseDir, resolvedHandler) && resolvedHandler !== pluginBaseDir) {
      api.logger.warn?.(
        `[hooks] ${entry.hook.name} handler path escapes plugin directory: ${entry.hook.handlerPath}`,
      );
      return null;
    }
    const url = pathToFileURL(resolvedHandler).href;
    const cacheBustedUrl = `${url}?t=${Date.now()}`;
    const mod = (await import(cacheBustedUrl)) as Record<string, unknown>;
    const exportName = entry.metadata?.export ?? "default";
    const handler = mod[exportName];
    if (typeof handler === "function") {
      return handler as InternalHookHandler;
    }
    api.logger.warn?.(`[hooks] ${entry.hook.name} handler is not a function`);
    return null;
  } catch (err) {
    api.logger.warn?.(`[hooks] Failed to load ${entry.hook.name}: ${String(err)}`);
    return null;
  }
}

export async function registerPluginHooksFromDir(
  api: OpenClawPluginApi,
  dir: string,
): Promise<PluginHookLoadResult> {
  const resolvedDir = resolveHookDir(api, dir);
  const hooks = loadHookEntriesFromDir({
    dir: resolvedDir,
    source: "openclaw-plugin",
    pluginId: api.id,
  });

  const result: PluginHookLoadResult = {
    hooks,
    loaded: 0,
    skipped: 0,
    errors: [],
  };

  for (const entry of hooks) {
    const normalizedEntry = normalizePluginHookEntry(api, entry);
    const events = normalizedEntry.metadata?.events ?? [];
    if (events.length === 0) {
      api.logger.warn?.(`[hooks] ${entry.hook.name} has no events; skipping`);
      api.registerHook(events, async () => undefined, {
        entry: normalizedEntry,
        register: false,
      });
      result.skipped += 1;
      continue;
    }

    const handler = await loadHookHandler(entry, api);
    if (!handler) {
      result.errors.push(`[hooks] Failed to load ${entry.hook.name}`);
      api.registerHook(events, async () => undefined, {
        entry: normalizedEntry,
        register: false,
      });
      result.skipped += 1;
      continue;
    }

    const eligible = shouldIncludeHook({ entry: normalizedEntry, config: api.config });
    api.registerHook(events, handler, {
      entry: normalizedEntry,
      register: eligible,
    });

    if (eligible) {
      result.loaded += 1;
    } else {
      result.skipped += 1;
    }
  }

  return result;
}
