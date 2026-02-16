import path from "node:path";
import { describe, expect, it } from "vitest";
import type { OpenClawPluginApi } from "../plugins/types.js";
import { isContainedPath, resolveHookDir } from "./plugin-hooks.js";

function createMockApi(source: string): OpenClawPluginApi {
  return {
    id: "test-plugin",
    name: "test",
    source,
    config: {} as OpenClawPluginApi["config"],
    runtime: {} as OpenClawPluginApi["runtime"],
    logger: { warn: () => {} },
    registerTool: () => {},
    registerHook: () => {},
    registerHttpHandler: () => {},
    registerHttpRoute: () => {},
    registerChannel: () => {},
    registerGatewayMethod: () => {},
    registerCli: () => {},
    registerService: () => {},
    registerProvider: () => {},
    registerCommand: () => {},
  } as unknown as OpenClawPluginApi;
}

describe("isContainedPath", () => {
  it("accepts path within base directory", () => {
    expect(isContainedPath("/home/plugins/foo", "/home/plugins/foo/hooks")).toBe(true);
  });

  it("rejects path escaping via ..", () => {
    expect(isContainedPath("/home/plugins/foo", "/home/plugins/foo/../../etc")).toBe(false);
  });

  it("rejects absolute path outside base", () => {
    expect(isContainedPath("/home/plugins/foo", "/etc/passwd")).toBe(false);
  });

  it("rejects identical paths (base === target)", () => {
    expect(isContainedPath("/home/plugins/foo", "/home/plugins/foo")).toBe(false);
  });
});

describe("resolveHookDir", () => {
  const pluginSource = path.join("/home", "plugins", "my-plugin", "index.js");
  const api = createMockApi(pluginSource);

  it("accepts a relative directory within the plugin tree", () => {
    const result = resolveHookDir(api, "hooks");
    expect(result).toBe(path.join("/home", "plugins", "my-plugin", "hooks"));
  });

  it("rejects absolute hook directory outside plugin", () => {
    expect(() => resolveHookDir(api, "/etc/hooks")).toThrow(
      /Hook directory must be within the plugin directory/,
    );
  });

  it("rejects traversal hook directory", () => {
    expect(() => resolveHookDir(api, "../../etc")).toThrow(
      /Hook directory must be within the plugin directory/,
    );
  });
});
