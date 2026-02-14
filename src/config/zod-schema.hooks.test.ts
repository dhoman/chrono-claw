import { describe, expect, it } from "vitest";
import {
  isSafeRelativeModulePath,
  HookMappingSchema,
  InternalHookHandlerSchema,
} from "./zod-schema.hooks.js";

describe("isSafeRelativeModulePath", () => {
  it("accepts relative path with leading ./", () => {
    expect(isSafeRelativeModulePath("./hooks/handler.ts")).toBe(true);
  });

  it("accepts bare relative path", () => {
    expect(isSafeRelativeModulePath("hooks/handler.ts")).toBe(true);
  });

  it("accepts single filename", () => {
    expect(isSafeRelativeModulePath("handler.ts")).toBe(true);
  });

  it("rejects absolute path", () => {
    expect(isSafeRelativeModulePath("/etc/passwd")).toBe(false);
  });

  it("rejects home-relative path", () => {
    expect(isSafeRelativeModulePath("~/evil.ts")).toBe(false);
  });

  it("rejects colon (URL-ish)", () => {
    expect(isSafeRelativeModulePath("file:///etc/passwd")).toBe(false);
  });

  it("rejects parent traversal", () => {
    expect(isSafeRelativeModulePath("../outside.ts")).toBe(false);
  });

  it("rejects deep traversal", () => {
    expect(isSafeRelativeModulePath("foo/../../outside.ts")).toBe(false);
  });

  it("rejects empty string", () => {
    expect(isSafeRelativeModulePath("")).toBe(false);
  });

  it("rejects whitespace only", () => {
    expect(isSafeRelativeModulePath("   ")).toBe(false);
  });

  it("rejects Windows drive path", () => {
    expect(isSafeRelativeModulePath("C:\\Windows\\System32")).toBe(false);
  });
});

describe("HookMappingSchema module path integration", () => {
  it("accepts valid transform module", () => {
    const result = HookMappingSchema.safeParse({
      transform: { module: "./hooks/transform.ts" },
    });
    expect(result.success).toBe(true);
  });

  it("rejects absolute transform module", () => {
    const result = HookMappingSchema.safeParse({
      transform: { module: "/etc/passwd" },
    });
    expect(result.success).toBe(false);
  });

  it("rejects traversal in transform module", () => {
    const result = HookMappingSchema.safeParse({
      transform: { module: "../../../tmp/evil.js" },
    });
    expect(result.success).toBe(false);
  });
});

describe("InternalHookHandlerSchema module path integration", () => {
  it("accepts valid handler module", () => {
    const result = InternalHookHandlerSchema.safeParse({
      event: "command:new",
      module: "hooks/handler.ts",
    });
    expect(result.success).toBe(true);
  });

  it("rejects absolute handler module", () => {
    const result = InternalHookHandlerSchema.safeParse({
      event: "command:new",
      module: "/etc/passwd",
    });
    expect(result.success).toBe(false);
  });

  it("rejects traversal in handler module", () => {
    const result = InternalHookHandlerSchema.safeParse({
      event: "command:new",
      module: "../../outside.ts",
    });
    expect(result.success).toBe(false);
  });

  it("rejects empty handler module", () => {
    const result = InternalHookHandlerSchema.safeParse({
      event: "command:new",
      module: "",
    });
    expect(result.success).toBe(false);
  });
});
