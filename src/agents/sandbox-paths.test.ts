import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertSandboxPath, resolveSandboxPath } from "./sandbox-paths.js";

describe("resolveSandboxPath", () => {
  const root = "/tmp/sandbox-test-root";

  it("allows paths within sandbox root", () => {
    const result = resolveSandboxPath({
      filePath: "src/index.ts",
      cwd: root,
      root,
    });
    expect(result.resolved).toBe(path.join(root, "src/index.ts"));
    expect(result.relative).toBe(path.join("src", "index.ts"));
  });

  it("allows nested paths within sandbox root", () => {
    const result = resolveSandboxPath({
      filePath: "src/deep/nested/file.ts",
      cwd: root,
      root,
    });
    expect(result.resolved).toBe(path.join(root, "src/deep/nested/file.ts"));
  });

  it("rejects path traversal with ../../etc/shadow", () => {
    expect(() =>
      resolveSandboxPath({
        filePath: "../../etc/shadow",
        cwd: root,
        root,
      }),
    ).toThrow(/Path escapes sandbox root/);
  });

  it("rejects deep path traversal", () => {
    expect(() =>
      resolveSandboxPath({
        filePath: "../../../../../../../etc/passwd",
        cwd: root,
        root,
      }),
    ).toThrow(/Path escapes sandbox root/);
  });

  it("rejects absolute paths outside sandbox root", () => {
    expect(() =>
      resolveSandboxPath({
        filePath: "/home/user/.ssh/id_rsa",
        cwd: root,
        root,
      }),
    ).toThrow(/Path escapes sandbox root/);
  });

  it("rejects absolute path to /etc/shadow", () => {
    expect(() =>
      resolveSandboxPath({
        filePath: "/etc/shadow",
        cwd: root,
        root,
      }),
    ).toThrow(/Path escapes sandbox root/);
  });

  it("rejects ~ expansion outside sandbox root", () => {
    // ~ expands to os.homedir() which is outside /tmp/sandbox-test-root
    expect(() =>
      resolveSandboxPath({
        filePath: "~/.env",
        cwd: root,
        root,
      }),
    ).toThrow(/Path escapes sandbox root/);
  });

  it("rejects ~/. ssh/id_rsa expansion", () => {
    expect(() =>
      resolveSandboxPath({
        filePath: "~/.ssh/id_rsa",
        cwd: root,
        root,
      }),
    ).toThrow(/Path escapes sandbox root/);
  });

  it("allows path that resolves to the root itself", () => {
    const result = resolveSandboxPath({
      filePath: ".",
      cwd: root,
      root,
    });
    expect(result.resolved).toBe(path.resolve(root));
    expect(result.relative).toBe("");
  });

  it("rejects path with embedded .. after valid prefix", () => {
    expect(() =>
      resolveSandboxPath({
        filePath: "src/../../outside",
        cwd: root,
        root,
      }),
    ).toThrow(/Path escapes sandbox root/);
  });
});

describe("assertSandboxPath", () => {
  let tempRoot: string;
  let symlinkTarget: string;

  beforeAll(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "sandbox-symlink-test-"));
    symlinkTarget = path.join(os.tmpdir(), "sandbox-symlink-target");

    // Create a directory inside the sandbox
    await fs.mkdir(path.join(tempRoot, "allowed"), { recursive: true });
    await fs.writeFile(path.join(tempRoot, "allowed", "file.txt"), "ok", "utf8");

    // Create a symlink inside the sandbox that points outside
    await fs.mkdir(symlinkTarget, { recursive: true });
    await fs.writeFile(path.join(symlinkTarget, "secret.txt"), "secret data", "utf8");
    try {
      await fs.symlink(symlinkTarget, path.join(tempRoot, "escape-link"));
    } catch {
      // symlink creation may fail on some platforms
    }
  });

  afterAll(async () => {
    await fs.rm(tempRoot, { recursive: true, force: true });
    await fs.rm(symlinkTarget, { recursive: true, force: true });
  });

  it("allows valid paths without symlinks", async () => {
    const result = await assertSandboxPath({
      filePath: "allowed/file.txt",
      cwd: tempRoot,
      root: tempRoot,
    });
    expect(result.resolved).toBe(path.join(tempRoot, "allowed", "file.txt"));
  });

  it("rejects symlink traversal outside sandbox", async () => {
    // Check if symlink was created (skip on platforms where it fails)
    try {
      const stat = await fs.lstat(path.join(tempRoot, "escape-link"));
      if (!stat.isSymbolicLink()) {
        return;
      }
    } catch {
      return;
    }

    await expect(
      assertSandboxPath({
        filePath: "escape-link/secret.txt",
        cwd: tempRoot,
        root: tempRoot,
      }),
    ).rejects.toThrow(/Symlink not allowed/);
  });
});
