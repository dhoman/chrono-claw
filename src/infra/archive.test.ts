import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import JSZip from "jszip";
import * as tar from "tar";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { extractArchive, resolveArchiveKind, resolvePackedRootDir } from "./archive.js";

let fixtureRoot = "";
let fixtureCount = 0;

async function makeTempDir(prefix = "case") {
  const dir = path.join(fixtureRoot, `${prefix}-${fixtureCount++}`);
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

async function expectExtractedSizeBudgetExceeded(params: {
  archivePath: string;
  destDir: string;
  timeoutMs?: number;
  maxExtractedBytes: number;
}) {
  await expect(
    extractArchive({
      archivePath: params.archivePath,
      destDir: params.destDir,
      timeoutMs: params.timeoutMs ?? 5_000,
      limits: { maxExtractedBytes: params.maxExtractedBytes },
    }),
  ).rejects.toThrow("archive extracted size exceeds limit");
}

beforeAll(async () => {
  fixtureRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-archive-"));
});

afterAll(async () => {
  await fs.rm(fixtureRoot, { recursive: true, force: true });
});

describe("archive utils", () => {
  it("detects archive kinds", () => {
    expect(resolveArchiveKind("/tmp/file.zip")).toBe("zip");
    expect(resolveArchiveKind("/tmp/file.tgz")).toBe("tar");
    expect(resolveArchiveKind("/tmp/file.tar.gz")).toBe("tar");
    expect(resolveArchiveKind("/tmp/file.tar")).toBe("tar");
    expect(resolveArchiveKind("/tmp/file.txt")).toBeNull();
  });

  it("extracts zip archives", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.zip");
    const extractDir = path.join(workDir, "extract");

    const zip = new JSZip();
    zip.file("package/hello.txt", "hi");
    await fs.writeFile(archivePath, await zip.generateAsync({ type: "nodebuffer" }));

    await fs.mkdir(extractDir, { recursive: true });
    await extractArchive({ archivePath, destDir: extractDir, timeoutMs: 5_000 });
    const rootDir = await resolvePackedRootDir(extractDir);
    const content = await fs.readFile(path.join(rootDir, "hello.txt"), "utf-8");
    expect(content).toBe("hi");
  });

  it("rejects zip path traversal (zip slip)", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.zip");
    const extractDir = path.join(workDir, "a");

    const zip = new JSZip();
    zip.file("../b/evil.txt", "pwnd");
    await fs.writeFile(archivePath, await zip.generateAsync({ type: "nodebuffer" }));

    await fs.mkdir(extractDir, { recursive: true });
    await expect(
      extractArchive({ archivePath, destDir: extractDir, timeoutMs: 5_000 }),
    ).rejects.toThrow(/(escapes destination|absolute)/i);
  });

  it("extracts tar archives", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.tar");
    const extractDir = path.join(workDir, "extract");
    const packageDir = path.join(workDir, "package");

    await fs.mkdir(packageDir, { recursive: true });
    await fs.writeFile(path.join(packageDir, "hello.txt"), "yo");
    await tar.c({ cwd: workDir, file: archivePath }, ["package"]);

    await fs.mkdir(extractDir, { recursive: true });
    await extractArchive({ archivePath, destDir: extractDir, timeoutMs: 5_000 });
    const rootDir = await resolvePackedRootDir(extractDir);
    const content = await fs.readFile(path.join(rootDir, "hello.txt"), "utf-8");
    expect(content).toBe("yo");
  });

  it("rejects tar path traversal (zip slip)", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.tar");
    const extractDir = path.join(workDir, "extract");
    const insideDir = path.join(workDir, "inside");
    await fs.mkdir(insideDir, { recursive: true });
    await fs.writeFile(path.join(workDir, "outside.txt"), "pwnd");

    await tar.c({ cwd: insideDir, file: archivePath }, ["../outside.txt"]);

    await fs.mkdir(extractDir, { recursive: true });
    await expect(
      extractArchive({ archivePath, destDir: extractDir, timeoutMs: 5_000 }),
    ).rejects.toThrow(/escapes destination/i);
  });

  it("rejects zip archives that exceed extracted size budget", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.zip");
    const extractDir = path.join(workDir, "extract");

    const zip = new JSZip();
    zip.file("package/big.txt", "x".repeat(64));
    await fs.writeFile(archivePath, await zip.generateAsync({ type: "nodebuffer" }));

    await fs.mkdir(extractDir, { recursive: true });
    await expectExtractedSizeBudgetExceeded({
      archivePath,
      destDir: extractDir,
      maxExtractedBytes: 32,
    });
  });

  it("rejects archives that exceed archive size budget", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.zip");
    const extractDir = path.join(workDir, "extract");

    const zip = new JSZip();
    zip.file("package/file.txt", "ok");
    await fs.writeFile(archivePath, await zip.generateAsync({ type: "nodebuffer" }));
    const stat = await fs.stat(archivePath);

    await fs.mkdir(extractDir, { recursive: true });
    await expect(
      extractArchive({
        archivePath,
        destDir: extractDir,
        timeoutMs: 5_000,
        limits: { maxArchiveBytes: Math.max(1, stat.size - 1) },
      }),
    ).rejects.toThrow("archive size exceeds limit");
  });

  it("rejects tar archives that exceed extracted size budget", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.tar");
    const extractDir = path.join(workDir, "extract");
    const packageDir = path.join(workDir, "package");

    await fs.mkdir(packageDir, { recursive: true });
    await fs.writeFile(path.join(packageDir, "big.txt"), "x".repeat(64));
    await tar.c({ cwd: workDir, file: archivePath }, ["package"]);

    await fs.mkdir(extractDir, { recursive: true });
    await expectExtractedSizeBudgetExceeded({
      archivePath,
      destDir: extractDir,
      maxExtractedBytes: 32,
    });
  });

  it("rejects zip archives that exceed entry count limit", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.zip");
    const extractDir = path.join(workDir, "extract");

    const zip = new JSZip();
    // Create 5 entries but set maxEntries to 3
    for (let i = 0; i < 5; i++) {
      zip.file(`package/file-${i}.txt`, `content-${i}`);
    }
    await fs.writeFile(archivePath, await zip.generateAsync({ type: "nodebuffer" }));

    await fs.mkdir(extractDir, { recursive: true });
    await expect(
      extractArchive({
        archivePath,
        destDir: extractDir,
        timeoutMs: 5_000,
        limits: { maxEntries: 3 },
      }),
    ).rejects.toThrow("archive entry count exceeds limit");
  });

  it("rejects zip archives where a single entry exceeds maxEntryBytes", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.zip");
    const extractDir = path.join(workDir, "extract");

    const zip = new JSZip();
    zip.file("package/big.txt", "x".repeat(256));
    await fs.writeFile(archivePath, await zip.generateAsync({ type: "nodebuffer" }));

    await fs.mkdir(extractDir, { recursive: true });
    await expect(
      extractArchive({
        archivePath,
        destDir: extractDir,
        timeoutMs: 5_000,
        limits: { maxEntryBytes: 64 },
      }),
    ).rejects.toThrow("archive entry extracted size exceeds limit");
  });

  it("rejects tar archives containing symlinks", async () => {
    // Symlink creation may be unreliable on Windows CI
    if (process.platform === "win32") {
      return;
    }

    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.tar");
    const extractDir = path.join(workDir, "extract");
    const packageDir = path.join(workDir, "package");

    await fs.mkdir(packageDir, { recursive: true });
    await fs.writeFile(path.join(packageDir, "real.txt"), "real");
    await fs.symlink(path.join(packageDir, "real.txt"), path.join(packageDir, "link.txt"));

    await tar.c({ cwd: workDir, file: archivePath, follow: false }, ["package"]);

    await fs.mkdir(extractDir, { recursive: true });
    await expect(
      extractArchive({ archivePath, destDir: extractDir, timeoutMs: 5_000 }),
    ).rejects.toThrow(/link/i);
  });

  it("rejects zip entries with backslash traversal", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.zip");
    const extractDir = path.join(workDir, "extract");

    const zip = new JSZip();
    // Use backslash-based traversal: package\..\..\evil.txt
    zip.file("package\\..\\..\\evil.txt", "pwnd");
    await fs.writeFile(archivePath, await zip.generateAsync({ type: "nodebuffer" }));

    await fs.mkdir(extractDir, { recursive: true });
    await expect(
      extractArchive({ archivePath, destDir: extractDir, timeoutMs: 5_000 }),
    ).rejects.toThrow(/(escapes destination|absolute)/i);
  });

  it("rejects zip entries with Windows drive paths", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.zip");
    const extractDir = path.join(workDir, "extract");

    const zip = new JSZip();
    zip.file("C:\\Windows\\evil.dll", "pwnd");
    await fs.writeFile(archivePath, await zip.generateAsync({ type: "nodebuffer" }));

    await fs.mkdir(extractDir, { recursive: true });
    await expect(
      extractArchive({ archivePath, destDir: extractDir, timeoutMs: 5_000 }),
    ).rejects.toThrow(/drive path/i);
  });

  it("rejects tar entries with absolute extraction paths", async () => {
    const workDir = await makeTempDir();
    const archivePath = path.join(workDir, "bundle.tar");
    const extractDir = path.join(workDir, "extract");

    const inputDir = path.join(workDir, "input");
    const outsideFile = path.join(inputDir, "outside.txt");
    await fs.mkdir(inputDir, { recursive: true });
    await fs.writeFile(outsideFile, "owned");
    await tar.c({ file: archivePath, preservePaths: true }, [outsideFile]);

    await fs.mkdir(extractDir, { recursive: true });
    await expect(
      extractArchive({
        archivePath,
        destDir: extractDir,
        timeoutMs: 5_000,
      }),
    ).rejects.toThrow(/absolute|drive path|escapes destination/i);
  });
});
