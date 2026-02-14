import fs from "node:fs/promises";
import path from "node:path";
import type { SkillScanFinding, SkillScanSummary } from "../src/security/skill-scanner.js";
import { scanDirectoryWithSummary } from "../src/security/skill-scanner.js";

// Only scan third-party skill directories in CI. First-party extensions/
// legitimately use child_process, process.env, etc. and would produce false
// positives.  Extensions are still covered by `openclaw security audit --deep`.
const SCAN_DIRS = ["skills"];

function hasFlag(flag: string): boolean {
  return process.argv.includes(flag);
}

function formatAnnotation(finding: SkillScanFinding): string {
  const level = finding.severity === "critical" ? "error" : "warning";
  return `::${level} file=${finding.file},line=${finding.line}::${finding.message} [${finding.ruleId}]`;
}

async function dirExists(dirPath: string): Promise<boolean> {
  try {
    const stat = await fs.stat(dirPath);
    return stat.isDirectory();
  } catch {
    return false;
  }
}

async function main(): Promise<void> {
  const jsonMode = hasFlag("--json");
  const root = process.cwd();

  const summaries: SkillScanSummary[] = [];
  const scannedDirs: string[] = [];

  for (const dir of SCAN_DIRS) {
    const fullPath = path.resolve(root, dir);
    if (!(await dirExists(fullPath))) {
      continue;
    }
    scannedDirs.push(dir);
    const summary = await scanDirectoryWithSummary(fullPath);
    summaries.push(summary);
  }

  const merged: SkillScanSummary = {
    scannedFiles: summaries.reduce((acc, s) => acc + s.scannedFiles, 0),
    critical: summaries.reduce((acc, s) => acc + s.critical, 0),
    warn: summaries.reduce((acc, s) => acc + s.warn, 0),
    info: summaries.reduce((acc, s) => acc + s.info, 0),
    findings: summaries.flatMap((s) => s.findings),
  };

  if (jsonMode) {
    process.stdout.write(`${JSON.stringify(merged, null, 2)}\n`);
  } else {
    if (scannedDirs.length === 0) {
      console.log("No skill directories found. Nothing to scan.");
    } else {
      console.log(`Scanned ${merged.scannedFiles} files in: ${scannedDirs.join(", ")}`);
    }

    for (const finding of merged.findings) {
      console.log(formatAnnotation(finding));
      console.log(`  ${finding.evidence}`);
    }

    if (merged.findings.length === 0) {
      console.log("No findings.");
    } else {
      console.log(
        `\nTotal: ${merged.critical} critical, ${merged.warn} warnings, ${merged.info} info`,
      );
    }
  }

  if (merged.critical > 0) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error("scan-skills failed:", err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
