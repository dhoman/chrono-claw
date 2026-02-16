import fs from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { OpenClawConfig } from "../../src/config/types.openclaw.js";
import type { SecurityAuditReport } from "../../src/security/audit.js";
import { runSecurityAudit } from "../../src/security/audit.js";
import { withTempHome } from "../helpers/temp-home.js";

// ---------------------------------------------------------------------------
// Deterministic baseline config
// ---------------------------------------------------------------------------

const BASELINE_CONFIG: OpenClawConfig = {
  gateway: {
    bind: "loopback",
    auth: { mode: "token", token: "baseline-test-token-long-enough-32chars" },
  },
  hooks: { enabled: false },
  channels: {},
  tools: { profile: "coding" },
  agents: { defaults: { sandbox: { mode: "off" } } },
};

// ---------------------------------------------------------------------------
// Baseline snapshot types
// ---------------------------------------------------------------------------

type BaselineFinding = {
  checkId: string;
  severity: "info" | "warn" | "critical";
  title: string;
};

type BaselineSnapshot = {
  summary: { critical: number; warn: number; info: number };
  findings: BaselineFinding[];
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASELINE_PATH = path.join(import.meta.dirname, "baseline-audit.json");

function normalizeReport(report: SecurityAuditReport): BaselineSnapshot {
  const findings: BaselineFinding[] = report.findings
    .map((f) => ({
      checkId: f.checkId,
      severity: f.severity,
      title: f.title,
    }))
    .toSorted((a, b) => a.checkId.localeCompare(b.checkId));

  return { summary: report.summary, findings };
}

async function runBaselineAudit(): Promise<BaselineSnapshot> {
  return await withTempHome(async (home) => {
    const stateDir = path.join(home, ".openclaw");
    const configPath = path.join(stateDir, "openclaw.json");
    await fs.mkdir(stateDir, { recursive: true });
    await fs.writeFile(configPath, JSON.stringify(BASELINE_CONFIG, null, 2), "utf8");

    const report = await runSecurityAudit({
      config: BASELINE_CONFIG,
      includeFilesystem: false,
      includeChannelSecurity: false,
      stateDir,
      configPath,
    });

    return normalizeReport(report);
  });
}

function isCI(): boolean {
  return process.env.CI === "true" || process.env.CI === "1";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("baseline audit", () => {
  it("generate baseline snapshot (run with GENERATE_BASELINE=1 to update)", async () => {
    // Block GENERATE_BASELINE in CI — baseline must be committed, never auto-generated.
    if (isCI()) {
      expect(process.env.GENERATE_BASELINE).not.toBe("1");
      return;
    }

    if (process.env.GENERATE_BASELINE !== "1") {
      return;
    }

    const snapshot = await runBaselineAudit();
    await fs.writeFile(BASELINE_PATH, JSON.stringify(snapshot, null, 2) + "\n", "utf8");
  });

  it("baseline file must exist (no auto-generate)", async () => {
    let exists = false;
    try {
      await fs.access(BASELINE_PATH);
      exists = true;
    } catch {
      // file missing
    }

    expect(
      exists,
      "baseline-audit.json is missing — run GENERATE_BASELINE=1 locally to create it",
    ).toBe(true);
  });

  it("matches committed baseline snapshot", async () => {
    const baselineRaw = await fs.readFile(BASELINE_PATH, "utf8");
    const baseline: BaselineSnapshot = JSON.parse(baselineRaw);
    const current = await runBaselineAudit();

    expect(current.summary).toEqual(baseline.summary);
    expect(current.findings).toEqual(baseline.findings);
  });

  it("findings have not increased (directional guard)", async () => {
    const baselineRaw = await fs.readFile(BASELINE_PATH, "utf8");
    const baseline: BaselineSnapshot = JSON.parse(baselineRaw);
    const current = await runBaselineAudit();

    // Count findings by severity
    const countBySeverity = (findings: BaselineFinding[], severity: string) =>
      findings.filter((f) => f.severity === severity).length;

    const currentCritical = countBySeverity(current.findings, "critical");
    const currentWarn = countBySeverity(current.findings, "warn");
    const currentInfo = countBySeverity(current.findings, "info");

    const baselineCritical = countBySeverity(baseline.findings, "critical");
    const baselineWarn = countBySeverity(baseline.findings, "warn");
    const baselineInfo = countBySeverity(baseline.findings, "info");

    expect(
      currentCritical,
      `critical findings increased: ${currentCritical} > ${baselineCritical} — update baseline if intentional`,
    ).toBeLessThanOrEqual(baselineCritical);

    expect(
      currentWarn,
      `warn findings increased: ${currentWarn} > ${baselineWarn} — update baseline if intentional`,
    ).toBeLessThanOrEqual(baselineWarn);

    expect(
      currentInfo,
      `info findings increased: ${currentInfo} > ${baselineInfo} — update baseline if intentional`,
    ).toBeLessThanOrEqual(baselineInfo);

    // Also check that no new finding IDs appeared
    const baselineIds = new Set(baseline.findings.map((f) => f.checkId));
    const newFindings = current.findings.filter((f) => !baselineIds.has(f.checkId));
    expect(
      newFindings,
      `new findings detected: ${newFindings.map((f) => f.checkId).join(", ")} — update baseline if intentional`,
    ).toHaveLength(0);
  });
});
