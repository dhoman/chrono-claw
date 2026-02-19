import fs from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { OpenClawConfig } from "../../src/config/types.openclaw.js";
import type { SecurityAuditReport, SecurityAuditSummary } from "../../src/security/audit.js";
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

type BaselineSnapshot = {
  summary: SecurityAuditSummary;
  findingIds: string[];
  findingsBySeverity: {
    critical: string[];
    warn: string[];
    info: string[];
  };
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASELINE_PATH = path.join(import.meta.dirname, "baseline-audit.json");

function normalizeReport(report: SecurityAuditReport): BaselineSnapshot {
  const findingIds = report.findings.map((f) => f.checkId).toSorted();
  const findingsBySeverity: BaselineSnapshot["findingsBySeverity"] = {
    critical: report.findings
      .filter((f) => f.severity === "critical")
      .map((f) => f.checkId)
      .toSorted(),
    warn: report.findings
      .filter((f) => f.severity === "warn")
      .map((f) => f.checkId)
      .toSorted(),
    info: report.findings
      .filter((f) => f.severity === "info")
      .map((f) => f.checkId)
      .toSorted(),
  };
  return { summary: report.summary, findingIds, findingsBySeverity };
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("baseline audit", () => {
  it("generate baseline snapshot (run with GENERATE_BASELINE=1 to update)", async () => {
    if (process.env.GENERATE_BASELINE !== "1") {
      // Skip generation unless explicitly requested or baseline doesn't exist
      let exists = false;
      try {
        await fs.access(BASELINE_PATH);
        exists = true;
      } catch {
        // file doesn't exist
      }
      if (exists) {
        return;
      }
    }

    const snapshot = await runBaselineAudit();
    await fs.writeFile(BASELINE_PATH, JSON.stringify(snapshot, null, 2) + "\n", "utf8");
  });

  it("matches committed baseline snapshot", async () => {
    // Ensure baseline exists — generate if missing
    let baselineRaw: string;
    try {
      baselineRaw = await fs.readFile(BASELINE_PATH, "utf8");
    } catch {
      // Auto-generate on first run
      const snapshot = await runBaselineAudit();
      await fs.writeFile(BASELINE_PATH, JSON.stringify(snapshot, null, 2) + "\n", "utf8");
      baselineRaw = JSON.stringify(snapshot, null, 2);
    }

    const baseline: BaselineSnapshot = JSON.parse(baselineRaw);
    const current = await runBaselineAudit();

    expect(current.summary).toEqual(baseline.summary);
    expect(current.findingIds).toEqual(baseline.findingIds);
    expect(current.findingsBySeverity).toEqual(baseline.findingsBySeverity);
  });
});
