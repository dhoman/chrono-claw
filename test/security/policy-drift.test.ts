import fs from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  expandToolGroups,
  resolveToolProfilePolicy,
  type ToolProfileId,
} from "../../src/agents/tool-policy.js";

// ---------------------------------------------------------------------------
// Snapshot types
// ---------------------------------------------------------------------------

type PolicyDriftSnapshot = Record<string, string[]>;

const PROFILES: ToolProfileId[] = ["minimal", "coding", "messaging", "full"];

const SNAPSHOT_PATH = path.join(import.meta.dirname, "policy-drift-snapshot.json");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function resolveCurrentAllowlists(): PolicyDriftSnapshot {
  const snapshot: PolicyDriftSnapshot = {};
  for (const profile of PROFILES) {
    const policy = resolveToolProfilePolicy(profile);
    const expanded = policy?.allow ? expandToolGroups(policy.allow).toSorted() : [];
    snapshot[profile] = expanded;
  }
  return snapshot;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("policy drift detection", () => {
  it("generate snapshot (run with GENERATE_POLICY_SNAPSHOT=1 to update)", async () => {
    const isCI = process.env.CI === "true" || process.env.CI === "1";
    if (isCI) {
      expect(process.env.GENERATE_POLICY_SNAPSHOT).not.toBe("1");
      return;
    }

    if (process.env.GENERATE_POLICY_SNAPSHOT !== "1") {
      // Only generate if snapshot doesn't exist or explicitly requested
      let exists = false;
      try {
        await fs.access(SNAPSHOT_PATH);
        exists = true;
      } catch {
        // missing
      }
      if (exists) {
        return;
      }
    }

    const snapshot = resolveCurrentAllowlists();
    await fs.writeFile(SNAPSHOT_PATH, JSON.stringify(snapshot, null, 2) + "\n", "utf8");
  });

  it("snapshot file must exist", async () => {
    let exists = false;
    try {
      await fs.access(SNAPSHOT_PATH);
      exists = true;
    } catch {
      // missing
    }

    expect(
      exists,
      "policy-drift-snapshot.json is missing — run GENERATE_POLICY_SNAPSHOT=1 locally to create it",
    ).toBe(true);
  });

  it("tool allowlists match committed snapshot", async () => {
    const snapshotRaw = await fs.readFile(SNAPSHOT_PATH, "utf8");
    const snapshot: PolicyDriftSnapshot = JSON.parse(snapshotRaw);
    const current = resolveCurrentAllowlists();

    for (const profile of PROFILES) {
      expect(current[profile], `profile "${profile}" allowlist changed`).toEqual(snapshot[profile]);
    }
  });

  it("minimal profile has not grown (directional guard)", async () => {
    const snapshotRaw = await fs.readFile(SNAPSHOT_PATH, "utf8");
    const snapshot: PolicyDriftSnapshot = JSON.parse(snapshotRaw);
    const current = resolveCurrentAllowlists();

    const baselineMinimal = snapshot.minimal ?? [];
    const currentMinimal = current.minimal ?? [];

    expect(
      currentMinimal.length,
      `minimal profile grew from ${baselineMinimal.length} to ${currentMinimal.length} tools — this is a security regression`,
    ).toBeLessThanOrEqual(baselineMinimal.length);

    // Check for new tools not in baseline
    const baselineSet = new Set(baselineMinimal);
    const newTools = currentMinimal.filter((t) => !baselineSet.has(t));
    expect(newTools, `new tools in minimal profile: ${newTools.join(", ")}`).toHaveLength(0);
  });

  it("no profile allowlist has grown unexpectedly", async () => {
    const snapshotRaw = await fs.readFile(SNAPSHOT_PATH, "utf8");
    const snapshot: PolicyDriftSnapshot = JSON.parse(snapshotRaw);
    const current = resolveCurrentAllowlists();

    for (const profile of PROFILES) {
      const baselineList = snapshot[profile] ?? [];
      const currentList = current[profile] ?? [];
      const baselineSet = new Set(baselineList);
      const newTools = currentList.filter((t) => !baselineSet.has(t));

      if (newTools.length > 0) {
        expect.fail(
          `profile "${profile}" gained new tools: ${newTools.join(", ")} — update snapshot if intentional`,
        );
      }
    }
  });
});
