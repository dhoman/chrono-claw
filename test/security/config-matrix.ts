/**
 * Vitest-parameterized config matrix for security E2E tests.
 *
 * Provides pre-defined axes (sandbox modes, tool profiles, exec approval modes)
 * and a cross-product helper to generate test permutations.
 */

import type { OpenClawConfig } from "../../src/config/types.openclaw.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SecurityMatrixEntry = {
  label: string;
  config: Partial<OpenClawConfig>;
};

// ---------------------------------------------------------------------------
// Axes
// ---------------------------------------------------------------------------

export const SANDBOX_MODES: SecurityMatrixEntry[] = [
  {
    label: "sandbox=off",
    config: { agents: { defaults: { sandbox: { mode: "off" } } } },
  },
  {
    label: "sandbox=all",
    config: { agents: { defaults: { sandbox: { mode: "all" } } } },
  },
];

export const TOOL_PROFILES: SecurityMatrixEntry[] = [
  {
    label: "tools=minimal",
    config: { tools: { profile: "minimal" } },
  },
  {
    label: "tools=coding",
    config: { tools: { profile: "coding" } },
  },
  {
    label: "tools=full",
    config: { tools: { profile: "full" } },
  },
];

export const EXEC_APPROVAL_MODES: SecurityMatrixEntry[] = [
  {
    label: "exec=deny",
    config: {
      approvals: { exec: { mode: "deny" } },
    },
  },
  {
    label: "exec=allowlist",
    config: {
      approvals: { exec: { mode: "allowlist", allow: ["echo", "ls"] } },
    },
  },
];

// ---------------------------------------------------------------------------
// Cross-product helper
// ---------------------------------------------------------------------------

export function crossMatrix(...axes: SecurityMatrixEntry[][]): SecurityMatrixEntry[] {
  if (axes.length === 0) {
    return [];
  }

  let result: SecurityMatrixEntry[] = axes[0].map((entry) => ({ ...entry }));

  for (let i = 1; i < axes.length; i++) {
    const next: SecurityMatrixEntry[] = [];
    for (const existing of result) {
      for (const entry of axes[i]) {
        next.push({
          label: `${existing.label} | ${entry.label}`,
          config: deepMergeConfig(existing.config, entry.config),
        });
      }
    }
    result = next;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Deep merge
// ---------------------------------------------------------------------------

export function deepMergeConfig(
  base: Partial<OpenClawConfig>,
  override: Partial<OpenClawConfig>,
): Partial<OpenClawConfig> {
  const result: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      typeof result[key] === "object" &&
      result[key] !== null &&
      !Array.isArray(result[key])
    ) {
      result[key] = deepMergeConfig(
        result[key] as Partial<OpenClawConfig>,
        value as Partial<OpenClawConfig>,
      );
    } else {
      result[key] = value;
    }
  }
  return result as Partial<OpenClawConfig>;
}
