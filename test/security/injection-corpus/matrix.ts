/**
 * Coverage matrix mapping injection corpus entries to ingress x expectation cells.
 *
 * This ensures every ingress source has at least one injection test and
 * no matrix cell is left empty.
 */

import type {
  InjectionCategory,
  InjectionCorpusEntry,
  IngressSource,
  SecurityExpectation,
} from "./types.js";
import { ALL_INJECTION_PAYLOADS } from "./payloads.js";

// ---------------------------------------------------------------------------
// Matrix types
// ---------------------------------------------------------------------------

export type MatrixCell = {
  ingress: IngressSource;
  expectation: SecurityExpectation;
  entries: InjectionCorpusEntry[];
};

export type CoverageReport = {
  /** Total corpus entries. */
  totalEntries: number;
  /** All ingress sources with at least one test. */
  coveredIngress: IngressSource[];
  /** All expectations with at least one test. */
  coveredExpectations: SecurityExpectation[];
  /** Ingress sources without any test (should be empty for full coverage). */
  uncoveredIngress: IngressSource[];
  /** Matrix cells with their entry counts. */
  cells: MatrixCell[];
  /** Categories with entry counts. */
  categoryCounts: Record<InjectionCategory, number>;
};

// ---------------------------------------------------------------------------
// Matrix computation
// ---------------------------------------------------------------------------

const ALL_INGRESS_SOURCES: IngressSource[] = [
  "webhook",
  "email",
  "api",
  "channel",
  "hook",
  "webchat",
  "cli",
];

const ALL_EXPECTATIONS: SecurityExpectation[] = [
  "detection",
  "content-wrapped",
  "tool-denied",
  "secret-redacted",
  "ssrf-blocked",
  "auth-enforced",
  "marker-sanitized",
];

export function computeCoverageReport(
  entries: InjectionCorpusEntry[] = ALL_INJECTION_PAYLOADS,
): CoverageReport {
  const cells: MatrixCell[] = [];
  const coveredIngressSet = new Set<IngressSource>();
  const coveredExpectationsSet = new Set<SecurityExpectation>();

  for (const ingress of ALL_INGRESS_SOURCES) {
    for (const expectation of ALL_EXPECTATIONS) {
      const matching = entries.filter(
        (e) => e.ingress === ingress && e.expectations.includes(expectation),
      );
      cells.push({ ingress, expectation, entries: matching });
      if (matching.length > 0) {
        coveredIngressSet.add(ingress);
        coveredExpectationsSet.add(expectation);
      }
    }
  }

  const coveredIngress = ALL_INGRESS_SOURCES.filter((s) => coveredIngressSet.has(s));
  const uncoveredIngress = ALL_INGRESS_SOURCES.filter((s) => !coveredIngressSet.has(s));
  const coveredExpectations = ALL_EXPECTATIONS.filter((s) => coveredExpectationsSet.has(s));

  const categoryCounts = {} as Record<InjectionCategory, number>;
  const allCategories: InjectionCategory[] = [
    "direct",
    "indirect",
    "polyglot",
    "tool-confusion",
    "exfiltration",
    "ssrf",
  ];
  for (const cat of allCategories) {
    categoryCounts[cat] = entries.filter((e) => e.category === cat).length;
  }

  return {
    totalEntries: entries.length,
    coveredIngress,
    coveredExpectations,
    uncoveredIngress,
    cells,
    categoryCounts,
  };
}
