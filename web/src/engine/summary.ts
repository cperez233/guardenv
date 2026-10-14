/**
 * Re-derive a summary's aggregates after its finding list changed (encoded
 * secrets merged in, acknowledged findings filtered out). Everything except the
 * findings and their counts is carried over from the original scan.
 */

import { EMPTY_COUNTS, SEVERITY_RANK } from "./types";
import type { ScanFinding, ScanSummary, SeverityLevel } from "./types";

export function sortFindings(findings: readonly ScanFinding[]): ScanFinding[] {
  return [...findings].sort((a, b) => {
    const severity = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (severity !== 0) return severity;
    if (a.line !== b.line) return a.line - b.line;
    return a.column - b.column;
  });
}

export function withFindings(summary: ScanSummary, findings: readonly ScanFinding[]): ScanSummary {
  const counts: Record<SeverityLevel, number> = { ...EMPTY_COUNTS };
  let highest: SeverityLevel | null = null;
  for (const finding of findings) {
    counts[finding.severity] += 1;
    if (highest === null || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest]) {
      highest = finding.severity;
    }
  }
  return {
    ...summary,
    findings: sortFindings(findings),
    countsBySeverity: counts,
    totalFindings: findings.length,
    highestSeverity: highest,
  };
}
