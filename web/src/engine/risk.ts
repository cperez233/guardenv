/**
 * A single exposure grade for the document, so the verdict reads at a glance.
 *
 * Each finding costs points by severity; a checksum-verified token costs more
 * because it is almost certainly live. Any CRITICAL caps the grade at D and any
 * HIGH at C, so a single leaked production key can never hide behind a decent
 * average.
 */

import type { ScanSummary, SeverityLevel } from "./types";

export type RiskGrade = "A" | "B" | "C" | "D" | "F";

const COST: Readonly<Record<SeverityLevel, number>> = {
  CRITICAL: 30,
  HIGH: 16,
  MEDIUM: 7,
  LOW: 2,
  INFO: 0.5,
};

const VERIFIED_COST = 10;

export function riskScore(summary: ScanSummary): { score: number; grade: RiskGrade } {
  let cost = 0;
  for (const finding of summary.findings) {
    cost += COST[finding.severity] + (finding.verified ? VERIFIED_COST : 0);
  }
  const score = Math.max(0, Math.round(100 - cost));
  let grade: RiskGrade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 55 ? "C" : score >= 30 ? "D" : "F";
  const counts = summary.countsBySeverity;
  const rank = (g: RiskGrade): number => "ABCDF".indexOf(g);
  if (counts.CRITICAL > 0 && rank(grade) < rank("D")) grade = "D";
  else if (counts.HIGH > 0 && rank(grade) < rank("C")) grade = "C";
  return { score, grade };
}
