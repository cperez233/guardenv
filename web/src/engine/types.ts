/**
 * Shared types for the GuardEnv client-side engine.
 *
 * These mirror the Python dataclasses in `guardenv/models.py` one-for-one so a
 * report produced in the browser is byte-compatible with a report produced by
 * the CLI (same field names, same severity ladder, same SARIF mapping).
 */

export const SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export type SeverityLevel = (typeof SEVERITY_LEVELS)[number];

export type DetectorKind = "regex" | "entropy";

export type CharsetKind = "hex" | "base64" | "base64url" | "alphanumeric" | "mixed";

/** Higher is worse. Used for sorting, thresholds and the severity floor. */
export const SEVERITY_RANK: Readonly<Record<SeverityLevel, number>> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/** SARIF only knows four levels; collapse the ladder onto them. */
export const SARIF_LEVEL: Readonly<Record<SeverityLevel, "error" | "warning" | "note">> = {
  CRITICAL: "error",
  HIGH: "error",
  MEDIUM: "warning",
  LOW: "note",
  INFO: "note",
};

/** GitHub Code Scanning orders alerts with this 0.0-10.0 property. */
export const SECURITY_SEVERITY: Readonly<Record<SeverityLevel, string>> = {
  CRITICAL: "9.5",
  HIGH: "8.0",
  MEDIUM: "5.5",
  LOW: "3.0",
  INFO: "1.0",
};

/**
 * A single detection signature.
 *
 * `pattern` must expose a named `secret` group; `scanText` reads it to decide
 * what to redact. `keywords` is a lowercase substring pre-filter applied before
 * the regex runs, which is what keeps a 5,000-line paste responsive.
 */
export interface RuleDefinition {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly severity: SeverityLevel;
  readonly pattern: RegExp;
  readonly keywords: readonly string[];
  readonly tags: readonly string[];
  readonly allowlist?: readonly RegExp[];
  /** Minimum Shannon entropy the captured secret must reach to be reported. */
  readonly entropyMin?: number;
  /** Rules anchored with `^`/`$` need the whole document, not a single line. */
  readonly documentScoped?: boolean;
  /** Optional structural check that can mark a finding as verified. */
  readonly validate?: (secret: string) => boolean;
}

/** Outcome of scoring one token with the entropy detector. */
export interface EntropyResult {
  readonly token: string;
  readonly entropy: number;
  readonly normalized: number;
  readonly charset: CharsetKind;
  readonly threshold: number;
  readonly suspicious: boolean;
  readonly reason: string;
  readonly line: number;
  readonly column: number;
}

/** A single potential credential leak. */
export interface ScanFinding {
  readonly id: string;
  readonly ruleId: string;
  readonly ruleName: string;
  readonly severity: SeverityLevel;
  readonly detector: DetectorKind;
  readonly path: string;
  readonly line: number;
  readonly column: number;
  readonly match: string;
  readonly redacted: string;
  readonly entropy: number | null;
  readonly linePreview: string;
  readonly description: string;
  readonly tags: readonly string[];
  readonly verified: boolean;
}

/** Aggregate outcome of a scan. */
export interface ScanSummary {
  readonly findings: readonly ScanFinding[];
  readonly entropyProfile: readonly EntropyResult[];
  readonly countsBySeverity: Readonly<Record<SeverityLevel, number>>;
  readonly totalFindings: number;
  readonly linesScanned: number;
  readonly bytesScanned: number;
  readonly durationMs: number;
  readonly highestSeverity: SeverityLevel | null;
}

/** Everything that shapes a client-side scan. */
export interface ScanConfig {
  readonly path: string;
  readonly entropyThreshold: number;
  readonly enableRules: boolean;
  readonly enableEntropy: boolean;
  readonly useHeuristics: boolean;
  readonly minSeverity: SeverityLevel;
  readonly rules: readonly RuleDefinition[];
}

export const EMPTY_COUNTS: Readonly<Record<SeverityLevel, number>> = {
  CRITICAL: 0,
  HIGH: 0,
  MEDIUM: 0,
  LOW: 0,
  INFO: 0,
};

export const EMPTY_SUMMARY: ScanSummary = {
  findings: [],
  entropyProfile: [],
  countsBySeverity: EMPTY_COUNTS,
  totalFindings: 0,
  linesScanned: 0,
  bytesScanned: 0,
  durationMs: 0,
  highestSeverity: null,
};

export function compareSeverity(a: SeverityLevel, b: SeverityLevel): number {
  return SEVERITY_RANK[b] - SEVERITY_RANK[a];
}

export function isAtLeast(severity: SeverityLevel, floor: SeverityLevel): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[floor];
}
