/**
 * The client-side scan orchestrator.
 *
 * Runs the regex ruleset and the entropy detector over a pasted document,
 * deduplicates overlapping detections and produces a `ScanSummary` that the UI
 * and the exporters both consume. No network access, no backend.
 */

import {
  configWithThreshold,
  profileDocument,
  shannonEntropy,
  type EntropyConfig,
} from "./entropy";
import { GENERIC_RULE_IDS, RULES } from "./rules";
import {
  EMPTY_COUNTS,
  SEVERITY_RANK,
  isAtLeast,
  type EntropyResult,
  type RuleDefinition,
  type ScanConfig,
  type ScanFinding,
  type ScanSummary,
  type SeverityLevel,
} from "./types";

export const DEFAULT_SCAN_CONFIG: ScanConfig = {
  path: "input.env",
  entropyThreshold: 4.5,
  enableRules: true,
  enableEntropy: true,
  useHeuristics: true,
  minSeverity: "INFO",
  rules: RULES,
};

const MAX_PREVIEW = 200;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

/** FNV-1a: small, dependency-free and stable across reloads. */
function hash(value: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < value.length; i += 1) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

export function fingerprint(...parts: (string | number)[]): string {
  const joined = parts.join("");
  return `${hash(joined)}${hash(`${joined}::salt`)}`;
}

/** Display-safe rendering of a credential: keep 4 characters either side. */
export function redact(secret: string, keep = 4): string {
  if (secret.length === 0) return "";
  if (secret.length <= keep * 2) {
    return secret.length > 1 ? `${secret[0] ?? ""}${"*".repeat(secret.length - 1)}` : "*";
  }
  return `${secret.slice(0, keep)}${"*".repeat(8)}${secret.slice(-keep)}`;
}

/** Never let a raw credential escape through the preview field. */
function maskPreview(preview: string, secret: string): string {
  if (secret.length > 0 && preview.includes(secret)) {
    return preview.split(secret).join(redact(secret));
  }
  return preview;
}

function isAllowlisted(rule: RuleDefinition, secret: string): boolean {
  return (rule.allowlist ?? []).some((pattern) => {
    pattern.lastIndex = 0;
    return pattern.test(secret);
  });
}

/** Offsets of the first character of every line, for offset -> line mapping. */
function buildLineIndex(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === "\n") starts.push(i + 1);
  }
  return starts;
}

function locate(starts: readonly number[], offset: number): { line: number; column: number } {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if ((starts[mid] ?? 0) <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - (starts[lo] ?? 0) + 1 };
}

function buildFinding(params: {
  rule: RuleDefinition;
  secret: string;
  path: string;
  line: number;
  column: number;
  preview: string;
  entropy: number;
}): ScanFinding {
  const { rule, secret, path, line, column, preview, entropy } = params;
  return {
    id: fingerprint(path, rule.id, line, secret),
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    detector: "regex",
    path,
    line,
    column,
    match: secret,
    redacted: redact(secret),
    entropy,
    linePreview: maskPreview(preview, secret),
    description: rule.description,
    tags: rule.tags,
    verified: rule.validate ? rule.validate(secret) : false,
  };
}

// --------------------------------------------------------------------------
// Regex detector
// --------------------------------------------------------------------------

function runRules(text: string, path: string, rules: readonly RuleDefinition[]): ScanFinding[] {
  if (text.length === 0) return [];

  const findings: ScanFinding[] = [];
  const seen = new Set<string>();
  const lines = text.split("\n");
  const lowered = lines.map((line) => line.toLowerCase());
  const starts = buildLineIndex(text);

  const documentRules = rules.filter((rule) => rule.documentScoped === true);
  const lineRules = rules.filter((rule) => rule.documentScoped !== true);

  const record = (finding: ScanFinding, key: string): void => {
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(finding);
  };

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (line.trim().length === 0) continue;
    const loweredLine = lowered[index] ?? "";
    const preview = line.trim().slice(0, MAX_PREVIEW);

    for (const rule of lineRules) {
      if (rule.keywords.length > 0 && !rule.keywords.some((k) => loweredLine.includes(k))) {
        continue;
      }
      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = rule.pattern.exec(line)) !== null) {
        // A zero-length match would spin this loop forever.
        if (match[0].length === 0) {
          rule.pattern.lastIndex += 1;
          continue;
        }
        const secret = (match.groups?.["secret"] ?? match[0]).trim();
        if (secret.length === 0 || isAllowlisted(rule, secret)) continue;
        const entropy = shannonEntropy(secret);
        if (rule.entropyMin !== undefined && entropy < rule.entropyMin) continue;
        record(
          buildFinding({
            rule,
            secret,
            path,
            line: index + 1,
            column: match.index + 1,
            preview,
            entropy,
          }),
          `${rule.id}:${index + 1}:${secret}`,
        );
      }
    }
  }

  for (const rule of documentRules) {
    rule.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = rule.pattern.exec(text)) !== null) {
      if (match[0].length === 0) {
        rule.pattern.lastIndex += 1;
        continue;
      }
      const secret = (match.groups?.["secret"] ?? match[0]).trim();
      if (secret.length === 0 || isAllowlisted(rule, secret)) continue;
      const entropy = shannonEntropy(secret);
      if (rule.entropyMin !== undefined && entropy < rule.entropyMin) continue;
      const { line, column } = locate(starts, match.index);
      const preview = (lines[line - 1] ?? "").trim().slice(0, MAX_PREVIEW);
      record(
        buildFinding({ rule, secret, path, line, column, preview, entropy }),
        `${rule.id}:${line}:${secret}`,
      );
    }
  }

  return findings;
}

// --------------------------------------------------------------------------
// Entropy detector
// --------------------------------------------------------------------------

function entropyFindings(
  profile: readonly EntropyResult[],
  text: string,
  path: string,
): ScanFinding[] {
  const lines = text.split("\n");
  return profile
    .filter((result) => result.suspicious)
    .map((result) => {
      const preview = (lines[result.line - 1] ?? "").trim().slice(0, MAX_PREVIEW);
      return {
        id: fingerprint(path, "high-entropy-string", result.line, result.token),
        ruleId: "high-entropy-string",
        ruleName: "High Entropy String",
        severity: "MEDIUM" as SeverityLevel,
        detector: "entropy" as const,
        path,
        line: result.line,
        column: result.column,
        match: result.token,
        redacted: redact(result.token),
        entropy: result.entropy,
        linePreview: maskPreview(preview, result.token),
        description:
          `${result.charset} string with ${result.entropy.toFixed(2)} bits/char ` +
          `of entropy (threshold ${result.threshold.toFixed(2)}).`,
        tags: ["entropy", result.charset],
        verified: false,
      } satisfies ScanFinding;
    });
}

// --------------------------------------------------------------------------
// Deduplication
// --------------------------------------------------------------------------

/**
 * Specificity tier: a vendor signature tells the reader far more than "this
 * looks random", so it wins whenever two detections cover the same bytes.
 */
function specificity(finding: ScanFinding): number {
  if (finding.detector === "entropy") return 0;
  if (GENERIC_RULE_IDS.has(finding.ruleId)) return 1;
  return 2;
}

export function deduplicate(findings: readonly ScanFinding[]): ScanFinding[] {
  const ordered = [...findings].sort((a, b) => {
    const tier = specificity(b) - specificity(a);
    if (tier !== 0) return tier;
    const severity = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (severity !== 0) return severity;
    return Number(b.verified) - Number(a.verified);
  });

  const kept: ScanFinding[] = [];
  const byLine = new Map<string, ScanFinding[]>();

  for (const finding of ordered) {
    const key = `${finding.path}:${finding.line}`;
    const neighbours = byLine.get(key) ?? [];
    let redundant = false;
    for (const other of neighbours) {
      if (finding.match === other.match) {
        redundant = true;
        break;
      }
      const overlapping =
        finding.match.includes(other.match) || other.match.includes(finding.match);
      if (overlapping && specificity(finding) < specificity(other)) {
        redundant = true;
        break;
      }
    }
    if (redundant) continue;
    neighbours.push(finding);
    byLine.set(key, neighbours);
    kept.push(finding);
  }
  return kept;
}

// --------------------------------------------------------------------------
// Public entry point
// --------------------------------------------------------------------------

function countBySeverity(findings: readonly ScanFinding[]): Record<SeverityLevel, number> {
  const counts: Record<SeverityLevel, number> = { ...EMPTY_COUNTS };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

function highestSeverity(findings: readonly ScanFinding[]): SeverityLevel | null {
  let best: SeverityLevel | null = null;
  for (const finding of findings) {
    if (best === null || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[best]) {
      best = finding.severity;
    }
  }
  return best;
}

function byteLength(text: string): number {
  if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(text).length;
  return text.length;
}

/** Scan a document and return everything the UI needs to render a report. */
export function scanText(text: string, config: Partial<ScanConfig> = {}): ScanSummary {
  const started = performance.now();
  const merged: ScanConfig = { ...DEFAULT_SCAN_CONFIG, ...config };

  const entropyConfig: EntropyConfig = configWithThreshold(
    merged.entropyThreshold,
    merged.useHeuristics,
  );

  // The scatter plot always needs the full profile, even when the entropy
  // *detector* is switched off - otherwise the chart would go blank and the
  // reader would lose the context that explains where the threshold sits.
  const profile = profileDocument(text, entropyConfig);

  const regex = merged.enableRules ? runRules(text, merged.path, merged.rules) : [];
  const entropy = merged.enableEntropy ? entropyFindings(profile, text, merged.path) : [];

  const findings = deduplicate([...regex, ...entropy])
    .filter((finding) => isAtLeast(finding.severity, merged.minSeverity))
    .sort((a, b) => {
      const severity = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      if (severity !== 0) return severity;
      if (a.line !== b.line) return a.line - b.line;
      return a.column - b.column;
    });

  return {
    findings,
    entropyProfile: profile,
    countsBySeverity: countBySeverity(findings),
    totalFindings: findings.length,
    linesScanned: text.length === 0 ? 0 : text.split("\n").length,
    bytesScanned: byteLength(text),
    durationMs: performance.now() - started,
    highestSeverity: highestSeverity(findings),
  };
}
