/**
 * Encoded-secret pass: credentials hidden inside base64 values.
 *
 * Kubernetes Secret manifests, Docker auth configs and "obfuscated" constants
 * carry credentials base64-encoded, where no signature can see them and the
 * entropy detector can only say "random-looking string". This pass decodes
 * every plausible base64 run, scans the plaintext with the signature rules and
 * reports what it finds at the position of the encoded value, so redaction and
 * line marks still land on the right bytes.
 */

import { redact, fingerprint, scanText } from "./scanner";
import type { ScanFinding, SeverityLevel } from "./types";

const CANDIDATE = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
const MIN_PLAINTEXT = 12;
const MAX_PREVIEW = 160;

/** Decode standard or URL-safe base64 to UTF-8 text, or null if it is not text. */
export function decodeBase64Text(value: string): string | null {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (normalized.length % 4 === 1) return null;
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return null;
  }
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  if (text.length < MIN_PLAINTEXT) return null;
  let printable = 0;
  for (const char of text) {
    const code = char.charCodeAt(0);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code !== 127)) printable += 1;
  }
  return printable / text.length >= 0.95 ? text : null;
}

export function findEncodedSecrets(
  text: string,
  path: string,
  minSeverity: SeverityLevel = "INFO",
): ScanFinding[] {
  const out: ScanFinding[] = [];
  const lines = text.split("\n");
  lines.forEach((line, index) => {
    CANDIDATE.lastIndex = 0;
    for (let match = CANDIDATE.exec(line); match !== null; match = CANDIDATE.exec(line)) {
      const blob = match[0];
      const plaintext = decodeBase64Text(blob);
      if (plaintext === null) continue;
      const inner = scanText(plaintext, { path, enableEntropy: false, minSeverity });
      // Report the most severe credential inside the value; one blob, one finding.
      const top = inner.findings[0];
      if (top === undefined) continue;
      const lineNumber = index + 1;
      out.push({
        id: fingerprint(path, `${top.ruleId}@base64`, lineNumber, blob),
        ruleId: top.ruleId,
        ruleName: `${top.ruleName} (base64)`,
        severity: top.severity,
        detector: "regex",
        path,
        line: lineNumber,
        column: match.index + 1,
        match: blob,
        redacted: redact(blob),
        entropy: top.entropy,
        linePreview: line.trim().split(blob).join(redact(blob)).slice(0, MAX_PREVIEW),
        description: `Base64-encoded value that decodes to ${top.redacted}. ${top.description}`,
        tags: [...top.tags, "encoded", "base64"],
        verified: top.verified,
      });
    }
  });
  return out;
}

/**
 * Fold encoded findings into a scan's findings. A decoded credential is more
 * specific than "high entropy string" on the same bytes, so it replaces it;
 * a signature that already matched the raw value wins over the decoded copy.
 */
export function mergeEncoded(
  findings: readonly ScanFinding[],
  encoded: readonly ScanFinding[],
): ScanFinding[] {
  const kept = findings.filter(
    (finding) =>
      finding.detector !== "entropy" ||
      !encoded.some((e) => e.line === finding.line && e.match.includes(finding.match)),
  );
  const extra = encoded.filter(
    (e) => !kept.some((f) => f.line === e.line && (f.match.includes(e.match) || e.match.includes(f.match))),
  );
  return [...kept, ...extra];
}
