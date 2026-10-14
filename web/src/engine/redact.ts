/**
 * Produce a shareable copy of a document with every reported credential
 * blacked out.
 *
 * Each secret is replaced by a run of full-block characters of the same
 * length, so columns, line lengths and the shape of the file survive while
 * not a single character of the credential does (unlike `redact()`, which
 * keeps the edges for display).
 */

import type { ScanFinding } from "./types";

export const REDACTION_CHAR = "█";

export interface RedactionResult {
  readonly text: string;
  /** Number of distinct secret occurrences that were blacked out. */
  readonly count: number;
}

export function redactDocument(text: string, findings: readonly ScanFinding[]): RedactionResult {
  if (findings.length === 0) return { text, count: 0 };
  const lines = text.split("\n");
  const byLine = new Map<number, ScanFinding[]>();
  for (const finding of findings) {
    if (finding.match.length === 0) continue;
    const bucket = byLine.get(finding.line) ?? [];
    bucket.push(finding);
    byLine.set(finding.line, bucket);
  }

  let count = 0;
  for (const [lineNumber, lineFindings] of byLine) {
    const index = lineNumber - 1;
    const original = lines[index];
    if (original === undefined) continue;
    let line: string = original;
    // Longest first, so a secret that contains another is masked whole.
    const secrets = [...new Set(lineFindings.map((finding) => finding.match))].sort(
      (a, b) => b.length - a.length,
    );
    for (const secret of secrets) {
      const parts: string[] = line.split(secret);
      if (parts.length > 1) {
        count += parts.length - 1;
        line = parts.join(REDACTION_CHAR.repeat(secret.length));
      }
    }
    lines[index] = line;
  }
  return { text: lines.join("\n"), count };
}
