/**
 * Diff mode: scan a unified diff (`git diff`, a PR patch) instead of a file.
 *
 * Every line keeps its number; the leading `+`, `-` or space is stripped before
 * scanning and added back to the column afterwards, so marks and redaction
 * still land on the right characters. Each finding learns which file of the
 * diff it belongs to and whether the line was added, removed or context. A
 * secret on a removed line is not fixed: it is still in the repository's
 * history, which is exactly what people forget.
 */

import { fingerprint } from "./scanner";
import type { ScanFinding } from "./types";

export type DiffLineKind = "added" | "removed" | "context" | "meta";

export interface ParsedDiff {
  /** The diff with markers and headers blanked, line numbers unchanged. */
  readonly stripped: string;
  readonly kinds: readonly DiffLineKind[];
  /** File each line belongs to (from `+++ b/…`, or `--- a/…` for deletions). */
  readonly files: readonly (string | null)[];
  readonly fileNames: readonly string[];
}

const META = /^(?:diff --git |index |--- |\+\+\+ |@@ |new file mode|deleted file mode|old mode|new mode|similarity index|rename from|rename to|Binary files|\\ No newline)/;

export function looksLikeDiff(text: string): boolean {
  return /^(?:diff --git |@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@)/m.test(text) && /^[+-](?![+-]{2} )/m.test(text);
}

export function parseDiff(text: string): ParsedDiff {
  const lines = text.split("\n");
  const kinds: DiffLineKind[] = [];
  const files: (string | null)[] = [];
  const names: string[] = [];
  let current: string | null = null;
  let oldName: string | null = null;
  const stripped = lines.map((line) => {
    if (META.test(line)) {
      if (line.startsWith("--- ")) oldName = line.slice(4).replace(/^a\//, "").trim();
      if (line.startsWith("+++ ")) {
        const target = line.slice(4).trim();
        current = target === "/dev/null" ? oldName : target.replace(/^b\//, "");
        if (current !== null && !names.includes(current)) names.push(current);
      }
      kinds.push("meta");
      files.push(current);
      return "";
    }
    const marker = line[0];
    kinds.push(marker === "+" ? "added" : marker === "-" ? "removed" : "context");
    files.push(current);
    return line.slice(1);
  });
  return { stripped: stripped.join("\n"), kinds, files, fileNames: names };
}

/** Map findings from the stripped text back onto the diff. */
export function mapDiffFindings(findings: readonly ScanFinding[], diff: ParsedDiff, fallbackPath: string): ScanFinding[] {
  return findings.map((finding) => {
    const kind = diff.kinds[finding.line - 1] ?? "context";
    const path = diff.files[finding.line - 1] ?? fallbackPath;
    return {
      ...finding,
      id: fingerprint(path, finding.ruleId, finding.line, finding.match, kind),
      path,
      column: kind === "meta" ? finding.column : finding.column + 1,
      tags: [...finding.tags, `diff-${kind}`],
    };
  });
}
