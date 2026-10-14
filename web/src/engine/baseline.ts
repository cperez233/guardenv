/**
 * Baseline files compatible with the CLI's `--baseline` flag.
 *
 * The CLI fingerprints a finding as the first 16 hex characters of
 * sha256("path␟rule_id␟line␟match") (`guardenv/models.py`). Reproducing that
 * here means findings acknowledged in the browser stay acknowledged in CI, as
 * long as the file name in the editor is the repository-relative path.
 */

import type { ScanFinding } from "./types";

export async function cliFingerprint(finding: ScanFinding): Promise<string> {
  const joined = [finding.path, finding.ruleId, finding.line, finding.match].join("\u001f");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(joined));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);
}

export async function buildBaseline(findings: readonly ScanFinding[]): Promise<string> {
  const entries = await Promise.all(
    findings.map(async (finding) => ({
      id: await cliFingerprint(finding),
      ruleId: finding.ruleId,
      path: finding.path,
      line: finding.line,
      redacted: finding.redacted,
    })),
  );
  return `${JSON.stringify({ schemaVersion: "1.0", tool: "guardenv", findings: entries }, null, 2)}\n`;
}
