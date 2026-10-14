/**
 * Prevention snippets generated from the document on screen: what to ignore,
 * what to commit instead, and how to stop the next leak before it lands.
 */

import type { ScanFinding } from "./types";

const ASSIGNMENT = /^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(.*)$/;
const SENSITIVE_KEY = /(SECRET|TOKEN|PASSW(OR)?D|PASS|PWD|API_?KEY|ACCESS_?KEY|PRIVATE|CREDENTIAL|AUTH|DSN|WEBHOOK)/i;

/** `.gitignore` lines that keep this kind of file out of the repository. */
export function gitignoreFor(filename: string): string {
  const name = filename.trim() || "untitled";
  const base = name.split(/[\\/]/).pop() ?? name;
  const lines = [
    "# Local environment files: commit a .env.example instead",
    ".env",
    ".env.*",
    "*.env",
    "!.env.example",
    "",
    "# Keys and certificates",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
  ];
  const envLike = /(^|\.)env($|\.)/i.test(base) || base.endsWith(".env");
  const keyLike = /\.(pem|key|p12|pfx)$/i.test(base);
  if (!envLike && !keyLike) {
    lines.push("", `# ${base} carried credentials: ignore it, or move its secrets to the environment`, base);
  }
  return `${lines.join("\n")}\n`;
}

/**
 * A committable template of a dotenv-style document: every value that carried
 * a finding, or whose key names a secret, is emptied; everything else (ports,
 * flags, regions) keeps its default. Returns null for documents that are not
 * KEY=value shaped.
 */
export function envExampleFor(source: string, findings: readonly ScanFinding[]): string | null {
  const lines = source.split("\n");
  const assignments = lines.filter((line) => ASSIGNMENT.test(line) && !line.trim().startsWith("#"));
  if (assignments.length === 0 || assignments.length < lines.filter((l) => l.trim().length > 0 && !l.trim().startsWith("#")).length * 0.6) {
    return null;
  }
  const flagged = new Set(findings.map((finding) => finding.line));
  const body = lines.map((line, index) => {
    if (line.trim().startsWith("#")) return line;
    const match = ASSIGNMENT.exec(line);
    if (match === null) return line;
    const [, lead = "", key = "", separator = "="] = match;
    if (flagged.has(index + 1) || SENSITIVE_KEY.test(key)) return `${lead}${key}${separator}`;
    return line;
  });
  return ["# Copy to .env and fill in the empty values. Never commit the copy.", ...body].join("\n").replace(/\n*$/, "\n");
}

/** From the repository README: the pre-commit hook and the CI step. */
export const PRECOMMIT_CONFIG = `# .pre-commit-config.yaml
repos:
  - repo: https://github.com/cperez233/guardenv
    rev: v1.1.0
    hooks:
      - id: guardenv
`;

export const GITHUB_ACTIONS_STEP = `- run: pip install "git+https://github.com/cperez233/guardenv@v1.1.0"
- run: guardenv scan . --sarif --output guardenv.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: guardenv.sarif
`;
