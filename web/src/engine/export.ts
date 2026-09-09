/**
 * Report exporters.
 *
 * Both formats are byte-compatible with what `guardenv --json` and
 * `guardenv --sarif` emit, so a report produced in the browser can be uploaded
 * to GitHub Code Scanning or diffed against a CI artifact directly.
 */

import { RULES_BY_ID } from "./rules";
import {
  SARIF_LEVEL,
  SECURITY_SEVERITY,
  type ScanFinding,
  type ScanSummary,
  type SeverityLevel,
} from "./types";

export const TOOL_VERSION = "1.0.0";
export const TOOL_URI = "https://github.com/guardenv/guardenv";
const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

export type ExportFormat = "json" | "sarif";

interface JsonFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: SeverityLevel;
  detector: string;
  path: string;
  line: number;
  column: number;
  redacted: string;
  entropy: number | null;
  linePreview: string;
  description: string;
  tags: string[];
  verified: boolean;
  match?: string;
}

function toJsonFinding(finding: ScanFinding, includeSecret: boolean): JsonFinding {
  const payload: JsonFinding = {
    id: finding.id,
    ruleId: finding.ruleId,
    ruleName: finding.ruleName,
    severity: finding.severity,
    detector: finding.detector,
    path: finding.path,
    line: finding.line,
    column: finding.column,
    redacted: finding.redacted,
    entropy: finding.entropy === null ? null : Number(finding.entropy.toFixed(4)),
    linePreview: finding.linePreview,
    description: finding.description,
    tags: [...finding.tags],
    verified: finding.verified,
  };
  if (includeSecret) payload.match = finding.match;
  return payload;
}

/** GuardEnv's native JSON report. */
export function toJsonReport(summary: ScanSummary, includeSecret = false): string {
  return JSON.stringify(
    {
      schemaVersion: "1.0",
      tool: "guardenv",
      summary: {
        filesScanned: summary.totalFindings >= 0 ? 1 : 0,
        filesSkipped: 0,
        bytesScanned: summary.bytesScanned,
        durationMs: Number(summary.durationMs.toFixed(3)),
        totalFindings: summary.totalFindings,
        countsBySeverity: summary.countsBySeverity,
      },
      findings: summary.findings.map((finding) => toJsonFinding(finding, includeSecret)),
      errors: [],
    },
    null,
    2,
  );
}

function sarifRuleDescriptor(ruleId: string): Record<string, unknown> {
  const rule = RULES_BY_ID.get(ruleId);
  if (rule === undefined) {
    return {
      id: ruleId,
      name: "HighEntropyString",
      shortDescription: { text: "High entropy string" },
      fullDescription: {
        text:
          "A string whose Shannon entropy exceeds the configured threshold, which is " +
          "characteristic of randomly generated credentials.",
      },
      defaultConfiguration: { level: "warning" },
      properties: {
        tags: ["security", "entropy", "guardenv"],
        "security-severity": SECURITY_SEVERITY.MEDIUM,
      },
    };
  }
  const pascal = rule.id
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
  return {
    id: rule.id,
    name: pascal,
    shortDescription: { text: rule.name },
    fullDescription: { text: rule.description },
    helpUri: `${TOOL_URI}#rule-${rule.id}`,
    help: {
      text: `${rule.description} Rotate the credential and remove it from version control.`,
      markdown:
        `**${rule.name}**\n\n${rule.description}\n\n**Remediation**\n\n` +
        "1. Revoke/rotate the credential at the provider.\n" +
        "2. Remove it from the working tree and from git history.\n" +
        "3. Move it into a secrets manager or CI secret store.",
    },
    defaultConfiguration: { level: SARIF_LEVEL[rule.severity] },
    properties: {
      tags: ["security", "guardenv", ...rule.tags],
      "security-severity": SECURITY_SEVERITY[rule.severity],
      precision: rule.entropyMin === undefined ? "high" : "medium",
    },
  };
}

/** SARIF 2.1.0, ready for `github/codeql-action/upload-sarif`. */
export function toSarifReport(summary: ScanSummary): string {
  const referenced: string[] = [];
  for (const finding of summary.findings) {
    if (!referenced.includes(finding.ruleId)) referenced.push(finding.ruleId);
  }
  const ruleIndex = new Map(referenced.map((id, index) => [id, index]));

  const document = {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "GuardEnv",
            informationUri: TOOL_URI,
            version: TOOL_VERSION,
            semanticVersion: TOOL_VERSION,
            rules: referenced.map(sarifRuleDescriptor),
          },
        },
        invocations: [{ executionSuccessful: true, toolExecutionNotifications: [] }],
        results: summary.findings.map((finding) => ({
          ruleId: finding.ruleId,
          ruleIndex: ruleIndex.get(finding.ruleId) ?? 0,
          level: SARIF_LEVEL[finding.severity],
          message: {
            text:
              `${finding.ruleName}: potential credential \`${finding.redacted}\` ` +
              `detected via ${finding.detector} analysis.`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.path, uriBaseId: "%SRCROOT%" },
                region: {
                  startLine: Math.max(1, finding.line),
                  startColumn: Math.max(1, finding.column),
                  snippet: { text: finding.linePreview },
                },
              },
            },
          ],
          partialFingerprints: { "guardenv/v1": finding.id },
          properties: {
            severity: finding.severity,
            detector: finding.detector,
            entropy: finding.entropy,
            verified: finding.verified,
            tags: [...finding.tags],
          },
        })),
        properties: {
          filesScanned: 1,
          filesSkipped: 0,
          durationMs: Number(summary.durationMs.toFixed(3)),
        },
      },
    ],
  };
  return JSON.stringify(document, null, 2);
}

/** Compact human-readable summary, for pasting into an issue or a PR comment. */
export function toMarkdownReport(summary: ScanSummary): string {
  if (summary.findings.length === 0) {
    return [
      "## GuardEnv scan",
      "",
      "**No credentials detected.**",
      "",
      `- Lines scanned: ${summary.linesScanned}`,
      `- Duration: ${summary.durationMs.toFixed(2)} ms`,
    ].join("\n");
  }

  const counts = Object.entries(summary.countsBySeverity)
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => `${count} ${severity}`)
    .join(" · ");

  const rows = summary.findings.map(
    (finding) =>
      `| ${finding.severity} | \`${finding.ruleId}\` | ${finding.path}:${finding.line}:${finding.column} | \`${finding.redacted}\` | ${finding.entropy === null ? "-" : finding.entropy.toFixed(2)} |`,
  );

  return [
    "## GuardEnv scan",
    "",
    `**${summary.totalFindings} finding(s)** — ${counts}`,
    "",
    "| Severity | Rule | Location | Secret | Entropy |",
    "| --- | --- | --- | --- | --- |",
    ...rows,
    "",
    `Scanned ${summary.linesScanned} lines in ${summary.durationMs.toFixed(2)} ms.`,
  ].join("\n");
}

export function buildReport(summary: ScanSummary, format: ExportFormat): string {
  return format === "sarif" ? toSarifReport(summary) : toJsonReport(summary);
}

export function reportFilename(format: ExportFormat): string {
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  return format === "sarif" ? `guardenv-${stamp}.sarif` : `guardenv-${stamp}.json`;
}

/** Trigger a client-side download without ever touching a server. */
export function downloadReport(summary: ScanSummary, format: ExportFormat): void {
  const blob = new Blob([buildReport(summary, format)], {
    type: format === "sarif" ? "application/sarif+json" : "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = reportFilename(format);
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Revoke on the next tick: revoking synchronously can cancel the download in
  // Safari before the browser has read the blob.
  window.setTimeout(() => { URL.revokeObjectURL(url); }, 0);
}
