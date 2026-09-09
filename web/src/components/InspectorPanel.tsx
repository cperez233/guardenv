import {
  BadgeCheck,
  Braces,
  Check,
  ClipboardCopy,
  Download,
  Regex,
  ShieldCheck,
  Sigma,
} from "lucide-react";
import { useMemo, useState } from "react";
import type { ReactElement } from "react";

import { buildReport, downloadReport, toMarkdownReport } from "@/engine/export";
import type { ExportFormat } from "@/engine/export";
import { SEVERITY_LEVELS } from "@/engine/types";
import type { ScanFinding, ScanSummary, SeverityLevel } from "@/engine/types";
import { useCopyToClipboard } from "@/hooks/useCopyToClipboard";
import { SEVERITY_CLASSES, cx, formatDuration, formatEntropy, pluralize } from "@/lib/format";
import { SeverityBadge } from "./SeverityBadge";
import { StatTile } from "./StatTile";

interface InspectorPanelProps {
  readonly summary: ScanSummary;
  readonly hasInput: boolean;
  readonly minSeverity: SeverityLevel;
  readonly activeFindingId: string | null;
  readonly onMinSeverityChange: (severity: SeverityLevel) => void;
  readonly onSelectFinding: (finding: ScanFinding) => void;
}

function FindingRow({
  finding,
  isActive,
  onSelect,
}: {
  finding: ScanFinding;
  isActive: boolean;
  onSelect: () => void;
}): ReactElement {
  const classes = SEVERITY_CLASSES[finding.severity];
  return (
    <li>
      <button
        type="button"
        onClick={onSelect}
        aria-current={isActive}
        className={cx(
          "w-full animate-fade-in rounded-lg border px-3 py-2.5 text-left transition-colors",
          isActive
            ? "border-hairline-strong bg-surface-3"
            : "border-hairline bg-surface-2 hover:border-hairline-strong hover:bg-surface-3",
        )}
      >
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} size="sm" />
          <code className="font-mono text-xs text-content-primary">{finding.ruleId}</code>
          {finding.verified && (
            <span
              title="Checksum verified against the provider's token format"
              className="inline-flex items-center gap-1 rounded bg-severity-clean/15 px-1.5 py-0.5 text-[10px] font-medium text-severity-clean"
            >
              <BadgeCheck className="h-3 w-3" aria-hidden />
              verified
            </span>
          )}
          <span className="ml-auto inline-flex items-center gap-1 font-mono text-[11px] text-content-faint">
            {finding.detector === "entropy" ? (
              <Sigma className="h-3 w-3" aria-hidden />
            ) : (
              <Regex className="h-3 w-3" aria-hidden />
            )}
            {formatEntropy(finding.entropy)}
          </span>
        </div>

        <p className="mt-1.5 text-xs leading-snug text-content-secondary">{finding.description}</p>

        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px]">
          <span className="text-content-tertiary">
            {finding.path}:{finding.line}:{finding.column}
          </span>
          <span className={cx("rounded bg-surface-4 px-1.5 py-0.5", classes.text)}>
            {finding.redacted}
          </span>
        </div>

        {finding.linePreview.length > 0 && (
          <pre className="mt-2 overflow-x-auto rounded border border-hairline bg-surface-0 px-2 py-1.5 font-mono text-[11px] text-content-tertiary">
            {finding.linePreview}
          </pre>
        )}
      </button>
    </li>
  );
}

export function InspectorPanel({
  summary,
  hasInput,
  minSeverity,
  activeFindingId,
  onMinSeverityChange,
  onSelectFinding,
}: InspectorPanelProps): ReactElement {
  const [format, setFormat] = useState<ExportFormat>("json");
  const { state: copyState, copy } = useCopyToClipboard();
  const { state: mdCopyState, copy: copyMarkdown } = useCopyToClipboard();

  const counts = summary.countsBySeverity;
  const detectorSplit = useMemo(() => {
    let regex = 0;
    let entropy = 0;
    for (const finding of summary.findings) {
      if (finding.detector === "entropy") entropy += 1;
      else regex += 1;
    }
    return { regex, entropy };
  }, [summary.findings]);

  const clean = hasInput && summary.totalFindings === 0;

  return (
    <section className="flex min-h-0 flex-col rounded-xl border border-hairline bg-surface-1">
      <div className="flex flex-wrap items-center gap-2 border-b border-hairline px-3 py-2">
        <ShieldCheck className="h-4 w-4 text-content-tertiary" aria-hidden />
        <h2 className="text-xs font-semibold uppercase tracking-[0.12em] text-content-secondary">
          Audit inspector
        </h2>
        <label className="ml-auto flex items-center gap-1.5 text-[11px] text-content-tertiary">
          Min severity
          <select
            value={minSeverity}
            onChange={(event) => { onMinSeverityChange(event.target.value as SeverityLevel); }}
            className="rounded border border-hairline bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-content-primary outline-none focus:border-hairline-strong"
          >
            {SEVERITY_LEVELS.map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="grid grid-cols-2 gap-2 border-b border-hairline p-3 sm:grid-cols-4">
        <StatTile
          label="Findings"
          value={summary.totalFindings}
          hint={`${detectorSplit.regex} signature · ${detectorSplit.entropy} entropy`}
          accent={
            summary.totalFindings === 0 ? "text-severity-clean" : "text-severity-critical"
          }
        />
        <StatTile
          label="Analysis"
          value={formatDuration(summary.durationMs)}
          hint={`${summary.linesScanned} ${pluralize(summary.linesScanned, "line")} scanned`}
        />
        <StatTile
          label="Critical"
          value={counts.CRITICAL}
          hint={`${counts.HIGH} high · ${counts.MEDIUM} medium`}
          accent={counts.CRITICAL > 0 ? "text-severity-critical" : "text-content-secondary"}
        />
        <StatTile
          label="Tokens profiled"
          value={summary.entropyProfile.length}
          hint="candidates measured"
        />
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {!hasInput && (
          <div className="grid h-full min-h-[12rem] place-items-center rounded-lg border border-dashed border-hairline text-center">
            <div className="px-6 py-8">
              <p className="text-sm text-content-secondary">Nothing to audit yet</p>
              <p className="mt-1 text-xs text-content-faint">
                Paste a document or load one of the samples to see findings here.
              </p>
            </div>
          </div>
        )}

        {clean && (
          <div className="grid h-full min-h-[12rem] place-items-center rounded-lg border border-severity-clean/25 bg-severity-clean/5 text-center">
            <div className="px-6 py-8">
              <ShieldCheck className="mx-auto h-6 w-6 text-severity-clean" aria-hidden />
              <p className="mt-2 text-sm font-medium text-severity-clean">No credentials detected</p>
              <p className="mt-1 text-xs text-content-tertiary">
                {summary.entropyProfile.length} token
                {summary.entropyProfile.length === 1 ? "" : "s"} profiled in{" "}
                {formatDuration(summary.durationMs)}.
              </p>
            </div>
          </div>
        )}

        {summary.findings.length > 0 && (
          <ul className="flex flex-col gap-2">
            {summary.findings.map((finding) => (
              <FindingRow
                key={finding.id}
                finding={finding}
                isActive={activeFindingId === finding.id}
                onSelect={() => { onSelectFinding(finding); }}
              />
            ))}
          </ul>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 border-t border-hairline px-3 py-2">
        <div
          role="radiogroup"
          aria-label="Export format"
          className="flex rounded-md border border-hairline bg-surface-2 p-0.5"
        >
          {(["json", "sarif"] as const).map((option) => (
            <button
              key={option}
              type="button"
              role="radio"
              aria-checked={format === option}
              onClick={() => { setFormat(option); }}
              className={cx(
                "rounded px-2 py-1 font-mono text-[11px] uppercase transition-colors",
                format === option
                  ? "bg-surface-4 text-content-primary"
                  : "text-content-tertiary hover:text-content-secondary",
              )}
            >
              {option}
            </button>
          ))}
        </div>

        <button
          type="button"
          onClick={() => void copy(buildReport(summary, format))}
          className="inline-flex items-center gap-1.5 rounded-md border border-hairline bg-surface-2 px-2.5 py-1 text-[11px] font-medium text-content-secondary transition-colors hover:border-hairline-strong hover:text-content-primary"
        >
          {copyState === "copied" ? (
            <Check className="h-3 w-3 text-severity-clean" aria-hidden />
          ) : (
            <ClipboardCopy className="h-3 w-3" aria-hidden />
          )}
          {copyState === "copied" ? "Copied" : copyState === "error" ? "Copy failed" : "Copy report"}
        </button>

        <button
          type="button"
          onClick={() => void copyMarkdown(toMarkdownReport(summary))}
          className="inline-flex items-center gap-1.5 rounded-md border border-hairline bg-surface-2 px-2.5 py-1 text-[11px] font-medium text-content-secondary transition-colors hover:border-hairline-strong hover:text-content-primary"
        >
          {mdCopyState === "copied" ? (
            <Check className="h-3 w-3 text-severity-clean" aria-hidden />
          ) : (
            <Braces className="h-3 w-3" aria-hidden />
          )}
          {mdCopyState === "copied" ? "Copied" : "Copy Markdown"}
        </button>

        <button
          type="button"
          onClick={() => { downloadReport(summary, format); }}
          className="ml-auto inline-flex items-center gap-1.5 rounded-md border border-hairline-strong bg-surface-3 px-2.5 py-1 text-[11px] font-medium text-content-primary transition-colors hover:bg-surface-4"
        >
          <Download className="h-3 w-3" aria-hidden />
          Download .{format === "sarif" ? "sarif" : "json"}
        </button>
      </div>
    </section>
  );
}
