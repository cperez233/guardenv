/* editorial-ui · Cristian Pérez · cristianperez.me */
import { AnimatePresence, motion } from "framer-motion";
import {
  BadgeCheck,
  BellOff,
  Binary,
  ChevronDown,
  ExternalLink,
  FileCheck2,
  RotateCcw,
  Wrench,
  Braces,
  Check,
  ClipboardCopy,
  Download,
  Regex,
  ShieldCheck,
  Sigma,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { ReactElement } from "react";

import { buildBaseline } from "@/engine/baseline";
import { buildReport, downloadReport, toMarkdownReport } from "@/engine/export";
import { remediationFor } from "@/engine/remediation";
import type { ExportFormat } from "@/engine/export";
import { SEVERITY_LEVELS } from "@/engine/types";
import type { ScanFinding, ScanSummary, SeverityLevel } from "@/engine/types";
import { useCopyToClipboard } from "@/hooks/useCopyToClipboard";
import { SEVERITY_CLASSES, cx, formatDuration, formatEntropy, pluralize } from "@/lib/format";
import { ease, reveal, softSpring, spring } from "@/lib/motion";
import { RollingNumber, SpringNumber } from "./Numbers";
import { SeverityBadge } from "./SeverityBadge";
import { StatTile } from "./StatTile";

interface InspectorPanelProps {
  readonly summary: ScanSummary;
  readonly hasInput: boolean;
  readonly minSeverity: SeverityLevel;
  readonly activeFindingId: string | null;
  readonly onMinSeverityChange: (severity: SeverityLevel) => void;
  readonly onSelectFinding: (finding: ScanFinding) => void;
  readonly decodeEncoded: boolean;
  readonly onDecodeEncodedChange: (value: boolean) => void;
  /** Findings acknowledged as false positives, hidden from the list above. */
  readonly ignored: readonly ScanFinding[];
  readonly onIgnore: (finding: ScanFinding) => void;
  readonly onRestoreIgnored: () => void;
}

function FindingRow({
  finding,
  index,
  isActive,
  onSelect,
  onIgnore,
}: {
  finding: ScanFinding;
  index: number;
  isActive: boolean;
  onSelect: () => void;
  onIgnore: () => void;
}): ReactElement {
  const classes = SEVERITY_CLASSES[finding.severity];
  const fix = remediationFor(finding);
  const encoded = finding.tags.includes("encoded");
  return (
    <motion.li
      layout="position"
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, x: 40, transition: { duration: 0.22, ease } }}
      transition={{ duration: 0.45, delay: Math.min(index * 0.05, 0.4), ease }}
      className={cx("relative border-b border-hairline last:border-b-0", isActive && "bg-mark/25")}
    >
      {/* Severity tab on the left edge; it grows into an ink bar when selected. */}
      <span
        aria-hidden
        className={cx(
          "pointer-events-none absolute left-0 top-3 z-[1] w-[3px] rounded-r-sm transition-all duration-300",
          isActive ? "bottom-3 w-[5px] bg-ink" : cx("bottom-[calc(100%-2.25rem)]", classes.dot),
        )}
      />
      <button
        type="button"
        id={`finding-${finding.id}`}
        onClick={onSelect}
        aria-current={isActive}
        aria-expanded={isActive}
        className={cx(
          "group relative w-full px-4 py-3.5 text-left transition-colors duration-200 active:bg-surface-3 sm:px-5",
          isActive ? "bg-mark/20" : "hover:bg-surface-2",
        )}
      >
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} size="sm" />
          <code className="min-w-0 break-all font-mono text-[14px] font-bold text-content-primary">{finding.ruleId}</code>
          {encoded && (
            <span
              title="Found by decoding a base64 value"
              className="inline-flex shrink-0 items-center gap-1 rounded bg-ink px-1.5 py-0.5 font-mono text-[11px] font-bold text-mark"
            >
              <Binary className="h-3.5 w-3.5 shrink-0" aria-hidden />
              base64
            </span>
          )}
          {finding.verified && (
            <span
              title="Checksum verified against the provider's token format"
              className="inline-flex shrink-0 items-center gap-1 rounded bg-severity-clean/10 px-1.5 py-0.5 text-[12px] font-semibold text-severity-clean"
            >
              <BadgeCheck className="h-3.5 w-3.5 shrink-0" aria-hidden />
              verified
            </span>
          )}
          <span
            className="ml-auto inline-flex shrink-0 items-center gap-1 font-mono text-[12px] text-content-tertiary"
            title={finding.detector === "entropy" ? "Entropy detector" : "Signature detector"}
          >
            {finding.detector === "entropy" ? (
              <Sigma className="h-3.5 w-3.5 shrink-0" aria-hidden />
            ) : (
              <Regex className="h-3.5 w-3.5 shrink-0" aria-hidden />
            )}
            {formatEntropy(finding.entropy)}
            <ChevronDown
              className={cx("ml-1 h-4 w-4 shrink-0 transition-transform duration-300", isActive && "rotate-180")}
              aria-hidden
            />
          </span>
        </div>

        <p className="mt-1.5 text-[15px] leading-snug text-content-secondary">{finding.description}</p>

        <div className="mt-2.5 flex flex-wrap items-center gap-x-3 gap-y-1.5 font-mono text-[12px]">
          <span className="text-content-tertiary">
            {finding.path}:{finding.line}:{finding.column}
          </span>
          {/* The redacted value, set as a redaction bar. */}
          <span className="max-w-full truncate rounded-[3px] bg-ink px-2 py-0.5 font-medium text-surface-1 transition-transform duration-200 group-hover:-translate-y-px">
            {finding.redacted}
          </span>
        </div>

        {finding.linePreview.length > 0 && (
          <pre className="mt-2.5 overflow-x-auto rounded-md bg-surface-2 px-2.5 py-2 font-mono text-[12px] text-content-tertiary ring-1 ring-inset ring-hairline">
            {finding.linePreview}
          </pre>
        )}
      </button>

      {/* The fix: opens under the selected finding. */}
      <AnimatePresence initial={false}>
        {isActive && (
          <motion.div
            key="fix"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.32, ease }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 sm:px-5">
              <div className="rounded-lg bg-surface-1 p-3.5 shadow-rest ring-1 ring-hairline sm:p-4">
                <p className="flex items-center gap-2 text-[13px] font-bold text-content-primary">
                  <Wrench className="h-4 w-4 shrink-0" aria-hidden />
                  How to fix
                </p>
                <ol className="mt-2.5 flex flex-col gap-2 text-[14px] leading-snug text-content-secondary">
                  {[fix.revoke, ...fix.steps].map((step, stepIndex) => (
                    <motion.li
                      key={step}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.3, delay: 0.08 + stepIndex * 0.06, ease }}
                      className="flex gap-2.5"
                    >
                      <span
                        className={cx(
                          "mt-[1px] grid h-5 w-5 shrink-0 place-items-center rounded-[4px] font-mono text-[11px] font-bold",
                          stepIndex === 0 ? "bg-ink text-mark" : "bg-surface-3 text-content-secondary",
                        )}
                      >
                        {stepIndex + 1}
                      </span>
                      <span className={cx(stepIndex === 0 && "font-semibold text-content-primary")}>{step}</span>
                    </motion.li>
                  ))}
                </ol>
                <div className="mt-3.5 flex flex-wrap items-center gap-2">
                  {fix.console !== undefined && (
                    <a
                      href={fix.console.href}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="hit inline-flex items-center gap-1.5 rounded-md bg-ink px-3 py-1.5 text-[13px] font-semibold text-surface-1 transition-[transform,background-color] duration-150 hover:bg-ink-soft active:scale-[0.96]"
                    >
                      {fix.console.label}
                      <ExternalLink className="h-3.5 w-3.5 shrink-0 text-mark" aria-hidden />
                    </a>
                  )}
                  <button
                    type="button"
                    onClick={onIgnore}
                    title="Hide it here and add it to the baseline you can download"
                    className="hit inline-flex items-center gap-1.5 rounded-md border border-hairline bg-surface-1 px-3 py-1.5 text-[13px] font-medium text-content-secondary transition-[color,border-color,transform] duration-150 hover:border-hairline-strong hover:text-content-primary active:scale-[0.96]"
                  >
                    <BellOff className="h-3.5 w-3.5 shrink-0" aria-hidden />
                    Mark as false positive
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.li>
  );
}

function CopyLabel({ state, idle, error }: { state: string; idle: string; error?: string }): ReactElement {
  const label = state === "copied" ? "Copied" : state === "error" && error !== undefined ? error : idle;
  return (
    <AnimatePresence mode="popLayout" initial={false}>
      <motion.span
        key={label}
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -6 }}
        transition={{ duration: 0.18, ease }}
      >
        {label}
      </motion.span>
    </AnimatePresence>
  );
}

export function InspectorPanel({
  summary,
  hasInput,
  minSeverity,
  activeFindingId,
  onMinSeverityChange,
  onSelectFinding,
  decodeEncoded,
  onDecodeEncodedChange,
  ignored,
  onIgnore,
  onRestoreIgnored,
}: InspectorPanelProps): ReactElement {
  const [baselineError, setBaselineError] = useState<string | null>(null);

  const downloadBaseline = (): void => {
    setBaselineError(null);
    buildBaseline(ignored)
      .then((text) => {
        const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
        const link = document.createElement("a");
        link.href = url;
        link.download = ".guardenv-baseline.json";
        link.click();
        window.setTimeout(() => { URL.revokeObjectURL(url); }, 1000);
      })
      .catch(() => { setBaselineError("This browser cannot compute the baseline (needs a secure context)."); });
  };
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

  // Keyboard stepping (J / K) keeps the selected row in view inside the list.
  useEffect(() => {
    if (activeFindingId === null) return;
    document.getElementById(`finding-${activeFindingId}`)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [activeFindingId]);

  const secondaryButton =
    "hit inline-flex items-center gap-1.5 rounded-md border border-hairline bg-surface-1 px-2.5 py-1.5 text-[13px] font-medium text-content-secondary transition-[color,border-color,transform] duration-150 hover:border-hairline-strong hover:text-content-primary active:scale-[0.96]";

  return (
    <motion.section
      {...reveal}
      transition={{ ...reveal.transition, delay: 0.08 }}
      aria-label="Audit inspector"
      className="flex min-h-0 flex-col overflow-hidden rounded-xl bg-surface-1 shadow-raised ring-1 ring-hairline xl:h-[min(80svh,780px)]"
    >
      <div className="flex flex-wrap items-center gap-2 border-b border-hairline px-4 py-2.5 sm:px-5">
        <ShieldCheck className="h-4 w-4 shrink-0 text-content-tertiary" aria-hidden />
        <h2 className="font-display text-[17px] font-[750] tracking-[-0.01em] [font-stretch:110%]">
          Audit inspector
        </h2>
        {summary.findings.length > 1 && (
          <span className="ml-2 hidden items-center gap-1 text-[12px] text-content-tertiary [@media(hover:hover)_and_(pointer:fine)]:2xl:inline-flex">
            <kbd className="rounded border border-hairline bg-surface-2 px-1.5 font-mono text-[11px] font-bold text-content-secondary">J</kbd>
            <kbd className="rounded border border-hairline bg-surface-2 px-1.5 font-mono text-[11px] font-bold text-content-secondary">K</kbd>
            step through
          </span>
        )}
        <label
          className="ml-auto flex cursor-pointer select-none items-center gap-2 text-[13px] font-medium text-content-tertiary"
          title="Decode base64 values and scan what is inside them"
        >
          <input
            type="checkbox"
            checked={decodeEncoded}
            onChange={(event) => { onDecodeEncodedChange(event.target.checked); }}
            className="peer sr-only"
          />
          <span
            aria-hidden
            className={cx(
              "relative h-5 w-8 shrink-0 rounded-full transition-colors duration-200 peer-focus-visible:ring-2 peer-focus-visible:ring-ink peer-focus-visible:ring-offset-2",
              decodeEncoded ? "bg-ink" : "bg-surface-4",
            )}
          >
            <motion.span
              initial={false}
              animate={{ x: decodeEncoded ? 14 : 2 }}
              transition={{ type: "spring", stiffness: 600, damping: 34 }}
              className={cx("absolute top-[3px] h-[14px] w-[14px] rounded-full", decodeEncoded ? "bg-mark" : "bg-surface-1")}
            />
          </span>
          Decode base64
        </label>
        <label className="flex items-center gap-2 text-[13px] font-medium text-content-tertiary">
          Min severity
          <select
            value={minSeverity}
            onChange={(event) => { onMinSeverityChange(event.target.value as SeverityLevel); }}
            className="hit cursor-pointer rounded-md border border-hairline bg-surface-1 px-2 py-1 font-mono text-[16px] text-content-primary outline-none transition-colors hover:border-hairline-strong focus:border-ink sm:text-[13px]"
          >
            {SEVERITY_LEVELS.map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="grid grid-cols-2 divide-hairline border-b border-hairline sm:grid-cols-4 sm:divide-x [&>*:nth-child(-n+2)]:border-b [&>*:nth-child(-n+2)]:border-hairline sm:[&>*:nth-child(-n+2)]:border-b-0 [&>*:nth-child(odd)]:border-r [&>*:nth-child(odd)]:border-hairline sm:[&>*:nth-child(odd)]:border-r-0">
        <StatTile
          label="Findings"
          value={<RollingNumber value={summary.totalFindings} />}
          hint={`${detectorSplit.regex} signature · ${detectorSplit.entropy} entropy`}
          accent={
            summary.totalFindings === 0 ? "text-severity-clean" : "text-severity-critical"
          }
        />
        <StatTile
          label="Analysis"
          value={<SpringNumber value={summary.durationMs} format={formatDuration} />}
          hint={`${summary.linesScanned} ${pluralize(summary.linesScanned, "line")} scanned`}
        />
        <StatTile
          label="Critical"
          value={<RollingNumber value={counts.CRITICAL} />}
          hint={`${counts.HIGH} high · ${counts.MEDIUM} medium`}
          accent={counts.CRITICAL > 0 ? "text-severity-critical" : "text-content-secondary"}
        />
        <StatTile
          label="Tokens profiled"
          value={<RollingNumber value={summary.entropyProfile.length} />}
          hint="candidates measured"
        />
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto [overscroll-behavior:contain]">
        <AnimatePresence mode="wait" initial={false}>
          {!hasInput && (
            <motion.div
              key="empty"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="grid h-full min-h-[14rem] place-items-center p-4 text-center"
            >
              <div className="px-6 py-8">
                <div className="mx-auto flex w-40 flex-col gap-2" aria-hidden>
                  <span className="h-2 w-24 rounded-full bg-surface-4" />
                  <span className="h-3 w-full rounded-[3px] bg-ink/85" />
                  <span className="h-2 w-32 rounded-full bg-surface-4" />
                </div>
                <p className="mt-6 text-[16px] font-semibold text-content-secondary">Nothing to audit yet</p>
                <p className="mt-1 text-[14px] text-content-tertiary">
                  Paste a document or load one of the samples to see findings here.
                </p>
              </div>
            </motion.div>
          )}

          {clean && (
            <motion.div
              key="clean"
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3, ease }}
              className="grid h-full min-h-[14rem] place-items-center p-4 text-center"
            >
              <div className="px-6 py-8">
                <motion.span
                  initial={{ scale: 0.6, rotate: -12 }}
                  animate={{ scale: 1, rotate: 0 }}
                  transition={{ ...softSpring, delay: 0.05 }}
                  className="mx-auto grid h-14 w-14 place-items-center rounded-xl bg-severity-clean text-white shadow-raised"
                >
                  <ShieldCheck className="h-7 w-7" aria-hidden />
                </motion.span>
                <p className="mt-4 text-[18px] font-bold text-severity-clean">No credentials detected</p>
                <p className="mt-1 text-[14px] text-content-tertiary">
                  {summary.entropyProfile.length} token
                  {summary.entropyProfile.length === 1 ? "" : "s"} profiled in{" "}
                  {formatDuration(summary.durationMs)}.
                </p>
              </div>
            </motion.div>
          )}

          {summary.findings.length > 0 && (
            <motion.ul key="list" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex flex-col">
              <AnimatePresence initial={true}>
                {summary.findings.map((finding, index) => (
                  <FindingRow
                    key={finding.id}
                    finding={finding}
                    index={index}
                    isActive={activeFindingId === finding.id}
                    onSelect={() => { onSelectFinding(finding); }}
                    onIgnore={() => { onIgnore(finding); }}
                  />
                ))}
              </AnimatePresence>
            </motion.ul>
          )}
        </AnimatePresence>
      </div>

      <AnimatePresence initial={false}>
        {ignored.length > 0 && (
          <motion.div
            key="ignored"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.28, ease }}
            className="overflow-hidden border-t border-hairline"
          >
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5 sm:px-5">
              <span className="min-w-0 flex-1 text-[13px] text-content-secondary">
                <RollingNumber value={ignored.length} className="align-bottom font-bold" /> marked as false{" "}
                {ignored.length === 1 ? "positive" : "positives"}
                {baselineError !== null && <span className="block text-severity-critical">{baselineError}</span>}
              </span>
              <button type="button" onClick={onRestoreIgnored} className={secondaryButton}>
                <RotateCcw className="h-3.5 w-3.5 shrink-0" aria-hidden />
                Restore
              </button>
              <button
                type="button"
                onClick={downloadBaseline}
                title="A .guardenv-baseline.json the CLI accepts with --baseline (name the file with its path in the repo)"
                className={secondaryButton}
              >
                <FileCheck2 className="h-3.5 w-3.5 shrink-0" aria-hidden />
                Baseline
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="flex flex-wrap items-center gap-2 border-t border-hairline bg-surface-2/60 px-4 py-3 sm:px-5">
        <div
          role="radiogroup"
          aria-label="Export format"
          className="flex rounded-lg border border-hairline bg-surface-1 p-0.5"
        >
          {(["json", "sarif"] as const).map((option) => (
            <button
              key={option}
              type="button"
              role="radio"
              aria-checked={format === option}
              onClick={() => { setFormat(option); }}
              className={cx(
                "relative h-10 rounded-md px-3 font-mono sm:h-8 text-[12px] font-bold uppercase transition-colors",
                format === option ? "text-surface-1" : "text-content-tertiary hover:text-content-primary",
              )}
            >
              {format === option && (
                <motion.span layoutId="format-pill" transition={spring} className="absolute inset-0 rounded-md bg-ink" />
              )}
              <span className="relative">{option}</span>
            </button>
          ))}
        </div>

        <button
          type="button"
          onClick={() => void copy(buildReport(summary, format))}
          className={secondaryButton}
        >
          {copyState === "copied" ? (
            <motion.span initial={{ scale: 0 }} animate={{ scale: 1 }} transition={softSpring} className="inline-flex">
              <Check className="h-3.5 w-3.5 shrink-0 text-severity-clean" aria-hidden />
            </motion.span>
          ) : (
            <ClipboardCopy className="h-3.5 w-3.5 shrink-0" aria-hidden />
          )}
          <CopyLabel state={copyState} idle="Copy report" error="Copy failed" />
        </button>

        <button
          type="button"
          onClick={() => void copyMarkdown(toMarkdownReport(summary))}
          className={secondaryButton}
        >
          {mdCopyState === "copied" ? (
            <motion.span initial={{ scale: 0 }} animate={{ scale: 1 }} transition={softSpring} className="inline-flex">
              <Check className="h-3.5 w-3.5 shrink-0 text-severity-clean" aria-hidden />
            </motion.span>
          ) : (
            <Braces className="h-3.5 w-3.5 shrink-0" aria-hidden />
          )}
          <CopyLabel state={mdCopyState} idle="Copy Markdown" />
        </button>

        <button
          type="button"
          onClick={() => { downloadReport(summary, format); }}
          className="hit group ml-auto inline-flex items-center gap-2 rounded-md bg-ink px-3.5 py-1.5 text-[13px] font-semibold text-surface-1 shadow-raised transition-[transform,background-color] duration-150 hover:bg-ink-soft active:scale-[0.96]"
        >
          <Download className="h-3.5 w-3.5 shrink-0 text-mark transition-transform duration-200 group-hover:translate-y-0.5" aria-hidden />
          Download .{format === "sarif" ? "sarif" : "json"}
        </button>
      </div>
    </motion.section>
  );
}
