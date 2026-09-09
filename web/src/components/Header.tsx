import type { ReactElement } from "react";
import { Radar, ShieldAlert, ShieldCheck } from "lucide-react";

import type { ScanSummary } from "@/engine/types";
import type { AnalysisMode } from "@/hooks/useScanner";
import { cx, pluralize } from "@/lib/format";

const MODES: readonly { id: AnalysisMode; label: string; hint: string }[] = [
  { id: "combined", label: "Combined", hint: "Regex signatures plus entropy analysis" },
  { id: "rules", label: "Signatures", hint: "Deterministic vendor patterns only" },
  { id: "entropy", label: "Entropy", hint: "Shannon entropy analysis only" },
];

/**
 * Inline GitHub mark. lucide-react has deprecated its brand icons, so the glyph
 * lives here rather than pinning a dependency that is scheduled for removal.
 */
function GithubMark({ className }: { className?: string }): ReactElement {
  return (
    <svg viewBox="0 0 16 16" fill="currentColor" className={className} aria-hidden focusable="false">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}

interface HeaderProps {
  readonly summary: ScanSummary;
  readonly mode: AnalysisMode;
  readonly isScanning: boolean;
  readonly hasInput: boolean;
  readonly onModeChange: (mode: AnalysisMode) => void;
  readonly repositoryUrl: string;
}

function StatusPill({
  summary,
  isScanning,
  hasInput,
}: Pick<HeaderProps, "summary" | "isScanning" | "hasInput">): ReactElement {
  if (isScanning) {
    return (
      <span className="inline-flex items-center gap-2 rounded-full border border-hairline bg-surface-2 px-3 py-1 text-xs text-content-secondary">
        <Radar className="h-3.5 w-3.5 animate-spin text-content-tertiary" aria-hidden />
        Analysing
      </span>
    );
  }
  if (!hasInput) {
    return (
      <span className="inline-flex items-center gap-2 rounded-full border border-hairline bg-surface-2 px-3 py-1 text-xs text-content-tertiary">
        <span className="h-1.5 w-1.5 rounded-full bg-content-faint" aria-hidden />
        Idle
      </span>
    );
  }
  const clean = summary.totalFindings === 0;
  return (
    <span
      className={cx(
        "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium",
        clean
          ? "border-severity-clean/30 bg-severity-clean/10 text-severity-clean"
          : "border-severity-critical/30 bg-severity-critical/10 text-severity-critical",
      )}
    >
      {clean ? (
        <ShieldCheck className="h-3.5 w-3.5" aria-hidden />
      ) : (
        <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
      )}
      {clean
        ? "Clean"
        : `${summary.totalFindings} ${pluralize(summary.totalFindings, "finding")}`}
    </span>
  );
}

export function Header({
  summary,
  mode,
  isScanning,
  hasInput,
  onModeChange,
  repositoryUrl,
}: HeaderProps): ReactElement {
  return (
    <header className="sticky top-0 z-20 border-b border-hairline bg-surface-0/85 backdrop-blur-md">
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3 sm:px-6">
        <div className="flex items-center gap-3">
          <div className="grid h-8 w-8 place-items-center rounded-md border border-hairline-strong bg-surface-3">
            <ShieldCheck className="h-4 w-4 text-severity-clean" aria-hidden />
          </div>
          <div className="leading-tight">
            <h1 className="font-semibold tracking-tight text-content-primary">GuardEnv</h1>
            <p className="text-[11px] text-content-tertiary">
              Secret scanner playground · runs entirely in your browser
            </p>
          </div>
        </div>

        <StatusPill summary={summary} isScanning={isScanning} hasInput={hasInput} />

        <div className="ml-auto flex items-center gap-3">
          <div
            role="radiogroup"
            aria-label="Analysis mode"
            className="flex rounded-md border border-hairline bg-surface-2 p-0.5"
          >
            {MODES.map((entry) => (
              <button
                key={entry.id}
                type="button"
                role="radio"
                aria-checked={mode === entry.id}
                title={entry.hint}
                onClick={() => { onModeChange(entry.id); }}
                className={cx(
                  "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                  mode === entry.id
                    ? "bg-surface-4 text-content-primary shadow-sm"
                    : "text-content-tertiary hover:text-content-secondary",
                )}
              >
                {entry.label}
              </button>
            ))}
          </div>

          <a
            href={repositoryUrl}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-2 rounded-md border border-hairline bg-surface-2 px-3 py-1.5 text-xs font-medium text-content-secondary transition-colors hover:border-hairline-strong hover:text-content-primary"
          >
            <GithubMark className="h-3.5 w-3.5" />
            Repository
          </a>
        </div>
      </div>
    </header>
  );
}
