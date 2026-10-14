/* editorial-ui · Cristian Pérez · cristianperez.me */
import { motion } from "framer-motion";
import { FileText, FolderSearch, X } from "lucide-react";
import { useEffect, useMemo, useRef } from "react";
import type { ReactElement } from "react";

import { scanDocument } from "@/engine/pipeline";
import type { PipelineSettings } from "@/engine/pipeline";
import { SEVERITY_LEVELS, SEVERITY_RANK } from "@/engine/types";
import type { ScanSummary } from "@/engine/types";
import { useLang } from "@/i18n/context";
import type { FolderFile, FolderRead } from "@/lib/folder";
import { MAX_FOLDER_FILES } from "@/lib/folder";
import { SEVERITY_CLASSES, cx } from "@/lib/format";
import { ease, reveal } from "@/lib/motion";
import { RollingNumber } from "./Numbers";

interface FolderPanelProps {
  readonly folder: FolderRead;
  readonly settings: PipelineSettings;
  readonly activePath: string;
  readonly onOpen: (file: FolderFile) => void;
  readonly onClose: () => void;
}

interface FileResult {
  readonly file: FolderFile;
  readonly summary: ScanSummary;
}

/** Long paths keep their end (the file name) and lose the middle. */
function middleTruncate(path: string, max = 64): string {
  if (path.length <= max) return path;
  const keep = Math.floor((max - 1) / 2);
  return `${path.slice(0, keep)}…${path.slice(-keep)}`;
}

export function FolderPanel({ folder, settings, activePath, onOpen, onClose }: FolderPanelProps): ReactElement {
  const { t } = useLang();
  const sectionRef = useRef<HTMLElement>(null);

  // A new folder brings its report into view (the sticky header is the margin).
  useEffect(() => {
    sectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [folder]);

  const results = useMemo<FileResult[]>(() => {
    const scanned = folder.files.map((file) => ({ file, summary: scanDocument(file.content, file.path, settings) }));
    // Worst file first: highest severity, then most findings, then path.
    return scanned.sort((a, b) => {
      const rank = (r: FileResult): number =>
        r.summary.highestSeverity === null ? -1 : SEVERITY_RANK[r.summary.highestSeverity];
      return rank(b) - rank(a) || b.summary.totalFindings - a.summary.totalFindings || a.file.path.localeCompare(b.file.path);
    });
  }, [folder, settings]);

  const withFindings = results.filter((r) => r.summary.totalFindings > 0).length;
  const total = results.reduce((sum, r) => sum + r.summary.totalFindings, 0);

  return (
    <motion.section
      {...reveal}
      ref={sectionRef}
      aria-label={t.folder.title}
      className="scroll-mt-32 overflow-hidden rounded-xl bg-surface-1 shadow-raised ring-1 ring-hairline"
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-hairline px-4 py-3 sm:px-5">
        <FolderSearch className="h-4 w-4 shrink-0 text-content-tertiary" aria-hidden />
        <h2 className="font-display text-[17px] font-[750] tracking-[-0.01em] [font-stretch:110%]">{t.folder.title}</h2>
        <span className="text-[13px] text-content-tertiary">{t.folder.summary(results.length, withFindings)}</span>
        <span className="ml-auto flex items-baseline gap-2">
          <span className="font-display text-[26px] font-[850] leading-none tracking-[-0.02em] [font-stretch:108%]">
            <RollingNumber value={total} />
          </span>
          <span className="text-[13px] text-content-tertiary">{t.folder.total}</span>
        </span>
        <button
          type="button"
          onClick={onClose}
          aria-label={t.folder.close}
          className="hit inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-hairline text-content-secondary transition-[color,border-color,transform] duration-150 hover:border-hairline-strong hover:text-content-primary active:scale-[0.94]"
        >
          <X className="h-4 w-4 shrink-0" aria-hidden />
        </button>
      </div>

      <ul className="max-h-[22rem] overflow-y-auto [overscroll-behavior:contain]">
        {results.map((result, index) => {
          const { file, summary } = result;
          const active = file.path === activePath;
          const worst = summary.highestSeverity;
          return (
            <motion.li
              key={file.path}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.35, delay: Math.min(index * 0.025, 0.5), ease }}
              className="border-b border-hairline last:border-b-0"
            >
              <button
                type="button"
                onClick={() => { onOpen(file); }}
                title={t.folder.open}
                aria-current={active}
                className={cx(
                  "group relative flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors duration-200 sm:px-5",
                  active ? "bg-mark/25 dark:bg-mark/10" : "hover:bg-surface-2",
                )}
              >
                <span
                  aria-hidden
                  className={cx(
                    "absolute inset-y-2 left-0 w-[3px] rounded-r-sm",
                    worst === null ? "bg-transparent" : SEVERITY_CLASSES[worst].dot,
                  )}
                />
                <FileText className="h-4 w-4 shrink-0 text-content-tertiary" aria-hidden />
                <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-content-primary">
                  {middleTruncate(file.path)}
                </span>
                {summary.totalFindings === 0 ? (
                  <span className="shrink-0 text-[12px] font-semibold text-severity-clean">{t.folder.clean}</span>
                ) : (
                  <span className="flex shrink-0 items-center gap-1.5">
                    {SEVERITY_LEVELS.filter((level) => summary.countsBySeverity[level] > 0).map((level) => (
                      <span
                        key={level}
                        title={t.severity[level]}
                        className={cx(
                          "inline-flex min-w-6 items-center justify-center rounded px-1.5 py-0.5 font-mono text-[11px] font-bold ring-1 ring-inset",
                          SEVERITY_CLASSES[level].badge,
                        )}
                      >
                        {summary.countsBySeverity[level]}
                      </span>
                    ))}
                  </span>
                )}
              </button>
            </motion.li>
          );
        })}
      </ul>

      {(folder.skipped > 0 || folder.capped) && (
        <p className="border-t border-hairline px-4 py-2.5 text-[12px] text-content-tertiary sm:px-5">
          {folder.skipped > 0 && t.folder.skipped(folder.skipped)}
          {folder.capped && ` ${t.folder.capped(MAX_FOLDER_FILES)}`}
        </p>
      )}
    </motion.section>
  );
}
