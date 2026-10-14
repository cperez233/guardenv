/* editorial-ui · Cristian Pérez · cristianperez.me */
import { AnimatePresence, motion } from "framer-motion";
import { FileText, FolderSearch, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactElement } from "react";

import { scanDocument } from "@/engine/pipeline";
import type { PipelineSettings } from "@/engine/pipeline";
import { SEVERITY_LEVELS, SEVERITY_RANK } from "@/engine/types";
import type { ScanSummary } from "@/engine/types";
import { useLang } from "@/i18n/context";
import type { FolderFile, FolderRead } from "@/lib/folder";
import { MAX_FOLDER_FILES } from "@/lib/folder";
import { SEVERITY_CLASSES, cx } from "@/lib/format";
import { ease, reveal, spring } from "@/lib/motion";
import { RollingNumber } from "./Numbers";

interface FolderPanelProps {
  /** The read folder, or null while it is still being read. */
  readonly folder: FolderRead | null;
  /** Files read so far, while reading. */
  readonly reading: number | null;
  readonly settings: PipelineSettings;
  readonly activePath: string;
  readonly onOpen: (file: FolderFile) => void;
  readonly onClose: () => void;
}

interface FileResult {
  readonly file: FolderFile;
  readonly summary: ScanSummary;
}

type Filter = "findings" | "all";

/** Files scanned between two paints: keeps the page responsive on big folders. */
const SCAN_BATCH = 25;
/** Rows beyond this enter without their own animation (a long list is a list, not a show). */
const ANIMATED_ROWS = 30;

/** Long paths keep their end (the file name) and lose the middle. */
function middleTruncate(path: string, max = 64): string {
  if (path.length <= max) return path;
  const keep = Math.floor((max - 1) / 2);
  return `${path.slice(0, keep)}…${path.slice(-keep)}`;
}

const rank = (r: FileResult): number =>
  r.summary.highestSeverity === null ? -1 : SEVERITY_RANK[r.summary.highestSeverity];

export function FolderPanel({ folder, reading, settings, activePath, onOpen, onClose }: FolderPanelProps): ReactElement {
  const { t } = useLang();
  const sectionRef = useRef<HTMLElement>(null);
  const [results, setResults] = useState<FileResult[]>([]);
  const [scanned, setScanned] = useState(0);
  const [filter, setFilter] = useState<Filter>("findings");

  // The panel brings itself into view when it appears (the sticky header is the margin).
  useEffect(() => {
    sectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  // Scan in batches, yielding to the browser between them; restart when the
  // folder or the settings change, and drop the work of a stale run.
  useEffect(() => {
    if (folder === null) {
      setResults([]);
      setScanned(0);
      return;
    }
    let cancelled = false;
    const out: FileResult[] = [];
    setScanned(0);
    const run = async (): Promise<void> => {
      for (let start = 0; start < folder.files.length; start += SCAN_BATCH) {
        for (const file of folder.files.slice(start, start + SCAN_BATCH)) {
          out.push({ file, summary: scanDocument(file.content, file.path, settings) });
        }
        if (cancelled) return;
        setScanned(out.length);
        await new Promise((resolve) => { window.setTimeout(resolve, 0); });
        if (cancelled) return;
      }
      // Worst file first: highest severity, then most findings, then path.
      out.sort(
        (a, b) =>
          rank(b) - rank(a) || b.summary.totalFindings - a.summary.totalFindings || a.file.path.localeCompare(b.file.path),
      );
      setResults(out);
    };
    void run();
    return () => { cancelled = true; };
  }, [folder, settings]);

  const total = folder?.files.length ?? 0;
  const scanning = folder !== null && scanned < total;
  const withFindings = results.filter((r) => r.summary.totalFindings > 0);
  const findingsTotal = results.reduce((sum, r) => sum + r.summary.totalFindings, 0);
  const visible = useMemo(() => (filter === "findings" ? withFindings : results), [filter, withFindings, results]);

  const progress = folder === null ? null : total === 0 ? 1 : scanned / total;

  return (
    <motion.section
      {...reveal}
      ref={sectionRef}
      aria-label={t.folder.title}
      aria-busy={folder === null || scanning}
      className="relative scroll-mt-32 overflow-hidden rounded-xl bg-surface-1 shadow-raised ring-1 ring-hairline"
    >
      {/* Progress: reading fills the first half, scanning the second. */}
      <motion.span
        aria-hidden
        className="absolute inset-x-0 top-0 h-[3px] origin-left bg-mark"
        initial={{ scaleX: 0 }}
        animate={{
          scaleX: folder === null ? 0.08 + Math.min(0.42, (reading ?? 0) / 4000) : 0.5 + (progress ?? 0) / 2,
          opacity: scanning || folder === null ? 1 : 0,
        }}
        transition={{ duration: 0.3, ease }}
      />

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-hairline px-4 py-3 sm:px-5">
        <FolderSearch className="h-4 w-4 shrink-0 text-content-tertiary" aria-hidden />
        <h2 className="font-display text-[17px] font-[750] tracking-[-0.01em] [font-stretch:110%]">{t.folder.title}</h2>
        <span className="text-[13px] text-content-tertiary" aria-live="polite">
          {folder === null
            ? t.folder.reading(reading ?? 0)
            : scanning
              ? t.folder.scanning(scanned, total)
              : t.folder.summary(results.length, withFindings.length)}
        </span>
        <span className="ml-auto flex items-baseline gap-2">
          <span className="font-display text-[26px] font-[850] leading-none tracking-[-0.02em] [font-stretch:108%]">
            <RollingNumber value={findingsTotal} />
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

      {results.length > 0 && (
        <div className="flex items-center gap-2 border-b border-hairline px-4 py-2 sm:px-5">
          <div role="radiogroup" aria-label={t.folder.filter} className="flex rounded-lg border border-hairline bg-surface-2 p-0.5">
            {(["findings", "all"] as const).map((option) => {
              const selected = filter === option;
              return (
                <button
                  key={option}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  onClick={() => { setFilter(option); }}
                  className={cx(
                    "relative h-8 rounded-md px-3 text-[13px] font-semibold transition-colors",
                    selected ? "text-surface-1" : "text-content-tertiary hover:text-content-primary",
                  )}
                >
                  {selected && <motion.span layoutId="folder-filter" transition={spring} className="absolute inset-0 rounded-md bg-ink" />}
                  <span className="relative">
                    {option === "findings" ? t.folder.withFindings(withFindings.length) : t.folder.all(results.length)}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      <ul className="max-h-[24rem] overflow-y-auto [overscroll-behavior:contain]">
        <AnimatePresence initial={false}>
          {visible.map((result, index) => {
            const { file, summary } = result;
            const active = file.path === activePath;
            const worst = summary.highestSeverity;
            const animated = index < ANIMATED_ROWS;
            return (
              <motion.li
                key={file.path}
                layout={animated ? "position" : false}
                initial={animated ? { opacity: 0, x: -10 } : false}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, transition: { duration: 0.12 } }}
                transition={{ duration: 0.35, delay: animated ? Math.min(index * 0.025, 0.5) : 0, ease }}
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
        </AnimatePresence>
        {folder !== null && !scanning && visible.length === 0 && results.length > 0 && (
          <li className="px-4 py-6 text-center text-[14px] text-content-tertiary sm:px-5">{t.folder.noneWithFindings}</li>
        )}
      </ul>

      {folder !== null && (folder.skipped > 0 || folder.capped) && (
        <p className="border-t border-hairline px-4 py-2.5 text-[12px] text-content-tertiary sm:px-5">
          {folder.skipped > 0 && t.folder.skipped(folder.skipped)}
          {folder.capped && ` ${t.folder.capped(MAX_FOLDER_FILES)}`}
        </p>
      )}
    </motion.section>
  );
}
