/* editorial-ui · Cristian Pérez · cristianperez.me */
import { AnimatePresence, motion } from "framer-motion";
import { Check, ClipboardCopy, EyeOff, FileCode2, Trash2, Undo2, Upload } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent, DragEvent, UIEvent, ReactElement } from "react";

import type { ScanFinding, SeverityLevel } from "@/engine/types";
import { SEVERITY_RANK } from "@/engine/types";
import { SAMPLE_DOCUMENTS } from "@/lib/samples";
import { SEVERITY_CLASSES, cx, formatBytes } from "@/lib/format";
import { useCopyToClipboard } from "@/hooks/useCopyToClipboard";
import { ease, reveal, softSpring, spring } from "@/lib/motion";

/** Files a text-oriented scanner can meaningfully read. */
const ACCEPTED_EXTENSIONS = [
  ".env",
  ".txt",
  ".py",
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".ini",
  ".cfg",
  ".conf",
  ".sh",
  ".bash",
  ".zsh",
  ".pem",
  ".key",
  ".md",
  ".xml",
  ".properties",
];

const MAX_FILE_BYTES = 2 * 1024 * 1024;

/** Row height and top padding of the editor, shared by gutter, text and marks. */
const LINE_PX = 24;
const PAD_PX = 14;

interface EditorPanelProps {
  readonly source: string;
  readonly filename: string;
  readonly findings: readonly ScanFinding[];
  readonly activeLine: number | null;
  readonly onSourceChange: (value: string) => void;
  readonly onFilenameChange: (value: string) => void;
  readonly onLoadSample: (content: string, filename: string) => void;
  readonly onClear: () => void;
  /** Whether a redaction can run now (findings exist and the scan is settled). */
  readonly canRedact: boolean;
  /** Called once the redaction bars have landed; the parent swaps the text. */
  readonly onRedact: () => void;
  /** Outcome of the last redaction, while the redacted text is untouched. */
  readonly redaction: { readonly count: number } | null;
  readonly onUndoRedaction: () => void;
}

/** Worst severity per line, so the gutter can carry a single colour. */
function severityByLine(findings: readonly ScanFinding[]): Map<number, SeverityLevel> {
  const map = new Map<number, SeverityLevel>();
  for (const finding of findings) {
    const current = map.get(finding.line);
    if (current === undefined || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[current]) {
      map.set(finding.line, finding.severity);
    }
  }
  return map;
}

export function EditorPanel({
  source,
  filename,
  findings,
  activeLine,
  onSourceChange,
  onFilenameChange,
  onLoadSample,
  onClear,
  canRedact,
  onRedact,
  redaction,
  onUndoRedaction,
}: EditorPanelProps): ReactElement {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [scrollLeft, setScrollLeft] = useState(0);
  const [isRedacting, setIsRedacting] = useState(false);
  // Bumped whenever a whole document arrives: replays the scan sweep.
  const [sweep, setSweep] = useState(0);
  const [metrics, setMetrics] = useState({ charWidth: 7.8, padLeft: 16 });
  const inputRef = useRef<HTMLInputElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const measureRef = useRef<HTMLSpanElement>(null);
  const { state: copyState, copy } = useCopyToClipboard();

  const loadDocument = useCallback(
    (content: string, name: string) => {
      setSweep((value) => value + 1);
      onLoadSample(content, name);
    },
    [onLoadSample],
  );

  // Monospace cell width and the textarea's inset, so overlays land on characters.
  useEffect(() => {
    const measure = (): void => {
      const probe = measureRef.current;
      const area = textareaRef.current;
      if (probe === null || area === null) return;
      setMetrics({
        charWidth: probe.getBoundingClientRect().width / 20,
        padLeft: parseFloat(getComputedStyle(area).paddingLeft) || 16,
      });
    };
    measure();
    void document.fonts.ready.then(measure);
    window.addEventListener("resize", measure);
    return () => { window.removeEventListener("resize", measure); };
  }, []);

  // Selecting a finding elsewhere brings its line into the editor's view.
  useEffect(() => {
    const area = textareaRef.current;
    if (activeLine === null || area === null) return;
    const top = PAD_PX + (activeLine - 1) * LINE_PX;
    if (top < area.scrollTop + LINE_PX || top > area.scrollTop + area.clientHeight - LINE_PX * 2) {
      area.scrollTo({ top: Math.max(0, top - area.clientHeight / 2), behavior: "smooth" });
    }
  }, [activeLine]);

  const redactionBars = useMemo(() => {
    if (!isRedacting) return [];
    const seen = new Set<string>();
    return [...findings]
      .sort((a, b) => a.line - b.line || a.column - b.column)
      .filter((finding) => {
        const key = `${finding.line}:${finding.column}:${finding.match.length}`;
        if (seen.has(key) || finding.match.length === 0) return false;
        seen.add(key);
        return true;
      });
  }, [isRedacting, findings]);

  const startRedaction = useCallback(() => {
    if (!canRedact || isRedacting) return;
    setIsRedacting(true);
  }, [canRedact, isRedacting]);

  const finishRedaction = useCallback(() => {
    setIsRedacting(false);
    setSweep((value) => value + 1);
    onRedact();
  }, [onRedact]);

  const lines = useMemo(() => source.split("\n"), [source]);
  const lineSeverity = useMemo(() => severityByLine(findings), [findings]);
  const byteSize = useMemo(() => new TextEncoder().encode(source).length, [source]);

  const handleScroll = useCallback((event: UIEvent<HTMLTextAreaElement>) => {
    setScrollTop(event.currentTarget.scrollTop);
    setScrollLeft(event.currentTarget.scrollLeft);
    if (gutterRef.current !== null) {
      gutterRef.current.scrollTop = event.currentTarget.scrollTop;
    }
  }, []);

  const readFile = useCallback(
    (file: File) => {
      setError(null);
      if (file.size > MAX_FILE_BYTES) {
        setError(`${file.name} is ${formatBytes(file.size)}; the playground caps files at 2 MB.`);
        return;
      }
      const reader = new FileReader();
      reader.onerror = () => { setError(`Could not read ${file.name}.`); };
      reader.onload = () => {
        const text = typeof reader.result === "string" ? reader.result : "";
        // A NUL byte in the first 8 KiB is the same binary test the CLI uses.
        if (text.slice(0, 8192).includes("\u0000")) {
          setError(`${file.name} looks binary; GuardEnv only scans text.`);
          return;
        }
        loadDocument(text, file.name);
      };
      reader.readAsText(file);
    },
    [loadDocument],
  );

  const handleDrop = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setIsDragging(false);
      const file = event.dataTransfer.files.item(0);
      if (file !== null) readFile(file);
    },
    [readFile],
  );

  const handleFileInput = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.item(0);
      if (file != null) readFile(file);
      event.target.value = "";
    },
    [readFile],
  );

  const activeSampleId = SAMPLE_DOCUMENTS.find((sample) => sample.content === source)?.id ?? null;
  const markedLines = [...lineSeverity.keys()];

  const toolButton =
    "hit inline-flex items-center gap-1.5 rounded-md border border-hairline bg-surface-1 px-2.5 py-1.5 text-[13px] font-medium text-content-secondary transition-[color,border-color,background-color,transform] duration-150 hover:border-hairline-strong hover:text-content-primary active:scale-[0.96] disabled:cursor-not-allowed disabled:opacity-40 disabled:active:scale-100";

  return (
    <motion.section
      {...reveal}
      aria-label="Source editor"
      className={cx(
        "relative flex min-h-0 flex-col overflow-hidden rounded-xl bg-surface-1 shadow-raised ring-1 transition-[box-shadow] duration-300 xl:h-[min(80svh,780px)]",
        isDragging ? "ring-2 ring-ink" : "ring-hairline",
      )}
      onDragOver={(event) => {
        event.preventDefault();
        setIsDragging(true);
      }}
      onDragLeave={() => { setIsDragging(false); }}
      onDrop={handleDrop}
    >
      <div className="flex flex-wrap items-center gap-2 border-b border-hairline px-3 py-2.5 sm:px-4">
        <FileCode2 className="h-4 w-4 shrink-0 text-content-tertiary" aria-hidden />
        <label className="sr-only" htmlFor="guardenv-filename">
          File name
        </label>
        <input
          id="guardenv-filename"
          value={filename}
          onChange={(event) => { onFilenameChange(event.target.value); }}
          spellCheck={false}
          className="min-w-[9rem] flex-1 basis-[9rem] rounded-md border border-transparent bg-transparent px-1.5 py-1 font-mono text-[16px] font-medium text-content-primary outline-none transition-colors hover:border-hairline focus:border-hairline-strong focus:bg-surface-2 sm:text-[14px]"
        />
        <span className="shrink-0 font-mono text-[12px] text-content-tertiary">
          {lines.length} L · {formatBytes(byteSize)}
        </span>
        <div className="ml-auto flex items-center gap-1.5">
          <motion.button
            type="button"
            onClick={startRedaction}
            disabled={!canRedact || isRedacting}
            whileTap={{ scale: 0.95 }}
            title="Black out every reported credential in this document"
            className="hit group inline-flex items-center gap-1.5 rounded-md bg-ink px-2.5 py-1.5 text-[13px] font-semibold text-surface-1 shadow-rest transition-[background-color,opacity] duration-150 hover:bg-ink-soft disabled:cursor-not-allowed disabled:opacity-35"
          >
            <EyeOff className="h-3.5 w-3.5 shrink-0 text-mark transition-transform duration-200 group-hover:-rotate-12" aria-hidden />
            Redact
          </motion.button>
          <button type="button" onClick={() => inputRef.current?.click()} className={toolButton}>
            <Upload className="h-3.5 w-3.5 shrink-0" aria-hidden />
            Upload
          </button>
          <button type="button" onClick={onClear} disabled={source.length === 0} className={toolButton}>
            <Trash2 className="h-3.5 w-3.5 shrink-0" aria-hidden />
            Clear
          </button>
        </div>
        <input
          ref={inputRef}
          type="file"
          accept={ACCEPTED_EXTENSIONS.join(",")}
          onChange={handleFileInput}
          className="hidden"
        />
      </div>

      <div className="flex flex-wrap items-center gap-1 border-b border-hairline px-3 py-1.5 sm:px-4">
        <span className="mr-1 shrink-0 text-[13px] font-semibold text-content-secondary sm:mr-2">Samples</span>
        {SAMPLE_DOCUMENTS.map((sample) => {
          const active = activeSampleId === sample.id;
          return (
            <motion.button
              key={sample.id}
              type="button"
              title={sample.description}
              onClick={() => { loadDocument(sample.content, sample.filename); }}
              whileTap={{ scale: 0.95 }}
              className={cx(
                "relative h-10 shrink-0 rounded-md px-2 font-mono sm:h-8 sm:px-2.5 text-[13px] transition-colors",
                active ? "text-content-primary" : "text-content-tertiary hover:bg-surface-2 hover:text-content-primary",
              )}
            >
              {active && (
                <motion.span
                  layoutId="sample-mark"
                  transition={spring}
                  className="absolute inset-0 rounded-md bg-mark"
                />
              )}
              <span className="relative">{sample.label}</span>
            </motion.button>
          );
        })}
      </div>

      <AnimatePresence initial={false}>
        {error !== null && (
          <motion.p
            key="error"
            role="alert"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease }}
            className="overflow-hidden border-b border-severity-critical/30 bg-severity-critical/[0.07] text-[14px] text-severity-critical"
          >
            <span className="block px-4 py-2.5">{error}</span>
          </motion.p>
        )}
      </AnimatePresence>

      <AnimatePresence initial={false}>
        {redaction !== null && (
          <motion.div
            key="redacted"
            role="status"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease }}
            className="overflow-hidden border-b border-ink bg-ink text-surface-1"
          >
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-3 py-2.5 sm:px-4">
              <motion.span
                initial={{ scale: 0.6, rotate: -14 }}
                animate={{ scale: 1, rotate: -4 }}
                transition={{ ...softSpring, delay: 0.1 }}
                className="rounded-[3px] border-2 border-mark px-1.5 py-0.5 font-display text-[12px] font-[850] uppercase tracking-[0.08em] text-mark [font-stretch:110%]"
              >
                Redacted
              </motion.span>
              <span className="min-w-[12rem] flex-1 text-[14px] leading-snug text-surface-1/85">
                {redaction.count} {redaction.count === 1 ? "secret" : "secrets"} blacked out. This copy is safe to share.
              </span>
              <span className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => void copy(source)}
                  className="hit inline-flex items-center gap-1.5 rounded-md bg-mark px-2.5 py-1 text-[13px] font-semibold text-ink transition-transform duration-150 active:scale-[0.96]"
                >
                  {copyState === "copied" ? (
                    <Check className="h-3.5 w-3.5 shrink-0" aria-hidden />
                  ) : (
                    <ClipboardCopy className="h-3.5 w-3.5 shrink-0" aria-hidden />
                  )}
                  {copyState === "copied" ? "Copied" : copyState === "error" ? "Copy failed" : "Copy"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSweep((value) => value + 1);
                    onUndoRedaction();
                  }}
                  className="hit inline-flex items-center gap-1.5 rounded-md border border-surface-1/25 px-2.5 py-1 text-[13px] font-semibold text-surface-1 transition-[transform,border-color] duration-150 hover:border-surface-1/60 active:scale-[0.96]"
                >
                  <Undo2 className="h-3.5 w-3.5 shrink-0" aria-hidden />
                  Undo
                </button>
              </span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="relative flex h-[24rem] min-h-0 flex-1 sm:h-[28rem] xl:h-auto">
        <div
          ref={gutterRef}
          aria-hidden
          className="relative z-[1] shrink-0 select-none overflow-hidden border-r border-hairline bg-surface-2 text-right font-mono text-[12px] text-content-faint"
          // Room for the digits plus the severity tab that sits in the left margin.
          style={{ width: `${Math.max(4.5, String(lines.length).length + 3)}ch`, paddingTop: PAD_PX, paddingBottom: PAD_PX, lineHeight: `${LINE_PX}px` }}
        >
          <div style={{ transform: `translateY(-${scrollTop}px)` }}>
            {lines.map((_, index) => {
              const lineNumber = index + 1;
              const severity = lineSeverity.get(lineNumber);
              return (
                <div
                  key={lineNumber}
                  className={cx(
                    "relative pr-2.5 transition-colors duration-200",
                    severity !== undefined && cx(SEVERITY_CLASSES[severity].text, "font-bold"),
                    activeLine === lineNumber && "bg-ink !text-mark",
                  )}
                >
                  {severity !== undefined && (
                    <span
                      className={cx(
                        "absolute left-0 top-1 h-4 w-[3px] rounded-r-sm",
                        SEVERITY_CLASSES[severity].dot,
                      )}
                    />
                  )}
                  {lineNumber}
                </div>
              );
            })}
          </div>
        </div>

        <div className="relative min-w-0 flex-1">
          {/* Highlighter marks behind flagged lines; they scroll with the text. */}
          <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
            <div style={{ transform: `translateY(-${scrollTop}px)` }}>
              <AnimatePresence>
                {markedLines.map((line) => {
                  const active = activeLine === line;
                  return (
                    <motion.div
                      key={`${filename}-${line}`}
                      className={cx(
                        "absolute left-1.5 right-1.5 origin-left rounded-[3px] transition-colors duration-200",
                        active ? "bg-mark" : "bg-mark/45",
                      )}
                      style={{ top: PAD_PX + (line - 1) * LINE_PX + 2, height: LINE_PX - 4 }}
                      initial={{ clipPath: "inset(0 100% 0 0)" }}
                      animate={{ clipPath: "inset(0 0% 0 0)" }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.5, delay: Math.min(line * 0.025, 0.5), ease }}
                    />
                  );
                })}
              </AnimatePresence>
              {activeLine !== null && !lineSeverity.has(activeLine) && (
                <div
                  className="absolute left-1.5 right-1.5 rounded-[3px] bg-surface-4"
                  style={{ top: PAD_PX + (activeLine - 1) * LINE_PX + 2, height: LINE_PX - 4 }}
                />
              )}
            </div>
          </div>

          {/* Redaction bars: they land on each secret, then the text becomes blocks. */}
          {redactionBars.length > 0 && (
            <div aria-hidden className="pointer-events-none absolute inset-0 z-[2] overflow-hidden">
              {redactionBars.map((finding, index) => (
                <motion.span
                  key={`${finding.line}:${finding.column}`}
                  className="absolute rounded-[2px] bg-ink"
                  style={{
                    top: PAD_PX + (finding.line - 1) * LINE_PX + 3 - scrollTop,
                    left: metrics.padLeft + (finding.column - 1) * metrics.charWidth - scrollLeft - 1,
                    width: finding.match.length * metrics.charWidth + 2,
                    height: LINE_PX - 6,
                  }}
                  initial={{ clipPath: "inset(0 100% 0 0)" }}
                  animate={{ clipPath: "inset(0 0% 0 0)" }}
                  transition={{ duration: 0.38, delay: index * 0.09, ease }}
                  onAnimationComplete={() => { if (index === redactionBars.length - 1) finishRedaction(); }}
                />
              ))}
            </div>
          )}

          {/* Scan sweep: a highlighter edge passes down the page once per document. */}
          <div aria-hidden className="pointer-events-none absolute inset-0 z-[1] overflow-hidden">
            <motion.div
              key={`sweep-${sweep}`}
              className="h-full w-full"
              initial={{ y: "-100%", opacity: 1 }}
              animate={{ y: "0%", opacity: [1, 1, 0] }}
              transition={{ duration: 1.1, delay: sweep === 0 ? 0.5 : 0, ease: [0.45, 0, 0.2, 1], opacity: { times: [0, 0.8, 1], duration: 1.1, delay: sweep === 0 ? 0.5 : 0 } }}
              style={{
                background:
                  "linear-gradient(to bottom, transparent calc(100% - 72px), rgb(227 242 74 / 0.35) calc(100% - 4px), #101317 calc(100% - 2px), #101317 100%)",
              }}
            />
          </div>

          <span
            ref={measureRef}
            aria-hidden
            className="invisible absolute left-0 top-0 whitespace-pre font-mono text-[13px]"
          >
            {"0".repeat(20)}
          </span>

          <label className="sr-only" htmlFor="guardenv-source">
            Source to scan
          </label>
          <textarea
            ref={textareaRef}
            id="guardenv-source"
            value={source}
            onChange={(event) => { onSourceChange(event.target.value); }}
            onScroll={handleScroll}
            spellCheck={false}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            // Soft wrapping would desynchronise the gutter: one logical line has to
            // occupy exactly one visual row for the numbering to stay honest.
            wrap="off"
            placeholder="Paste a .env file, a config or any source code — nothing leaves your browser."
            className="relative h-full w-full resize-none overflow-auto whitespace-pre bg-transparent px-3 font-mono text-[13px] text-content-primary caret-ink outline-none placeholder:text-content-faint focus-visible:ring-0 focus-visible:ring-offset-0 sm:px-4"
            style={{ lineHeight: `${LINE_PX}px`, paddingTop: PAD_PX, paddingBottom: PAD_PX }}
          />
        </div>

        <AnimatePresence>
          {isDragging && (
            <motion.div
              key="drop"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.18 }}
              className="pointer-events-none absolute inset-2 z-10 grid place-items-center rounded-lg border-2 border-dashed border-ink bg-surface-1/90"
            >
              <motion.div
                initial={{ y: 8, scale: 0.96 }}
                animate={{ y: 0, scale: 1 }}
                transition={spring}
                className="flex flex-col items-center gap-2 text-content-primary"
              >
                <Upload className="h-6 w-6" aria-hidden />
                <span className="marker text-[15px] font-semibold">Drop the file to scan it</span>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.section>
  );
}
