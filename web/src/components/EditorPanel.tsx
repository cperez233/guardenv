/* editorial-ui · Cristian Pérez · cristianperez.me */
import { AnimatePresence, motion } from "framer-motion";
import { FileCode2, Trash2, Upload } from "lucide-react";
import { useCallback, useMemo, useRef, useState } from "react";
import type { ChangeEvent, DragEvent, UIEvent, ReactElement } from "react";

import type { ScanFinding, SeverityLevel } from "@/engine/types";
import { SEVERITY_RANK } from "@/engine/types";
import { SAMPLE_DOCUMENTS } from "@/lib/samples";
import { SEVERITY_CLASSES, cx, formatBytes } from "@/lib/format";
import { ease, reveal, spring } from "@/lib/motion";

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
}: EditorPanelProps): ReactElement {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);

  const lines = useMemo(() => source.split("\n"), [source]);
  const lineSeverity = useMemo(() => severityByLine(findings), [findings]);
  const byteSize = useMemo(() => new TextEncoder().encode(source).length, [source]);

  const handleScroll = useCallback((event: UIEvent<HTMLTextAreaElement>) => {
    setScrollTop(event.currentTarget.scrollTop);
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
        onLoadSample(text, file.name);
      };
      reader.readAsText(file);
    },
    [onLoadSample],
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
              onClick={() => { onLoadSample(sample.content, sample.filename); }}
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

          <label className="sr-only" htmlFor="guardenv-source">
            Source to scan
          </label>
          <textarea
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
