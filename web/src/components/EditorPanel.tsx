import { FileCode2, Trash2, Upload } from "lucide-react";
import { useCallback, useMemo, useRef, useState } from "react";
import type { ChangeEvent, DragEvent, UIEvent, ReactElement } from "react";

import type { ScanFinding, SeverityLevel } from "@/engine/types";
import { SEVERITY_RANK } from "@/engine/types";
import { SAMPLE_DOCUMENTS } from "@/lib/samples";
import { SEVERITY_CLASSES, cx, formatBytes } from "@/lib/format";

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

  return (
    <section
      className={cx(
        "flex min-h-0 flex-col rounded-xl border bg-surface-1 transition-colors",
        isDragging ? "border-severity-clean/60" : "border-hairline",
      )}
      onDragOver={(event) => {
        event.preventDefault();
        setIsDragging(true);
      }}
      onDragLeave={() => { setIsDragging(false); }}
      onDrop={handleDrop}
    >
      <div className="flex flex-wrap items-center gap-2 border-b border-hairline px-3 py-2">
        <FileCode2 className="h-4 w-4 shrink-0 text-content-tertiary" aria-hidden />
        <label className="sr-only" htmlFor="guardenv-filename">
          File name
        </label>
        <input
          id="guardenv-filename"
          value={filename}
          onChange={(event) => { onFilenameChange(event.target.value); }}
          spellCheck={false}
          className="min-w-0 flex-1 rounded border border-transparent bg-transparent px-1.5 py-1 font-mono text-xs text-content-primary outline-none transition-colors hover:border-hairline focus:border-hairline-strong"
        />
        <span className="font-mono text-[11px] text-content-faint">
          {lines.length} L · {formatBytes(byteSize)}
        </span>
        <div className="ml-auto flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => inputRef.current?.click()}
            className="inline-flex items-center gap-1.5 rounded-md border border-hairline bg-surface-2 px-2 py-1 text-[11px] font-medium text-content-secondary transition-colors hover:border-hairline-strong hover:text-content-primary"
          >
            <Upload className="h-3 w-3" aria-hidden />
            Upload
          </button>
          <button
            type="button"
            onClick={onClear}
            disabled={source.length === 0}
            className="inline-flex items-center gap-1.5 rounded-md border border-hairline bg-surface-2 px-2 py-1 text-[11px] font-medium text-content-secondary transition-colors hover:border-hairline-strong hover:text-content-primary disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Trash2 className="h-3 w-3" aria-hidden />
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

      <div className="flex flex-wrap items-center gap-1.5 border-b border-hairline px-3 py-2">
        <span className="mr-1 text-[10px] font-medium uppercase tracking-[0.12em] text-content-tertiary">
          Samples
        </span>
        {SAMPLE_DOCUMENTS.map((sample) => (
          <button
            key={sample.id}
            type="button"
            title={sample.description}
            onClick={() => { onLoadSample(sample.content, sample.filename); }}
            className="rounded border border-hairline bg-surface-2 px-2 py-0.5 font-mono text-[11px] text-content-secondary transition-colors hover:border-hairline-strong hover:text-content-primary"
          >
            {sample.label}
          </button>
        ))}
      </div>

      {error !== null && (
        <p className="border-b border-severity-critical/30 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical">
          {error}
        </p>
      )}

      <div className="relative flex min-h-0 flex-1">
        <div
          ref={gutterRef}
          aria-hidden
          className="select-none overflow-hidden border-r border-hairline bg-surface-2 py-3 text-right font-mono text-xs leading-[1.5rem] text-content-faint"
          // Room for the digits plus the severity dot that sits in the left margin.
          style={{ width: `${Math.max(4, String(lines.length).length + 3)}ch` }}
        >
          <div style={{ transform: `translateY(-${scrollTop}px)` }}>
            {lines.map((_, index) => {
              const lineNumber = index + 1;
              const severity = lineSeverity.get(lineNumber);
              return (
                <div
                  key={lineNumber}
                  className={cx(
                    "relative pr-2",
                    severity !== undefined && SEVERITY_CLASSES[severity].text,
                    activeLine === lineNumber && "bg-surface-4 text-content-primary",
                  )}
                >
                  {severity !== undefined && (
                    <span
                      className={cx(
                        "absolute left-1 top-1/2 h-1.5 w-1.5 -translate-y-1/2 rounded-full",
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
          className="min-h-[22rem] flex-1 resize-none overflow-x-auto whitespace-pre bg-transparent px-3 py-3 font-mono text-xs leading-[1.5rem] text-content-primary outline-none placeholder:text-content-faint"
        />

        {isDragging && (
          <div className="pointer-events-none absolute inset-0 grid place-items-center rounded-b-xl border-2 border-dashed border-severity-clean/60 bg-surface-0/80">
            <div className="flex flex-col items-center gap-2 text-severity-clean">
              <Upload className="h-6 w-6" aria-hidden />
              <span className="text-sm font-medium">Drop the file to scan it</span>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
