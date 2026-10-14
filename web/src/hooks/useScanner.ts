/**
 * Scan state for the playground.
 *
 * The scan itself is synchronous and fast (single-digit milliseconds for a
 * typical paste), so there is no worker and no async boundary. What this hook
 * adds is debouncing while the user types, so that a 2,000-line paste does not
 * re-run the ruleset on every keystroke.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { looksLikeDiff, parseDiff } from "@/engine/diff";
import { scanDocument } from "@/engine/pipeline";
import type { AnalysisMode } from "@/engine/pipeline";
import type { ScanSummary, SeverityLevel } from "@/engine/types";

export type { AnalysisMode };

export interface ScannerState {
  readonly source: string;
  readonly filename: string;
  readonly threshold: number;
  readonly mode: AnalysisMode;
  readonly useHeuristics: boolean;
  readonly minSeverity: SeverityLevel;
  readonly decodeEncoded: boolean;
}

export interface ScannerApi extends ScannerState {
  readonly summary: ScanSummary;
  /** Files touched by the document when it is a unified diff, else null. */
  readonly diffFiles: readonly string[] | null;
  readonly isScanning: boolean;
  setSource: (value: string) => void;
  setFilename: (value: string) => void;
  setThreshold: (value: number) => void;
  setMode: (value: AnalysisMode) => void;
  setUseHeuristics: (value: boolean) => void;
  setMinSeverity: (value: SeverityLevel) => void;
  setDecodeEncoded: (value: boolean) => void;
  loadSample: (content: string, filename: string) => void;
  clear: () => void;
}

const DEBOUNCE_MS = 120;

export interface UseScannerOptions {
  readonly initialSource: string;
  readonly initialFilename: string;
  readonly initialThreshold?: number;
  readonly initialMode?: AnalysisMode;
  readonly initialMinSeverity?: SeverityLevel;
  readonly initialHeuristics?: boolean;
  readonly initialDecode?: boolean;
}

export function useScanner(options: UseScannerOptions): ScannerApi {
  const [source, setSource] = useState(options.initialSource);
  const [filename, setFilename] = useState(options.initialFilename);
  const [threshold, setThreshold] = useState(options.initialThreshold ?? 4.5);
  const [mode, setMode] = useState<AnalysisMode>(options.initialMode ?? "combined");
  const [useHeuristics, setUseHeuristics] = useState(options.initialHeuristics ?? true);
  const [minSeverity, setMinSeverity] = useState<SeverityLevel>(options.initialMinSeverity ?? "INFO");
  // Decode base64 values and scan the plaintext too (a playground-only pass).
  const [decodeEncoded, setDecodeEncoded] = useState(options.initialDecode ?? true);

  // `debounced` trails `source`; every other input applies immediately because
  // moving the slider should feel like a live control, not a delayed one.
  const [debounced, setDebounced] = useState(options.initialSource);
  const [isScanning, setIsScanning] = useState(false);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (debounced === source) return;
    setIsScanning(true);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      setDebounced(source);
      setIsScanning(false);
    }, DEBOUNCE_MS);
    return () => {
      window.clearTimeout(timer.current);
    };
  }, [source, debounced]);

  const summary = useMemo<ScanSummary>(
    () => scanDocument(debounced, filename, { threshold, mode, useHeuristics, minSeverity, decodeEncoded }),
    [debounced, filename, threshold, mode, useHeuristics, minSeverity, decodeEncoded],
  );

  const diffFiles = useMemo(
    () => (looksLikeDiff(debounced) ? parseDiff(debounced).fileNames : null),
    [debounced],
  );

  const loadSample = useCallback((content: string, name: string) => {
    window.clearTimeout(timer.current);
    setSource(content);
    setDebounced(content);
    setFilename(name);
    setIsScanning(false);
  }, []);

  const clear = useCallback(() => {
    window.clearTimeout(timer.current);
    setSource("");
    setDebounced("");
    setIsScanning(false);
  }, []);

  return {
    source,
    filename,
    threshold,
    mode,
    useHeuristics,
    minSeverity,
    decodeEncoded,
    summary,
    diffFiles,
    isScanning,
    setSource,
    setFilename,
    setThreshold,
    setMode,
    setUseHeuristics,
    setMinSeverity,
    setDecodeEncoded,
    loadSample,
    clear,
  };
}
