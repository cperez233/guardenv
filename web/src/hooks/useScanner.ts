/**
 * Scan state for the playground.
 *
 * The scan itself is synchronous and fast (single-digit milliseconds for a
 * typical paste), so there is no worker and no async boundary. What this hook
 * adds is debouncing while the user types, so that a 2,000-line paste does not
 * re-run the ruleset on every keystroke.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { findEncodedSecrets, mergeEncoded } from "@/engine/decode";
import { scanText } from "@/engine/scanner";
import { withFindings } from "@/engine/summary";
import { EMPTY_SUMMARY, type ScanSummary, type SeverityLevel } from "@/engine/types";

export type AnalysisMode = "combined" | "rules" | "entropy";

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
}

export function useScanner(options: UseScannerOptions): ScannerApi {
  const [source, setSource] = useState(options.initialSource);
  const [filename, setFilename] = useState(options.initialFilename);
  const [threshold, setThreshold] = useState(options.initialThreshold ?? 4.5);
  const [mode, setMode] = useState<AnalysisMode>("combined");
  const [useHeuristics, setUseHeuristics] = useState(true);
  const [minSeverity, setMinSeverity] = useState<SeverityLevel>("INFO");
  // Decode base64 values and scan the plaintext too (a playground-only pass).
  const [decodeEncoded, setDecodeEncoded] = useState(true);

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

  const summary = useMemo<ScanSummary>(() => {
    if (debounced.trim().length === 0) return EMPTY_SUMMARY;
    const base = scanText(debounced, {
      path: filename,
      entropyThreshold: threshold,
      enableRules: mode !== "entropy",
      enableEntropy: mode !== "rules",
      useHeuristics,
      minSeverity,
    });
    if (!decodeEncoded || mode === "entropy") return base;
    const encoded = findEncodedSecrets(debounced, filename, minSeverity);
    return encoded.length === 0 ? base : withFindings(base, mergeEncoded(base.findings, encoded));
  }, [debounced, filename, threshold, mode, useHeuristics, minSeverity, decodeEncoded]);

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
