/**
 * The playground's full scan: signatures and entropy (the shared engine), then
 * the playground-side passes: base64 decoding and unified-diff mapping.
 * Used by the editor and by the folder scan, so both report the same thing.
 */

import { findEncodedSecrets, mergeEncoded } from "./decode";
import { looksLikeDiff, mapDiffFindings, parseDiff } from "./diff";
import { scanText } from "./scanner";
import { withFindings } from "./summary";
import { EMPTY_SUMMARY } from "./types";
import type { ScanSummary, SeverityLevel } from "./types";

export type AnalysisMode = "combined" | "rules" | "entropy";

export interface PipelineSettings {
  readonly threshold: number;
  readonly mode: AnalysisMode;
  readonly useHeuristics: boolean;
  readonly minSeverity: SeverityLevel;
  readonly decodeEncoded: boolean;
}

export function scanDocument(text: string, path: string, settings: PipelineSettings): ScanSummary {
  if (text.trim().length === 0) return EMPTY_SUMMARY;
  // A unified diff is scanned with its markers stripped, then mapped back.
  const diff = looksLikeDiff(text) ? parseDiff(text) : null;
  const body = diff?.stripped ?? text;
  const scanned = scanText(body, {
    path,
    entropyThreshold: settings.threshold,
    enableRules: settings.mode !== "entropy",
    enableEntropy: settings.mode !== "rules",
    useHeuristics: settings.useHeuristics,
    minSeverity: settings.minSeverity,
  });
  const encoded =
    !settings.decodeEncoded || settings.mode === "entropy" ? [] : findEncodedSecrets(body, path, settings.minSeverity);
  const merged = encoded.length === 0 ? scanned.findings : mergeEncoded(scanned.findings, encoded);
  const findings = diff === null ? merged : mapDiffFindings(merged, diff, path);
  if (diff === null && encoded.length === 0) return scanned;
  return withFindings({ ...scanned, linesScanned: text.split("\n").length }, findings);
}
