/**
 * Settings that travel in the URL hash, so a link reopens the same view:
 * analysis mode, threshold, severity floor, heuristics, base64 decoding and,
 * when the editor holds one of the bundled samples, which sample. Pasted text
 * is never put in the URL.
 */
import type { AnalysisMode } from "@/engine/pipeline";
import { SEVERITY_LEVELS } from "@/engine/types";
import type { SeverityLevel } from "@/engine/types";

export interface ShareState {
  readonly mode?: AnalysisMode;
  readonly threshold?: number;
  readonly minSeverity?: SeverityLevel;
  readonly heuristics?: boolean;
  readonly decode?: boolean;
  readonly sample?: string;
}

const MODES: readonly AnalysisMode[] = ["combined", "rules", "entropy"];

export function readShareState(hash: string): ShareState {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const state: { -readonly [K in keyof ShareState]: ShareState[K] } = {};
  const mode = params.get("mode");
  if (mode !== null && (MODES as readonly string[]).includes(mode)) state.mode = mode as AnalysisMode;
  const threshold = Number(params.get("t"));
  if (params.has("t") && Number.isFinite(threshold) && threshold >= 3 && threshold <= 6) state.threshold = threshold;
  const min = params.get("min");
  if (min !== null && (SEVERITY_LEVELS as readonly string[]).includes(min)) state.minSeverity = min as SeverityLevel;
  if (params.has("h")) state.heuristics = params.get("h") !== "0";
  if (params.has("b64")) state.decode = params.get("b64") !== "0";
  const sample = params.get("sample");
  if (sample !== null && /^[a-z0-9-]{1,20}$/.test(sample)) state.sample = sample;
  return state;
}

export function writeShareState(state: Required<Omit<ShareState, "sample">> & { sample: string | null }): string {
  const params = new URLSearchParams();
  if (state.sample !== null) params.set("sample", state.sample);
  if (state.mode !== "combined") params.set("mode", state.mode);
  if (Math.abs(state.threshold - 4.5) > 1e-9) params.set("t", state.threshold.toFixed(2));
  if (state.minSeverity !== "INFO") params.set("min", state.minSeverity);
  if (!state.heuristics) params.set("h", "0");
  if (!state.decode) params.set("b64", "0");
  const encoded = params.toString();
  return encoded.length === 0 ? "" : `#${encoded}`;
}
