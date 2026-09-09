import { Activity, Sigma } from "lucide-react";
import { useMemo } from "react";
import type { ReactElement } from "react";

import type { EntropyResult } from "@/engine/types";
import { cx } from "@/lib/format";

const MIN_THRESHOLD = 3.0;
const MAX_THRESHOLD = 6.0;
const STEP = 0.05;

/** Chart geometry, in the SVG's own user units. */
const VIEW = { width: 640, height: 200, padLeft: 34, padRight: 12, padTop: 12, padBottom: 26 };
const PLOT_WIDTH = VIEW.width - VIEW.padLeft - VIEW.padRight;
const PLOT_HEIGHT = VIEW.height - VIEW.padTop - VIEW.padBottom;

/** Entropy axis. 8 bits/char is the ceiling for any byte-oriented alphabet. */
const Y_MIN = 0;
const Y_MAX = 8;

const CHARSET_COLORS: Readonly<Record<string, string>> = {
  hex: "#38bdf8",
  base64: "#a78bfa",
  base64url: "#f472b6",
  alphanumeric: "#34d399",
  mixed: "#fbbf24",
};

interface EntropySimulatorProps {
  readonly profile: readonly EntropyResult[];
  readonly threshold: number;
  readonly useHeuristics: boolean;
  readonly onThresholdChange: (value: number) => void;
  readonly onHeuristicsChange: (value: boolean) => void;
  readonly onSelectToken: (line: number) => void;
}

interface PlottedPoint {
  readonly key: string;
  readonly cx: number;
  readonly cy: number;
  readonly color: string;
  readonly result: EntropyResult;
  readonly above: boolean;
  readonly suppressed: boolean;
}

function yFor(entropy: number): number {
  const clamped = Math.min(Math.max(entropy, Y_MIN), Y_MAX);
  return VIEW.padTop + PLOT_HEIGHT * (1 - (clamped - Y_MIN) / (Y_MAX - Y_MIN));
}

export function EntropySimulator({
  profile,
  threshold,
  useHeuristics,
  onThresholdChange,
  onHeuristicsChange,
  onSelectToken,
}: EntropySimulatorProps): ReactElement {
  const points = useMemo<PlottedPoint[]>(() => {
    if (profile.length === 0) return [];
    const maxIndex = Math.max(profile.length - 1, 1);
    return profile.map((result, index) => {
      // Tokens are laid out in document order along X, so a cluster in the
      // chart maps directly onto a region of the pasted file.
      const ratio = profile.length === 1 ? 0.5 : index / maxIndex;
      const above = result.entropy >= threshold;
      return {
        key: `${result.line}:${result.column}:${index}`,
        cx: VIEW.padLeft + ratio * PLOT_WIDTH,
        cy: yFor(result.entropy),
        color: CHARSET_COLORS[result.charset] ?? "#a1a1aa",
        result,
        above,
        // Above the line but rejected by a structural heuristic: the reader
        // should be able to see *why* a high-entropy token was not reported.
        suppressed: above && !result.suspicious,
      };
    });
  }, [profile, threshold]);

  const thresholdY = yFor(threshold);
  const flagged = points.filter((point) => point.result.suspicious).length;
  const suppressed = points.filter((point) => point.suppressed).length;

  return (
    <section className="rounded-xl border border-hairline bg-surface-1">
      <div className="flex flex-wrap items-center gap-3 border-b border-hairline px-3 py-2">
        <Sigma className="h-4 w-4 text-content-tertiary" aria-hidden />
        <h2 className="text-xs font-semibold uppercase tracking-[0.12em] text-content-secondary">
          Entropy simulator
        </h2>
        <span className="font-mono text-[11px] text-content-faint">
          {profile.length} tokens · {flagged} above threshold
          {suppressed > 0 && ` · ${suppressed} suppressed`}
        </span>
        <label className="ml-auto flex cursor-pointer select-none items-center gap-2 text-[11px] text-content-secondary">
          <input
            type="checkbox"
            checked={useHeuristics}
            onChange={(event) => { onHeuristicsChange(event.target.checked); }}
            className="h-3.5 w-3.5 accent-severity-clean"
          />
          Suppress benign shapes
        </label>
      </div>

      <div className="px-3 py-3">
        <div className="flex items-center gap-3">
          <label
            htmlFor="guardenv-threshold"
            className="text-[10px] font-medium uppercase tracking-[0.12em] text-content-tertiary"
          >
            Shannon threshold
          </label>
          <input
            id="guardenv-threshold"
            type="range"
            min={MIN_THRESHOLD}
            max={MAX_THRESHOLD}
            step={STEP}
            value={threshold}
            onChange={(event) => { onThresholdChange(Number(event.target.value)); }}
            className="h-1 flex-1 cursor-pointer appearance-none rounded-full bg-surface-4 accent-severity-clean"
            aria-valuetext={`${threshold.toFixed(2)} bits per character`}
          />
          <output
            htmlFor="guardenv-threshold"
            className="w-20 shrink-0 rounded border border-hairline bg-surface-2 px-2 py-0.5 text-center font-mono text-xs text-content-primary"
          >
            {threshold.toFixed(2)}
          </output>
        </div>

        <div className="mt-1 flex justify-between font-mono text-[10px] text-content-faint">
          <span>{MIN_THRESHOLD.toFixed(1)} · permissive</span>
          <span>bits / character</span>
          <span>{MAX_THRESHOLD.toFixed(1)} · strict</span>
        </div>

        <div className="mt-3 overflow-x-auto">
          <svg
            viewBox={`0 0 ${VIEW.width} ${VIEW.height}`}
            className="h-[200px] w-full min-w-[520px]"
            role="img"
            aria-label={`Entropy of ${profile.length} tokens against a threshold of ${threshold.toFixed(2)} bits per character`}
          >
            {[0, 2, 4, 6, 8].map((tick) => (
              <g key={tick}>
                <line
                  x1={VIEW.padLeft}
                  x2={VIEW.width - VIEW.padRight}
                  y1={yFor(tick)}
                  y2={yFor(tick)}
                  stroke="#27272a"
                  strokeWidth={1}
                />
                <text
                  x={VIEW.padLeft - 6}
                  y={yFor(tick) + 3}
                  textAnchor="end"
                  fill="#52525b"
                  fontSize={9}
                  fontFamily="ui-monospace, monospace"
                >
                  {tick}
                </text>
              </g>
            ))}

            <rect
              x={VIEW.padLeft}
              y={VIEW.padTop}
              width={PLOT_WIDTH}
              height={Math.max(0, thresholdY - VIEW.padTop)}
              fill="#f43f5e"
              opacity={0.06}
            />

            <line
              x1={VIEW.padLeft}
              x2={VIEW.width - VIEW.padRight}
              y1={thresholdY}
              y2={thresholdY}
              stroke="#f43f5e"
              strokeWidth={1.5}
              strokeDasharray="5 4"
            />
            <text
              x={VIEW.width - VIEW.padRight}
              y={thresholdY - 5}
              textAnchor="end"
              fill="#f43f5e"
              fontSize={9}
              fontFamily="ui-monospace, monospace"
            >
              threshold {threshold.toFixed(2)}
            </text>

            {points.map((point) => (
              <circle
                key={point.key}
                cx={point.cx}
                cy={point.cy}
                r={point.result.suspicious ? 4 : 2.5}
                fill={point.result.suspicious ? point.color : "transparent"}
                stroke={point.color}
                strokeWidth={1.2}
                strokeDasharray={point.suppressed ? "2 2" : undefined}
                opacity={point.result.suspicious ? 0.95 : 0.5}
                className="cursor-pointer transition-[r] hover:opacity-100"
                onClick={() => { onSelectToken(point.result.line); }}
              >
                <title>
                  {`line ${point.result.line} · ${point.result.charset} · ${point.result.entropy.toFixed(2)} bits/char · ${point.result.reason}`}
                </title>
              </circle>
            ))}

            <text
              x={VIEW.padLeft}
              y={VIEW.height - 8}
              fill="#52525b"
              fontSize={9}
              fontFamily="ui-monospace, monospace"
            >
              tokens in document order
            </text>
          </svg>
        </div>

        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5">
          {Object.entries(CHARSET_COLORS).map(([charset, color]) => (
            <span
              key={charset}
              className="inline-flex items-center gap-1.5 font-mono text-[10px] text-content-tertiary"
            >
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: color }}
                aria-hidden
              />
              {charset}
            </span>
          ))}
          <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-content-faint">
            <span
              className="h-2 w-2 rounded-full border border-dashed border-content-faint"
              aria-hidden
            />
            suppressed by heuristics
          </span>
        </div>

        {profile.length === 0 && (
          <p
            className={cx(
              "mt-3 flex items-center gap-2 rounded-md border border-hairline bg-surface-2",
              "px-3 py-2 text-xs text-content-tertiary",
            )}
          >
            <Activity className="h-3.5 w-3.5" aria-hidden />
            No candidate tokens yet. Paste a document with strings of 20 characters or more.
          </p>
        )}
      </div>
    </section>
  );
}
