/* editorial-ui · Cristian Pérez · cristianperez.me */
import { motion } from "framer-motion";
import { Activity, Sigma } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactElement, RefObject } from "react";

import type { EntropyResult } from "@/engine/types";
import { useLang } from "@/i18n/context";
import { cx } from "@/lib/format";
import { ease, reveal } from "@/lib/motion";
import { RollingNumber } from "./Numbers";

const MIN_THRESHOLD = 3.0;
const MAX_THRESHOLD = 6.0;
const STEP = 0.05;

/** Chart geometry, in the SVG's own user units. Width follows the container. */
/** The right gutter holds the threshold chip, so it never covers a point. */
const VIEW = { height: 240, padLeft: 34, padRight: 56, padTop: 16, padBottom: 28 };
const MIN_WIDTH = 300;
const PLOT_HEIGHT = VIEW.height - VIEW.padTop - VIEW.padBottom;

/** Entropy axis. 8 bits/char is the ceiling for any byte-oriented alphabet. */
const Y_MIN = 0;
const Y_MAX = 8;

/** Charset hues come from the theme (src/index.css), so they hold up on both sheets. */
const CHARSET_COLORS: Readonly<Record<string, string>> = {
  hex: "rgb(var(--c-cs-hex))",
  base64: "rgb(var(--c-cs-base64))",
  base64url: "rgb(var(--c-cs-base64url))",
  alphanumeric: "rgb(var(--c-cs-alphanumeric))",
  mixed: "rgb(var(--c-cs-mixed))",
};

const INK = "rgb(var(--c-ink))";
const MARK = "#e3f24a";

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

/** Width of an element, kept current with a ResizeObserver. */
function useWidth<T extends HTMLElement>(fallback: number): [RefObject<T>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(fallback);
  useEffect(() => {
    const node = ref.current;
    if (node === null) return;
    const observer = new ResizeObserver(([entry]) => {
      if (entry !== undefined) setWidth(Math.round(entry.contentRect.width));
    });
    observer.observe(node);
    return () => { observer.disconnect(); };
  }, []);
  return [ref, width];
}

export function EntropySimulator({
  profile,
  threshold,
  useHeuristics,
  onThresholdChange,
  onHeuristicsChange,
  onSelectToken,
}: EntropySimulatorProps): ReactElement {
  const { t } = useLang();
  const [frameRef, frameWidth] = useWidth<HTMLDivElement>(900);
  const width = Math.max(MIN_WIDTH, frameWidth);
  const plotWidth = width - VIEW.padLeft - VIEW.padRight;

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
        cx: VIEW.padLeft + ratio * plotWidth,
        cy: yFor(result.entropy),
        color: CHARSET_COLORS[result.charset] ?? "rgb(var(--c-sev-info))",
        result,
        above,
        // Above the line but rejected by a structural heuristic: the reader
        // should be able to see *why* a high-entropy token was not reported.
        suppressed: above && !result.suspicious,
      };
    });
  }, [profile, threshold, plotWidth]);

  const thresholdY = yFor(threshold);
  const flagged = points.filter((point) => point.result.suspicious).length;
  const suppressed = points.filter((point) => point.suppressed).length;
  const fill = ((threshold - MIN_THRESHOLD) / (MAX_THRESHOLD - MIN_THRESHOLD)) * 100;

  return (
    <motion.section
      {...reveal}
      aria-label={t.entropy.title}
      className="overflow-hidden rounded-xl bg-surface-1 shadow-raised ring-1 ring-hairline"
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-hairline px-4 py-3 sm:px-5">
        <Sigma className="h-4 w-4 shrink-0 text-content-tertiary" aria-hidden />
        <h2 className="font-display text-[17px] font-[750] tracking-[-0.01em] [font-stretch:110%]">
          {t.entropy.title}
        </h2>
        <span className="font-mono text-[12px] text-content-tertiary">
          {t.entropy.summary(profile.length)}
          <RollingNumber value={flagged} className="align-bottom" /> {t.entropy.above}
          {suppressed > 0 && t.entropy.suppressed(suppressed)}
        </span>
        <label className="group flex w-full cursor-pointer sm:ml-auto sm:w-auto select-none items-center gap-2.5 py-1 text-[14px] font-medium text-content-secondary">
          <input
            type="checkbox"
            checked={useHeuristics}
            onChange={(event) => { onHeuristicsChange(event.target.checked); }}
            className="peer sr-only"
          />
          <span
            aria-hidden
            className={cx(
              "relative h-6 w-10 shrink-0 rounded-full transition-colors duration-200 peer-focus-visible:ring-2 peer-focus-visible:ring-ink peer-focus-visible:ring-offset-2",
              useHeuristics ? "bg-ink" : "bg-surface-4",
            )}
          >
            <motion.span
              initial={false}
              animate={{ x: useHeuristics ? 18 : 2 }}
              transition={{ type: "spring", stiffness: 600, damping: 34 }}
              className={cx(
                "absolute top-[3px] h-[18px] w-[18px] rounded-full shadow-rest",
                useHeuristics ? "bg-mark" : "bg-surface-1",
              )}
            />
          </span>
          {t.entropy.heuristics}
        </label>
      </div>

      <div className="px-4 py-4 sm:px-5 sm:py-5">
        <div className="flex items-center gap-3 sm:gap-5">
          <label
            htmlFor="guardenv-threshold"
            className="sr-only text-[13px] font-semibold text-content-secondary sm:not-sr-only sm:shrink-0"
          >
            {t.entropy.threshold}
          </label>
          <input
            id="guardenv-threshold"
            type="range"
            min={MIN_THRESHOLD}
            max={MAX_THRESHOLD}
            step={STEP}
            value={threshold}
            onChange={(event) => { onThresholdChange(Number(event.target.value)); }}
            className="ruler min-w-0 flex-1 cursor-pointer"
            style={{ ["--fill" as string]: `${fill}%` }}
            aria-valuetext={t.entropy.valueText(threshold.toFixed(2))}
          />
          <output
            htmlFor="guardenv-threshold"
            className="w-[4.5rem] shrink-0 rounded-md bg-ink px-2 py-1 text-center font-mono text-[15px] font-bold tabular-nums text-ink-accent"
          >
            {threshold.toFixed(2)}
          </output>
        </div>

        <div className="mt-1.5 flex justify-between gap-2 whitespace-nowrap font-mono text-[12px] text-content-tertiary">
          <span>{MIN_THRESHOLD.toFixed(1)} · {t.entropy.permissive}</span>
          <span className="hidden sm:inline">{t.entropy.unit}</span>
          <span>{MAX_THRESHOLD.toFixed(1)} · {t.entropy.strict}</span>
        </div>

        <div ref={frameRef} className="mt-4 overflow-x-auto [overscroll-behavior-x:contain]">
          <svg
            viewBox={`0 0 ${width} ${VIEW.height}`}
            width={width}
            height={VIEW.height}
            className="block"
            role="img"
            aria-label={t.entropy.chartLabel(profile.length, threshold.toFixed(2))}
          >
            {/* The band above the threshold is the highlighter: what lands there is evidence. */}
            <motion.rect
              x={VIEW.padLeft}
              y={VIEW.padTop}
              width={plotWidth}
              initial={false}
              animate={{ height: Math.max(0, thresholdY - VIEW.padTop) }}
              transition={{ type: "spring", stiffness: 500, damping: 40 }}
              fill={MARK}
              style={{ opacity: "calc(var(--mark-line) * 0.7)" }}
              rx={3}
            />

            {[0, 2, 4, 6, 8].map((tick) => (
              <g key={tick}>
                <line
                  x1={VIEW.padLeft}
                  x2={width - VIEW.padRight}
                  y1={yFor(tick)}
                  y2={yFor(tick)}
                  className="stroke-hairline"
                  strokeWidth={1}
                />
                <text
                  x={VIEW.padLeft - 8}
                  y={yFor(tick) + 4}
                  textAnchor="end"
                  className="fill-content-tertiary"
                  fontSize={11}
                  fontFamily="'JetBrains Mono', ui-monospace, monospace"
                >
                  {tick}
                </text>
              </g>
            ))}


            {points.map((point, index) => {
              const hot = point.result.suspicious;
              return (
                <motion.circle
                  key={point.key}
                  cx={point.cx}
                  cy={point.cy}
                  initial={{ r: 0, opacity: 0 }}
                  animate={{ r: hot ? 6 : 4, opacity: hot ? 1 : 0.75 }}
                  transition={{ duration: 0.45, delay: Math.min(index * 0.03, 0.6), ease }}
                  style={{ fill: hot ? point.color : "rgb(var(--c-surface-1))", stroke: hot ? INK : point.color }}
                  strokeWidth={hot ? 1.5 : 1.6}
                  strokeDasharray={point.suppressed ? "2 2" : undefined}
                  className="cursor-pointer outline-none transition-[stroke-width] duration-150 hover:[stroke-width:3px]"
                  onClick={() => { onSelectToken(point.result.line); }}
                >
                  <title>
                    {t.entropy.point(point.result.line, point.result.charset, point.result.entropy.toFixed(2), point.result.reason)}
                  </title>
                </motion.circle>
              );
            })}

            <motion.g
              initial={false}
              animate={{ y: thresholdY }}
              transition={{ type: "spring", stiffness: 500, damping: 40 }}
            >
              <line
                x1={VIEW.padLeft}
                x2={width - VIEW.padRight}
                y1={0}
                y2={0}
                style={{ stroke: INK }}
                strokeWidth={1.5}
                strokeDasharray="6 4"
              />
              <line
                x1={width - VIEW.padRight}
                x2={width - 48}
                y1={0}
                y2={0}
                style={{ stroke: INK }}
                strokeWidth={1.5}
              />
              <rect x={width - 48} y={-9} width={46} height={18} rx={3} style={{ fill: INK }}>
                <title>{`${t.entropy.thresholdTag} ${threshold.toFixed(2)}`}</title>
              </rect>
              <text
                x={width - 25}
                y={4}
                textAnchor="middle"
                fill={MARK}
                style={{ fill: "rgb(var(--c-ink-accent))" }}
                fontSize={11}
                fontWeight={700}
                fontFamily="'JetBrains Mono', ui-monospace, monospace"
              >
                {threshold.toFixed(2)}
              </text>
            </motion.g>

            <text
              x={VIEW.padLeft}
              y={VIEW.height - 8}
              className="fill-content-tertiary"
              fontSize={11}
              fontFamily="'JetBrains Mono', ui-monospace, monospace"
            >
              {t.entropy.axis}
            </text>
          </svg>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2">
          {Object.entries(CHARSET_COLORS).map(([charset, color]) => (
            <span
              key={charset}
              className="inline-flex items-center gap-1.5 font-mono text-[12px] text-content-secondary"
            >
              <span
                className="h-2.5 w-2.5 shrink-0 rounded-full ring-1 ring-ink/70"
                style={{ backgroundColor: color }}
                aria-hidden
              />
              {charset}
            </span>
          ))}
          <span className="inline-flex items-center gap-1.5 font-mono text-[12px] text-content-secondary">
            <span className="h-0 w-4 shrink-0 border-t-[1.5px] border-dashed border-ink" aria-hidden />
            {t.entropy.thresholdTag}
          </span>
          <span className="inline-flex items-center gap-1.5 font-mono text-[12px] text-content-tertiary">
            <span
              className="h-2.5 w-2.5 shrink-0 rounded-full border border-dashed border-content-tertiary"
              aria-hidden
            />
            {t.entropy.suppressedLegend}
          </span>
        </div>

        {profile.length === 0 && (
          <p
            className={cx(
              "mt-4 flex items-center gap-2 rounded-md bg-surface-2 ring-1 ring-inset ring-hairline",
              "px-3 py-2.5 text-[14px] text-content-tertiary",
            )}
          >
            <Activity className="h-4 w-4 shrink-0" aria-hidden />
            {t.entropy.empty}
          </p>
        )}
      </div>
    </motion.section>
  );
}
