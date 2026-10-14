/* editorial-ui · Cristian Pérez · cristianperez.me */
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useCallback, useRef, useState } from "react";
import type { ReactElement } from "react";

import { SEVERITY_LEVELS } from "@/engine/types";
import type { ScanSummary } from "@/engine/types";
import { SEVERITY_CLASSES, cx, pluralize } from "@/lib/format";
import { ease } from "@/lib/motion";
import { RollingNumber } from "./Numbers";

interface HeroProps {
  readonly summary: ScanSummary;
  readonly hasInput: boolean;
  readonly filename: string;
}

const LETTERS_A = "Guard".split("");
const LETTERS_B = "Env".split("");

/**
 * The wordmark acts out what the tool does: "Env" is struck through by an ink
 * redaction bar, which lifts away and leaves the auditor's highlighter behind.
 * Hovering the word replays it (a key bump, so the animation restarts cleanly).
 */
function Wordmark(): ReactElement {
  const reduce = useReducedMotion() ?? false;
  const [take, setTake] = useState(0);
  const lastReplay = useRef(0);

  const replay = useCallback(() => {
    if (reduce || !window.matchMedia("(hover: hover)").matches) return;
    const now = performance.now();
    if (now - lastReplay.current < 2200) return;
    lastReplay.current = now;
    setTake((value) => value + 1);
  }, [reduce]);

  const first = take === 0;
  const base = first ? 0.35 : 0;

  return (
    <h1
      onMouseEnter={replay}
      className="font-display text-[clamp(3.4rem,15vw,8rem)] lg:text-[min(9vw,9.5rem)] font-[900] leading-[0.92] tracking-[-0.035em] [font-stretch:118%]"
    >
      <span className="sr-only">GuardEnv</span>
      <span aria-hidden className="inline-flex items-end">
        {LETTERS_A.map((letter, index) => (
          <span key={`a-${index}`} className="inline-block overflow-hidden pb-[0.06em]">
            <motion.span
              className="inline-block"
              initial={reduce ? false : { y: "105%" }}
              animate={{ y: "0%" }}
              transition={{ duration: 0.9, delay: 0.05 + index * 0.045, ease }}
            >
              {letter}
            </motion.span>
          </span>
        ))}
        <span className="relative inline-flex pb-[0.06em]">
          {/* Highlighter stroke, drawn once the bar has lifted. */}
          <motion.span
            key={`mark-${take}`}
            aria-hidden
            className="absolute inset-x-[-0.04em] bottom-[0.1em] top-[0.4em] -z-0 rounded-[0.06em] bg-mark"
            initial={reduce ? false : { clipPath: "inset(0 100% 0 0)" }}
            animate={{ clipPath: "inset(0 0% 0 0)" }}
            transition={{ duration: 0.55, delay: base + 1.15, ease }}
          />
          {LETTERS_B.map((letter, index) => (
            <span key={`b-${index}`} className="relative inline-block overflow-hidden">
              <motion.span
                className="inline-block"
                initial={reduce ? false : { y: "105%" }}
                animate={{ y: "0%" }}
                transition={{ duration: 0.9, delay: 0.05 + (LETTERS_A.length + index) * 0.045, ease }}
              >
                {letter}
              </motion.span>
            </span>
          ))}
          {/* The redaction bar: sweeps on, holds, lifts off to the right. */}
          {!reduce && (
            <motion.span
              key={`bar-${take}`}
              aria-hidden
              className="absolute inset-x-[-0.06em] bottom-[0.1em] top-[0.18em] rounded-[0.05em] bg-ink"
              initial={{ clipPath: "inset(0 100% 0 0)" }}
              animate={{
                clipPath: ["inset(0 100% 0 0)", "inset(0 0% 0 0)", "inset(0 0% 0 0)", "inset(0 0% 0 100%)"],
              }}
              transition={{ duration: 1.35, delay: base, times: [0, 0.32, 0.62, 1], ease }}
            />
          )}
        </span>
      </span>
    </h1>
  );
}

function Verdict({ summary, hasInput, filename }: HeroProps): ReactElement {
  const total = summary.totalFindings;
  const clean = hasInput && total === 0;

  return (
    <motion.aside
      aria-live="polite"
      aria-label="Scan verdict"
      initial={{ opacity: 0, y: 24, rotate: 0.6 }}
      animate={{ opacity: 1, y: 0, rotate: 0 }}
      transition={{ duration: 0.9, delay: 0.5, ease }}
      className="relative w-full rounded-xl bg-surface-1 p-5 shadow-float ring-1 ring-hairline sm:p-6 lg:w-[400px]"
    >
      <div className="flex items-baseline justify-between gap-3">
        <span className="truncate font-mono text-[13px] text-content-tertiary">{filename || "untitled"}</span>
        <span className="shrink-0 font-mono text-[13px] text-content-tertiary">
          {summary.linesScanned} {pluralize(summary.linesScanned, "line")}
        </span>
      </div>

      <div className="mt-3 flex items-end gap-3">
        <span
          className={cx(
            "font-display text-[clamp(4rem,14vw,5.5rem)] font-[850] leading-[0.85] tracking-[-0.04em] [font-stretch:110%]",
            !hasInput ? "text-content-faint" : clean ? "text-severity-clean" : "text-content-primary",
          )}
        >
          {hasInput ? <RollingNumber value={total} /> : "—"}
        </span>
        <AnimatePresence mode="popLayout" initial={false}>
          {clean ? (
            /* A clean document earns the auditor's stamp. */
            <motion.span
              key="stamp"
              initial={{ scale: 1.8, rotate: -18, opacity: 0 }}
              animate={{ scale: 1, rotate: -6, opacity: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              transition={{ type: "spring", stiffness: 520, damping: 22 }}
              className="mb-2 rounded-[4px] border-[3px] border-severity-clean px-2.5 py-0.5 font-display text-[22px] font-[900] uppercase leading-tight tracking-[0.06em] text-severity-clean [font-stretch:115%]"
            >
              Clean
            </motion.span>
          ) : (
            <motion.span
              key={hasInput ? "findings" : "idle"}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.2, ease }}
              className="pb-1.5 text-[17px] font-semibold leading-tight text-content-secondary"
            >
              {!hasInput ? "Idle" : pluralize(total, "finding")}
            </motion.span>
          )}
        </AnimatePresence>
      </div>

      {/* Severity strip: one segment per level, sized by its count. */}
      <div className="mt-5 flex h-3 w-full gap-[3px] overflow-hidden rounded-[3px] bg-surface-3" aria-hidden>
        {SEVERITY_LEVELS.map((level) => (
          <motion.span
            key={level}
            className={cx("h-full min-w-0 rounded-[2px]", SEVERITY_CLASSES[level].bar)}
            initial={false}
            animate={{ flexGrow: summary.countsBySeverity[level], opacity: summary.countsBySeverity[level] > 0 ? 1 : 0 }}
            style={{ flexBasis: 0 }}
            transition={{ duration: 0.5, ease }}
          />
        ))}
      </div>

      <dl className="mt-4 grid grid-cols-5 gap-1.5 sm:gap-2">
        {SEVERITY_LEVELS.map((level) => {
          const count = summary.countsBySeverity[level];
          return (
            <div key={level} className={cx("min-w-0", count === 0 && "opacity-50")}>
              <dt className="flex items-center gap-1.5 truncate text-[12px] font-semibold capitalize text-content-tertiary">
                <span className={cx("hidden h-2 w-2 shrink-0 rounded-[2px] min-[400px]:block", SEVERITY_CLASSES[level].dot)} aria-hidden />
                {level.toLowerCase()}
              </dt>
              <dd className={cx("mt-0.5 font-mono text-[18px] font-bold", count > 0 && SEVERITY_CLASSES[level].text)}>
                <RollingNumber value={count} />
              </dd>
            </div>
          );
        })}
      </dl>
    </motion.aside>
  );
}

export function Hero({ summary, hasInput, filename }: HeroProps): ReactElement {
  return (
    <section
      id="top"
      className="relative mx-auto flex max-w-[1600px] scroll-mt-24 flex-col gap-8 px-4 pb-8 pt-10 sm:px-6 sm:pt-14 lg:flex-row lg:items-end lg:justify-between lg:gap-12 lg:px-10 lg:pb-12 lg:pt-20"
    >
      <div className="min-w-0">
        <Wordmark />
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.7, ease }}
          className="mt-4 max-w-[46ch] text-[clamp(1.1rem,2.2vw,1.45rem)] font-medium leading-snug text-content-secondary sm:mt-5"
        >
          Secret scanner playground · <span className="marker text-content-primary">runs entirely in your browser</span>
        </motion.p>
      </div>
      <Verdict summary={summary} hasInput={hasInput} filename={filename} />
    </section>
  );
}
