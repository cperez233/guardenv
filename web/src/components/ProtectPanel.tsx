/* editorial-ui · Cristian Pérez · cristianperez.me */
import { AnimatePresence, motion } from "framer-motion";
import { Check, ClipboardCopy, Download, ShieldPlus } from "lucide-react";
import { useMemo, useState } from "react";
import type { ReactElement } from "react";

import { GITHUB_ACTIONS_STEP, PRECOMMIT_CONFIG, envExampleFor, gitignoreFor } from "@/engine/protect";
import type { ScanFinding } from "@/engine/types";
import { useCopyToClipboard } from "@/hooks/useCopyToClipboard";
import { cx } from "@/lib/format";
import { ease, reveal, spring } from "@/lib/motion";

interface ProtectPanelProps {
  readonly source: string;
  readonly filename: string;
  readonly findings: readonly ScanFinding[];
}

type TabId = "gitignore" | "example" | "precommit" | "actions";

interface Tab {
  readonly id: TabId;
  readonly label: string;
  readonly file: string;
  readonly lead: string;
  readonly body: string | null;
  readonly empty?: string;
}

export function ProtectPanel({ source, filename, findings }: ProtectPanelProps): ReactElement {
  const [tab, setTab] = useState<TabId>("gitignore");
  const { state: copyState, copy } = useCopyToClipboard();

  const tabs = useMemo<readonly Tab[]>(
    () => [
      {
        id: "gitignore",
        label: ".gitignore",
        file: ".gitignore",
        lead: "Keep files like this one out of the repository in the first place.",
        body: gitignoreFor(filename),
      },
      {
        id: "example",
        label: ".env.example",
        file: ".env.example",
        lead: "Commit this template instead: secret values emptied, harmless defaults kept.",
        body: envExampleFor(source, findings),
        empty: "This document is not KEY=value shaped. Load the .env sample or paste a dotenv file to get a template.",
      },
      {
        id: "precommit",
        label: "pre-commit",
        file: ".pre-commit-config.yaml",
        lead: "Block the commit on your machine when a credential is staged.",
        body: PRECOMMIT_CONFIG,
      },
      {
        id: "actions",
        label: "GitHub Actions",
        file: "workflow step",
        lead: "Scan every push in CI and send the findings to the Security tab as SARIF.",
        body: GITHUB_ACTIONS_STEP,
      },
    ],
    [source, filename, findings],
  );

  const active = tabs.find((entry) => entry.id === tab) ?? tabs[0];
  if (active === undefined) throw new Error("ProtectPanel: no tabs");
  const lines = active.body?.replace(/\n$/, "").split("\n") ?? [];

  const download = (): void => {
    if (active.body === null) return;
    const url = URL.createObjectURL(new Blob([active.body], { type: "text/plain" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = active.id === "precommit" ? ".pre-commit-config.yaml" : active.file;
    link.click();
    window.setTimeout(() => { URL.revokeObjectURL(url); }, 1000);
  };

  return (
    <motion.section
      {...reveal}
      aria-label="Protect"
      className="overflow-hidden rounded-xl bg-ink text-surface-1 shadow-float"
    >
      <div className="grid gap-0 lg:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)]">
        <div className="flex flex-col gap-5 border-b border-white/10 p-5 sm:p-7 lg:border-b-0 lg:border-r">
          <div className="flex items-center gap-2.5">
            <ShieldPlus className="h-5 w-5 shrink-0 text-mark" aria-hidden />
            <h2 className="font-display text-[clamp(1.6rem,3vw,2.2rem)] font-[850] leading-[1.05] tracking-[-0.02em] [font-stretch:112%]">
              Protect
            </h2>
          </div>
          <p className="max-w-[40ch] text-[16px] leading-relaxed text-surface-1/75">
            Rotating fixes this leak. These files stop the next one, generated from the document above.
          </p>

          <div role="tablist" aria-label="Protection snippets" className="flex flex-col gap-1">
            {tabs.map((entry) => {
              const selected = entry.id === tab;
              return (
                <button
                  key={entry.id}
                  type="button"
                  role="tab"
                  aria-selected={selected}
                  onClick={() => { setTab(entry.id); }}
                  className={cx(
                    "relative flex min-h-11 items-center justify-between gap-3 rounded-md px-3.5 py-2.5 text-left transition-colors duration-200",
                    selected ? "text-ink" : "text-surface-1/70 hover:bg-white/5 hover:text-surface-1",
                  )}
                >
                  {selected && (
                    <motion.span layoutId="protect-tab" transition={spring} className="absolute inset-0 rounded-md bg-mark" />
                  )}
                  <span className="relative font-mono text-[14px] font-bold">{entry.label}</span>
                  <span className={cx("relative truncate text-[12px]", selected ? "text-ink/70" : "text-surface-1/45")}>
                    {entry.body === null ? "not applicable" : `${entry.body.trimEnd().split("\n").length} lines`}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex min-w-0 flex-col p-5 sm:p-7">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <AnimatePresence mode="wait" initial={false}>
              <motion.p
                key={active.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.2, ease }}
                className="min-w-0 flex-1 text-[15px] leading-snug text-surface-1/80"
              >
                {active.lead}
              </motion.p>
            </AnimatePresence>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                disabled={active.body === null}
                onClick={() => { if (active.body !== null) void copy(active.body); }}
                className="hit inline-flex items-center gap-1.5 rounded-md bg-mark px-3 py-1.5 text-[13px] font-semibold text-ink transition-transform duration-150 active:scale-[0.96] disabled:opacity-30"
              >
                {copyState === "copied" ? (
                  <Check className="h-3.5 w-3.5 shrink-0" aria-hidden />
                ) : (
                  <ClipboardCopy className="h-3.5 w-3.5 shrink-0" aria-hidden />
                )}
                {copyState === "copied" ? "Copied" : copyState === "error" ? "Copy failed" : "Copy"}
              </button>
              {(active.id === "gitignore" || active.id === "example" || active.id === "precommit") && (
                <button
                  type="button"
                  disabled={active.body === null}
                  onClick={download}
                  aria-label={`Download ${active.file}`}
                  className="hit inline-flex h-[30px] w-9 items-center justify-center rounded-md border border-white/20 text-surface-1 transition-[transform,border-color] duration-150 hover:border-white/50 active:scale-[0.96] disabled:opacity-30"
                >
                  <Download className="h-3.5 w-3.5 shrink-0" aria-hidden />
                </button>
              )}
            </div>
          </div>

          <div className="relative mt-4 min-h-[16rem] overflow-hidden rounded-lg bg-black/35 ring-1 ring-white/10">
            <div className="flex items-center gap-2 border-b border-white/10 px-4 py-2 font-mono text-[12px] text-surface-1/55">
              <span className="h-2 w-5 rounded-sm bg-mark" aria-hidden />
              {active.file}
            </div>
            <AnimatePresence mode="wait" initial={false}>
              <motion.pre
                key={`${active.id}-${active.body ?? ""}`}
                initial="hidden"
                animate="shown"
                exit={{ opacity: 0, transition: { duration: 0.12 } }}
                variants={{ shown: { transition: { staggerChildren: 0.025 } } }}
                className="max-h-[22rem] overflow-auto px-4 py-3 font-mono text-[13px] leading-[1.7] [overscroll-behavior:contain]"
              >
                {active.body === null ? (
                  <motion.span
                    variants={{ hidden: { opacity: 0 }, shown: { opacity: 1 } }}
                    className="block whitespace-normal font-sans text-[14px] text-surface-1/60"
                  >
                    {active.empty}
                  </motion.span>
                ) : (
                  lines.map((line, index) => {
                    const comment = line.trim().startsWith("#");
                    const emptied = /^(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=\s*$/.test(line);
                    return (
                      <motion.span
                        key={`${index}-${line}`}
                        variants={{ hidden: { opacity: 0, x: -6 }, shown: { opacity: 1, x: 0 } }}
                        transition={{ duration: 0.25, ease }}
                        className={cx(
                          "block min-h-[1.7em]",
                          comment ? "text-surface-1/45" : "text-surface-1/90",
                        )}
                      >
                        {line}
                        {emptied && (
                          <span className="ml-1 inline-block h-[0.9em] w-10 translate-y-[2px] rounded-[2px] bg-mark/80 align-baseline" aria-hidden />
                        )}
                      </motion.span>
                    );
                  })
                )}
              </motion.pre>
            </AnimatePresence>
          </div>
        </div>
      </div>
    </motion.section>
  );
}
