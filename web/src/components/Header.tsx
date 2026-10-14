/* editorial-ui · Cristian Pérez · cristianperez.me */
import type { ReactElement } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Check, Link2, Moon, Radar, ShieldAlert, ShieldCheck, Sun } from "lucide-react";

import type { ScanSummary } from "@/engine/types";
import type { AnalysisMode } from "@/hooks/useScanner";
import { useCopyToClipboard } from "@/hooks/useCopyToClipboard";
import { useTheme } from "@/hooks/useTheme";
import { useLang } from "@/i18n/context";
import type { Lang } from "@/i18n/context";
import { cx } from "@/lib/format";
import { ease, softSpring, spring } from "@/lib/motion";
import { BrandMark } from "./BrandMark";

const MODE_IDS: readonly AnalysisMode[] = ["combined", "rules", "entropy"];
const LANGS: readonly Lang[] = ["en", "es"];

/**
 * Inline GitHub mark. lucide-react has deprecated its brand icons, so the glyph
 * lives here rather than pinning a dependency that is scheduled for removal.
 */
function GithubMark({ className }: { className?: string }): ReactElement {
  return (
    <svg viewBox="0 0 16 16" fill="currentColor" className={className} aria-hidden focusable="false">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}

interface HeaderProps {
  readonly summary: ScanSummary;
  readonly mode: AnalysisMode;
  readonly isScanning: boolean;
  readonly hasInput: boolean;
  readonly onModeChange: (mode: AnalysisMode) => void;
  readonly repositoryUrl: string;
}

function StatusPill({
  summary,
  isScanning,
  hasInput,
}: Pick<HeaderProps, "summary" | "isScanning" | "hasInput">): ReactElement {
  const { t } = useLang();
  const clean = summary.totalFindings === 0;
  const key = isScanning ? "scanning" : !hasInput ? "idle" : clean ? "clean" : `findings-${summary.totalFindings}`;

  let body: ReactElement;
  if (isScanning) {
    body = (
      <span className="inline-flex items-center gap-2 rounded-md border border-hairline bg-surface-1 px-2.5 py-1 text-[13px] text-content-secondary">
        <Radar className="h-3.5 w-3.5 shrink-0 animate-spin text-content-tertiary" aria-hidden />
        {t.header.analysing}
      </span>
    );
  } else if (!hasInput) {
    body = (
      <span className="inline-flex items-center gap-2 rounded-md border border-hairline bg-surface-1 px-2.5 py-1 text-[13px] text-content-tertiary">
        <span className="h-1.5 w-3 shrink-0 rounded-sm bg-content-faint" aria-hidden />
        {t.header.idle}
      </span>
    );
  } else {
    body = (
      <span
        className={cx(
          "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md px-2 py-1 text-[13px] font-semibold sm:gap-2 sm:px-2.5",
          clean ? "bg-severity-clean text-white dark:text-on-mark" : "bg-ink text-surface-1",
        )}
      >
        {clean ? (
          <ShieldCheck className="h-3.5 w-3.5 shrink-0" aria-hidden />
        ) : (
          <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-ink-accent" aria-hidden />
        )}
        <span className="max-[379px]:sr-only">
          {clean ? t.header.clean : t.header.findings(summary.totalFindings)}
        </span>
        {!clean && (
          <span aria-hidden className="tabular-nums min-[380px]:hidden">
            {summary.totalFindings}
          </span>
        )}
      </span>
    );
  }

  return (
    <span className="relative inline-flex" aria-live="polite">
      <AnimatePresence mode="popLayout" initial={false}>
        <motion.span
          key={key}
          initial={{ opacity: 0, y: 6, scale: 0.96 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -6, scale: 0.96 }}
          transition={{ duration: 0.22, ease }}
          className="inline-flex"
        >
          {body}
        </motion.span>
      </AnimatePresence>
    </span>
  );
}

const iconButton =
  "hit relative inline-flex h-9 w-8 shrink-0 sm:w-9 items-center justify-center rounded-md border border-hairline bg-surface-1 text-content-secondary transition-[color,border-color,transform] duration-200 hover:border-hairline-strong hover:text-content-primary active:scale-[0.94]";

function ThemeToggle(): ReactElement {
  const { t } = useLang();
  const { theme, toggle } = useTheme();
  const dark = theme === "dark";
  return (
    <button type="button" onClick={toggle} aria-label={dark ? t.header.toLight : t.header.toDark} title={dark ? t.header.toLight : t.header.toDark} className={iconButton}>
      <AnimatePresence mode="popLayout" initial={false}>
        <motion.span
          key={theme}
          initial={{ rotate: -90, scale: 0.5, opacity: 0 }}
          animate={{ rotate: 0, scale: 1, opacity: 1 }}
          exit={{ rotate: 90, scale: 0.5, opacity: 0 }}
          transition={softSpring}
          className="inline-flex"
        >
          {dark ? <Sun className="h-4 w-4 shrink-0" aria-hidden /> : <Moon className="h-4 w-4 shrink-0" aria-hidden />}
        </motion.span>
      </AnimatePresence>
    </button>
  );
}

function LangSwitch(): ReactElement {
  const { lang, setLang, t } = useLang();
  return (
    <div role="radiogroup" aria-label={t.header.language} className="flex h-9 shrink-0 rounded-md border border-hairline bg-surface-2 p-0.5">
      {LANGS.map((code) => {
        const selected = lang === code;
        return (
          <button
            key={code}
            type="button"
            role="radio"
            aria-checked={selected}
            lang={code}
            aria-label={code === "en" ? "English" : "Español"}
            onClick={() => { setLang(code); }}
            className={cx(
              "relative w-7 rounded-[5px] font-mono sm:w-9 text-[12px] font-bold uppercase transition-colors",
              selected ? "text-surface-1" : "text-content-tertiary hover:text-content-primary",
            )}
          >
            {selected && <motion.span layoutId="lang-pill" transition={spring} className="absolute inset-0 rounded-[5px] bg-ink" />}
            <span className="relative">{code}</span>
          </button>
        );
      })}
    </div>
  );
}

function ShareButton(): ReactElement {
  const { t } = useLang();
  const { state, copy } = useCopyToClipboard();
  const copied = state === "copied";
  return (
    <button
      type="button"
      onClick={() => void copy(window.location.href)}
      title={t.header.shareTitle}
      aria-label={copied ? t.header.shareCopied : t.header.share}
      className={cx(iconButton, "lg:w-auto lg:gap-2 lg:px-3")}
    >
      {copied ? <Check className="h-4 w-4 shrink-0 text-severity-clean" aria-hidden /> : <Link2 className="h-4 w-4 shrink-0" aria-hidden />}
      <span className="hidden text-[13px] font-medium lg:inline">{copied ? t.header.shareCopied : t.header.share}</span>
    </button>
  );
}

export function Header({
  summary,
  mode,
  isScanning,
  hasInput,
  onModeChange,
  repositoryUrl,
}: HeaderProps): ReactElement {
  const { t } = useLang();
  return (
    <motion.header
      initial={{ y: -12, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6, ease }}
      className="sticky top-0 z-30 border-b border-hairline bg-surface-0/[0.98] shadow-rest"
    >
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-2 gap-y-2.5 px-4 sm:gap-x-3 py-2.5 sm:px-6 lg:gap-x-4 lg:px-10">
        <a
          href="#top"
          onClick={(event) => {
            // Scroll without writing #top into the URL, which carries the share state.
            event.preventDefault();
            window.scrollTo({ top: 0, behavior: "smooth" });
          }}
          className="group flex min-h-11 items-center gap-2.5"
          aria-label={t.header.home}
        >
          <BrandMark className="h-8 w-8 shrink-0 transition-transform duration-300 group-hover:-rotate-6" />
          <span className="hidden font-display text-[17px] font-[800] tracking-[-0.01em] [font-stretch:115%] min-[420px]:inline">
            GuardEnv
          </span>
        </a>

        <StatusPill summary={summary} isScanning={isScanning} hasInput={hasInput} />

        <div className="ml-auto flex items-center gap-1 sm:gap-1.5 md:order-last md:ml-0">
          <ShareButton />
          <LangSwitch />
          <ThemeToggle />
          <a
            href={repositoryUrl}
            target="_blank"
            rel="noreferrer noopener"
            aria-label={t.header.repository}
            title={t.header.repository}
            className={cx(iconButton, "xl:w-auto xl:gap-2 xl:px-3")}
          >
            <GithubMark className="h-4 w-4 shrink-0" />
            <span className="hidden text-[13px] font-medium xl:inline">{t.header.repository}</span>
          </a>
        </div>

        <div
          role="radiogroup"
          aria-label={t.header.modeGroup}
          className="flex w-full rounded-lg border border-hairline bg-surface-2 p-0.5 md:ml-auto md:w-auto"
        >
          {MODE_IDS.map((id) => {
            const selected = mode === id;
            const [label, hint] = t.header.modes[id];
            return (
              <motion.button
                key={id}
                type="button"
                role="radio"
                aria-checked={selected}
                title={hint}
                onClick={() => { onModeChange(id); }}
                whileTap={{ scale: 0.96 }}
                transition={softSpring}
                className={cx(
                  "relative h-10 flex-1 whitespace-nowrap rounded-md px-3 text-[13px] font-semibold transition-colors md:h-8 md:flex-none",
                  selected ? "text-surface-1" : "text-content-tertiary hover:text-content-primary",
                )}
              >
                {selected && (
                  <motion.span
                    layoutId="mode-pill"
                    transition={spring}
                    className="absolute inset-0 rounded-md bg-ink shadow-raised"
                  />
                )}
                <span className="relative">{label}</span>
              </motion.button>
            );
          })}
        </div>
      </div>
    </motion.header>
  );
}
