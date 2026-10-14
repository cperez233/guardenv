/* editorial-ui · Cristian Pérez · cristianperez.me */
import { MotionConfig, motion } from "framer-motion";
import { useCallback, useState } from "react";
import type { ReactElement } from "react";

import { EditorPanel } from "@/components/EditorPanel";
import { EntropySimulator } from "@/components/EntropySimulator";
import { Header } from "@/components/Header";
import { Hero } from "@/components/Hero";
import { InspectorPanel } from "@/components/InspectorPanel";
import type { ScanFinding } from "@/engine/types";
import { useScanner } from "@/hooks/useScanner";
import { ease } from "@/lib/motion";
import { DEFAULT_SAMPLE } from "@/lib/samples";
import { invisibleSignature } from "@/lib/signature";

const REPOSITORY_URL = "https://github.com/guardenv/guardenv";

export default function App(): ReactElement {
  const scanner = useScanner({
    initialSource: DEFAULT_SAMPLE.content,
    initialFilename: DEFAULT_SAMPLE.filename,
  });

  const [activeFinding, setActiveFinding] = useState<ScanFinding | null>(null);
  const [activeLine, setActiveLine] = useState<number | null>(null);

  const selectFinding = useCallback((finding: ScanFinding) => {
    setActiveFinding((current) => (current?.id === finding.id ? null : finding));
    setActiveLine((current) => (current === finding.line ? null : finding.line));
  }, []);

  const selectLine = useCallback((line: number) => {
    setActiveFinding(null);
    setActiveLine((current) => (current === line ? null : line));
  }, []);

  const hasInput = scanner.source.trim().length > 0;

  return (
    <MotionConfig reducedMotion="user">
      <div className="min-h-screen text-content-primary">
        <Header
          summary={scanner.summary}
          mode={scanner.mode}
          isScanning={scanner.isScanning}
          hasInput={hasInput}
          onModeChange={scanner.setMode}
          repositoryUrl={REPOSITORY_URL}
        />

        <Hero summary={scanner.summary} hasInput={hasInput} filename={scanner.filename} />

        <main className="mx-auto flex max-w-[1600px] flex-col gap-5 px-4 pb-4 sm:px-6 lg:gap-6 lg:px-10">
          <div className="grid gap-5 lg:gap-6 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)]">
            <EditorPanel
              source={scanner.source}
              filename={scanner.filename}
              findings={scanner.summary.findings}
              activeLine={activeLine}
              onSourceChange={scanner.setSource}
              onFilenameChange={scanner.setFilename}
              onLoadSample={(content, name) => {
                setActiveFinding(null);
                setActiveLine(null);
                scanner.loadSample(content, name);
              }}
              onClear={() => {
                setActiveFinding(null);
                setActiveLine(null);
                scanner.clear();
              }}
            />

            <InspectorPanel
              summary={scanner.summary}
              hasInput={hasInput}
              minSeverity={scanner.minSeverity}
              activeFindingId={activeFinding?.id ?? null}
              onMinSeverityChange={scanner.setMinSeverity}
              onSelectFinding={selectFinding}
            />
          </div>

          <EntropySimulator
            profile={scanner.summary.entropyProfile}
            threshold={scanner.threshold}
            useHeuristics={scanner.useHeuristics}
            onThresholdChange={scanner.setThreshold}
            onHeuristicsChange={scanner.setUseHeuristics}
            onSelectToken={selectLine}
          />

          <footer className="mt-6 border-t border-hairline pb-[calc(1.5rem+env(safe-area-inset-bottom))] pt-8 sm:mt-10 sm:pt-10">
            <div className="flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
              <p className="max-w-[46ch] text-[clamp(1.05rem,1.8vw,1.3rem)] font-medium leading-snug text-content-secondary">
                GuardEnv playground · every byte you paste{" "}
                <span className="relative inline-block">
                  stays in this tab
                  {/* The motif signs off: a redaction bar that settles under the promise. */}
                  <motion.span
                    aria-hidden
                    className="absolute -bottom-1 left-0 h-[5px] w-full origin-left rounded-[2px] bg-ink"
                    initial={{ scaleX: 0 }}
                    whileInView={{ scaleX: 1 }}
                    viewport={{ once: true, amount: 1 }}
                    transition={{ duration: 0.8, delay: 0.2, ease }}
                  />
                </span>
                . No upload, no telemetry.
              </p>
              <a
                href={`${REPOSITORY_URL}#quick-start`}
                target="_blank"
                rel="noreferrer noopener"
                className="group inline-flex shrink-0 items-center gap-2.5 self-start rounded-md bg-ink px-4 py-3 text-[15px] font-semibold text-surface-1 shadow-raised transition-[transform,background-color] duration-150 hover:bg-ink-soft active:scale-[0.97] md:self-auto"
              >
                Run the same engine in CI
                <span className="text-mark transition-transform duration-200 group-hover:translate-x-1" aria-hidden>
                  →
                </span>
              </a>
            </div>
            <p className="mt-10 text-[12px] text-content-faint">
              Built with care by{" "}
              <a
                href="https://cristianperez.me"
                target="_blank"
                rel="noopener"
                className="inline-block py-3 underline decoration-hairline-strong underline-offset-2 transition-colors hover:text-content-secondary hover:decoration-content-secondary"
              >
                Cristian Pérez
              </a>
              {invisibleSignature}
            </p>
          </footer>
        </main>
      </div>
    </MotionConfig>
  );
}
