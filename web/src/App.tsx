import { useCallback, useState } from "react";
import type { ReactElement } from "react";

import { EditorPanel } from "@/components/EditorPanel";
import { EntropySimulator } from "@/components/EntropySimulator";
import { Header } from "@/components/Header";
import { InspectorPanel } from "@/components/InspectorPanel";
import type { ScanFinding } from "@/engine/types";
import { useScanner } from "@/hooks/useScanner";
import { DEFAULT_SAMPLE } from "@/lib/samples";

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
    <div className="min-h-screen bg-surface-0 text-content-primary">
      <Header
        summary={scanner.summary}
        mode={scanner.mode}
        isScanning={scanner.isScanning}
        hasInput={hasInput}
        onModeChange={scanner.setMode}
        repositoryUrl={REPOSITORY_URL}
      />

      <main className="mx-auto flex max-w-[1600px] flex-col gap-4 px-4 py-4 sm:px-6">
        <div className="grid gap-4 xl:grid-cols-2">
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

        <footer className="flex flex-wrap items-center gap-x-4 gap-y-2 pb-6 pt-2 text-[11px] text-content-faint">
          <span>
            GuardEnv playground · every byte you paste stays in this tab. No upload, no telemetry.
          </span>
          <a
            href={`${REPOSITORY_URL}#quick-start`}
            target="_blank"
            rel="noreferrer noopener"
            className="underline decoration-hairline-strong underline-offset-2 transition-colors hover:text-content-secondary"
          >
            Run the same engine in CI
          </a>
        </footer>
      </main>
    </div>
  );
}
