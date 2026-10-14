/** Small presentation helpers shared across the UI. */

import type { SeverityLevel } from "@/engine/types";

export const SEVERITY_CLASSES: Readonly<
  Record<SeverityLevel, { badge: string; text: string; dot: string; bar: string }>
> = {
  CRITICAL: {
    badge: "bg-severity-critical/10 text-severity-critical ring-severity-critical/35",
    text: "text-severity-critical",
    dot: "bg-severity-critical",
    bar: "bg-severity-critical",
  },
  HIGH: {
    badge: "bg-severity-high/10 text-severity-high ring-severity-high/35",
    text: "text-severity-high",
    dot: "bg-severity-high",
    bar: "bg-severity-high",
  },
  MEDIUM: {
    badge: "bg-severity-medium/10 text-severity-medium ring-severity-medium/35",
    text: "text-severity-medium",
    dot: "bg-severity-medium",
    bar: "bg-severity-medium",
  },
  LOW: {
    badge: "bg-severity-low/10 text-severity-low ring-severity-low/35",
    text: "text-severity-low",
    dot: "bg-severity-low",
    bar: "bg-severity-low",
  },
  INFO: {
    badge: "bg-severity-info/10 text-severity-info ring-severity-info/35",
    text: "text-severity-info",
    dot: "bg-severity-info",
    bar: "bg-severity-info",
  },
};

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Sub-millisecond scans are the common case for a pasted snippet, so show
 * enough precision that the number does not collapse to a flat "0 ms".
 */
export function formatDuration(ms: number): string {
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 1000) return `${ms.toFixed(1)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function formatEntropy(value: number | null): string {
  return value === null ? "—" : value.toFixed(2);
}

export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return count === 1 ? singular : plural;
}

/** Tailwind class merge that is good enough for the conditional cases here. */
export function cx(...values: (string | false | null | undefined)[]): string {
  return values.filter(Boolean).join(" ");
}
