import type { ReactElement } from "react";
import type { SeverityLevel } from "@/engine/types";
import { SEVERITY_CLASSES, cx } from "@/lib/format";

interface SeverityBadgeProps {
  readonly severity: SeverityLevel;
  readonly size?: "sm" | "md";
}

export function SeverityBadge({ severity, size = "md" }: SeverityBadgeProps): ReactElement {
  const classes = SEVERITY_CLASSES[severity];
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded font-mono font-semibold uppercase tracking-wider ring-1 ring-inset",
        classes.badge,
        size === "sm" ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-0.5 text-[11px]",
      )}
    >
      <span className={cx("h-1.5 w-1.5 rounded-full", classes.dot)} aria-hidden />
      {severity}
    </span>
  );
}
