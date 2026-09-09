import type { ReactNode, ReactElement } from "react";

import { cx } from "@/lib/format";

interface StatTileProps {
  readonly label: string;
  readonly value: ReactNode;
  readonly hint?: string;
  readonly accent?: string;
}

export function StatTile({ label, value, hint, accent }: StatTileProps): ReactElement {
  return (
    <div className="rounded-lg border border-hairline bg-surface-2 px-3 py-2.5">
      <div className="text-[10px] font-medium uppercase tracking-[0.12em] text-content-tertiary">
        {label}
      </div>
      <div className={cx("mt-1 font-mono text-lg leading-none", accent ?? "text-content-primary")}>
        {value}
      </div>
      {hint !== undefined && (
        <div className="mt-1 text-[11px] leading-tight text-content-faint">{hint}</div>
      )}
    </div>
  );
}
