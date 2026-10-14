/* editorial-ui · Cristian Pérez · cristianperez.me */
import type { ReactNode, ReactElement } from "react";

import { cx } from "@/lib/format";

interface StatTileProps {
  readonly label: string;
  readonly value: ReactNode;
  readonly hint?: string;
  readonly accent?: string;
}

/** A big number with its caption: hairline-separated, not boxed. */
export function StatTile({ label, value, hint, accent }: StatTileProps): ReactElement {
  return (
    <div className="min-w-0 px-3 py-3 sm:px-4">
      <div className="truncate text-[13px] font-semibold text-content-tertiary">{label}</div>
      <div
        className={cx(
          "mt-1.5 font-display text-[28px] font-[800] leading-none tracking-[-0.02em] [font-stretch:105%]",
          accent ?? "text-content-primary",
        )}
      >
        {value}
      </div>
      {hint !== undefined && (
        <div className="mt-1.5 truncate text-[12px] leading-tight text-content-tertiary">{hint}</div>
      )}
    </div>
  );
}
