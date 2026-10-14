/* editorial-ui · Cristian Pérez · cristianperez.me */
import type { ReactElement } from "react";

/**
 * The brand motif: a line of text with one value redacted under an ink bar,
 * the highlighter tab at its end. Used as the logo and, larger, as a glyph.
 */
export function BrandMark({ className }: { className?: string }): ReactElement {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden focusable="false">
      <rect width="32" height="32" rx="7" className="fill-ink" />
      <rect x="7" y="9" width="10" height="2.5" rx="1.25" className="fill-surface-1" opacity="0.55" />
      <rect x="7" y="14.75" width="18" height="5" rx="1" fill="#e3f24a" />
      <rect x="7" y="22.5" width="13" height="2.5" rx="1.25" className="fill-surface-1" opacity="0.55" />
    </svg>
  );
}
