import { useCallback, useEffect, useRef, useState } from "react";

export type CopyState = "idle" | "copied" | "error";

/**
 * Copy helper with a self-resetting confirmation state.
 *
 * Falls back to a hidden textarea because `navigator.clipboard` is unavailable
 * on insecure origins, which is exactly where a locally served playground runs.
 */
export function useCopyToClipboard(resetAfterMs = 1800): {
  state: CopyState;
  copy: (value: string) => Promise<void>;
} {
  const [state, setState] = useState<CopyState>("idle");
  const timer = useRef<number | undefined>(undefined);

  useEffect(
    () => () => {
      window.clearTimeout(timer.current);
    },
    [],
  );

  const copy = useCallback(
    async (value: string) => {
      const schedule = (next: CopyState): void => {
        setState(next);
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => { setState("idle"); }, resetAfterMs);
      };

      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(value);
          schedule("copied");
          return;
        }
        const area = document.createElement("textarea");
        area.value = value;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        // Deprecated, but it is the only copy path available on insecure
        // origins - which is exactly where a locally served playground runs.
        // eslint-disable-next-line @typescript-eslint/no-deprecated
        const ok = document.execCommand("copy");
        area.remove();
        schedule(ok ? "copied" : "error");
      } catch {
        schedule("error");
      }
    },
    [resetAfterMs],
  );

  return { state, copy };
}
