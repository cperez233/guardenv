/* editorial-ui · Cristian Pérez · cristianperez.me */
/**
 * Light / dark. `public/theme-init.js` sets `data-theme` before first paint;
 * this hook reads it, toggles it and remembers the choice. Without a saved
 * choice the page keeps following the system setting.
 */
import { useCallback, useEffect, useState } from "react";

export type Theme = "light" | "dark";

const STORAGE_KEY = "guardenv-theme";
const THEME_COLOR: Readonly<Record<Theme, string>> = { light: "#e6e8eb", dark: "#0e1115" };

function current(): Theme {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

function apply(theme: Theme): void {
  const root = document.documentElement;
  // One transition for every surface at once, then the classes go back to normal.
  root.classList.add("theme-switching");
  root.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", THEME_COLOR[theme]);
  window.setTimeout(() => { root.classList.remove("theme-switching"); }, 380);
}

export function useTheme(): { theme: Theme; toggle: () => void } {
  const [theme, setTheme] = useState<Theme>(current);

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const follow = (event: MediaQueryListEvent): void => {
      let saved: string | null = null;
      try {
        saved = localStorage.getItem(STORAGE_KEY);
      } catch {
        saved = null;
      }
      if (saved !== null) return;
      const next: Theme = event.matches ? "dark" : "light";
      apply(next);
      setTheme(next);
    };
    media.addEventListener("change", follow);
    return () => { media.removeEventListener("change", follow); };
  }, []);

  const toggle = useCallback(() => {
    const next: Theme = current() === "dark" ? "light" : "dark";
    apply(next);
    setTheme(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Applies for this visit only.
    }
  }, []);

  return { theme, toggle };
}
