/* editorial-ui · Cristian Pérez · cristianperez.me */
/**
 * English / Spanish. The first visit follows the browser's language; a choice
 * made with the switch is remembered.
 */
import { createContext, useContext } from "react";

import type { Dictionary } from "./en";

export type Lang = "en" | "es";

export const LANG_STORAGE_KEY = "guardenv-lang";

/** The Spanish entry page lives at /es (its own share image and metadata). */
export function langFromPath(pathname: string): Lang | null {
  return pathname === "/es" || pathname.startsWith("/es/") ? "es" : null;
}

/** The path that matches a language, so a copied link previews in that language. */
export function pathForLang(lang: Lang): string {
  return lang === "es" ? "/es" : "/";
}

export function detectLang(): Lang {
  // An explicit /es link wins over a remembered choice.
  const fromPath = langFromPath(window.location.pathname);
  if (fromPath !== null) return fromPath;
  try {
    const saved = localStorage.getItem(LANG_STORAGE_KEY);
    if (saved === "en" || saved === "es") return saved;
  } catch {
    // Storage blocked (private mode, sandboxed iframe): fall through.
  }
  const languages = navigator.languages.length > 0 ? navigator.languages : [navigator.language];
  return languages.some((code) => code.toLowerCase().startsWith("es")) ? "es" : "en";
}

export interface LangContextValue {
  readonly lang: Lang;
  readonly t: Dictionary;
  readonly setLang: (lang: Lang) => void;
}

export const LangContext = createContext<LangContextValue | null>(null);

export function useLang(): LangContextValue {
  const value = useContext(LangContext);
  if (value === null) throw new Error("useLang must be used inside <LangProvider>");
  return value;
}
