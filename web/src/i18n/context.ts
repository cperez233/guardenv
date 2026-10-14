/* editorial-ui · Cristian Pérez · cristianperez.me */
/**
 * English / Spanish. The first visit follows the browser's language; a choice
 * made with the switch is remembered.
 */
import { createContext, useContext } from "react";

import type { Dictionary } from "./en";

export type Lang = "en" | "es";

export const LANG_STORAGE_KEY = "guardenv-lang";

export function detectLang(): Lang {
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
