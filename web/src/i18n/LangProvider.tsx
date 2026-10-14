/* editorial-ui · Cristian Pérez · cristianperez.me */
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactElement, ReactNode } from "react";

import { LANG_STORAGE_KEY, LangContext, detectLang, langFromPath, pathForLang } from "./context";
import type { Lang } from "./context";
import { en } from "./en";
import type { Dictionary } from "./en";
import { es } from "./es";

const DICTIONARIES: Readonly<Record<Lang, Dictionary>> = { en, es };

export function LangProvider({ children }: { children: ReactNode }): ReactElement {
  const [lang, setLangState] = useState<Lang>(detectLang);

  // <html lang> follows the choice, so screen readers and hyphenation do too.
  // The URL path follows the language too (/ or /es), keeping the hash with
  // the share state, so a copied link previews in the language on screen.
  useEffect(() => {
    document.documentElement.lang = lang;
    const { pathname, search, hash } = window.location;
    const onEsPage = langFromPath(pathname) === "es";
    if ((lang === "es") !== onEsPage) {
      window.history.replaceState(window.history.state, "", `${pathForLang(lang)}${search}${hash}`);
    }
  }, [lang]);

  const setLang = useCallback((next: Lang) => {
    setLangState(next);
    try {
      localStorage.setItem(LANG_STORAGE_KEY, next);
    } catch {
      // The choice still applies for this visit.
    }
  }, []);

  const value = useMemo(() => ({ lang, t: DICTIONARIES[lang], setLang }), [lang, setLang]);
  return <LangContext.Provider value={value}>{children}</LangContext.Provider>;
}
