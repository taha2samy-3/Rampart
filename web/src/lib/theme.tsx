import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

export type ThemePreference = 'system' | 'light' | 'dark';
export const THEME_KEY = 'rampart.theme';

/** Only the theme is stored in the browser. Nothing sensitive, never a token. */
export function readStoredTheme(): ThemePreference {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return v === 'light' || v === 'dark' ? v : 'system';
  } catch {
    return 'system';
  }
}

export function writeStoredTheme(pref: ThemePreference): void {
  try {
    if (pref === 'system') localStorage.removeItem(THEME_KEY);
    else localStorage.setItem(THEME_KEY, pref);
  } catch {
    /* storage blocked: the choice lasts for this page only */
  }
}

/** `system` removes the attribute so prefers-color-scheme decides. */
export function applyTheme(pref: ThemePreference): void {
  const el = document.documentElement;
  if (pref === 'system') el.removeAttribute('data-theme');
  else el.setAttribute('data-theme', pref);
}

interface ThemeCtx {
  preference: ThemePreference;
  setPreference: (p: ThemePreference) => void;
}
const Ctx = createContext<ThemeCtx>({ preference: 'system', setPreference: () => {} });
export const useTheme = () => useContext(Ctx);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setState] = useState<ThemePreference>(readStoredTheme);
  useEffect(() => applyTheme(preference), [preference]);
  const setPreference = useCallback((p: ThemePreference) => {
    writeStoredTheme(p);
    setState(p);
  }, []);
  const value = useMemo(() => ({ preference, setPreference }), [preference, setPreference]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
