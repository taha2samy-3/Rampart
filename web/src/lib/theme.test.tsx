import { act, render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { THEME_KEY, ThemeProvider, readStoredTheme, useTheme } from './theme';

function Probe() {
  const { preference, setPreference } = useTheme();
  return <button onClick={() => setPreference('dark')}>{preference}</button>;
}

describe('theme persistence', () => {
  it('defaults to system and leaves the attribute off', () => {
    render(<ThemeProvider><Probe /></ThemeProvider>);
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false);
  });
  it('stores only the theme and applies it', () => {
    const { getByRole } = render(<ThemeProvider><Probe /></ThemeProvider>);
    act(() => getByRole('button').click());
    expect(localStorage.getItem(THEME_KEY)).toBe('dark');
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(localStorage.length).toBe(1);
  });
  it('reads a stored choice and ignores junk', () => {
    localStorage.setItem(THEME_KEY, 'light');
    expect(readStoredTheme()).toBe('light');
    localStorage.setItem(THEME_KEY, 'neon');
    expect(readStoredTheme()).toBe('system');
  });
});
