import { describe, expect, it } from 'vitest';

const files = import.meta.glob('../**/*.tsx', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;

/** Every class list ("..." or `...` in a className) that holds bg-X and text-X of the same colour. */
function samePair(src: string): string[] {
  const out: string[] = [];
  for (const m of src.matchAll(/(["'`])((?:(?!\1).)*?\bbg-[a-z0-9-]+\b(?:(?!\1).)*?)\1/g)) {
    const list = m[2]!;
    for (const bg of list.matchAll(/\bbg-([a-z0-9-]+)(?:\/[0-9]+)?\b/g)) {
      // (?![\\w-]) so that text-accent-contrast is not read as text-accent
      if (new RegExp(`(?<![\\w-])text-${bg[1]}(?![\\w-])`).test(list) && !new RegExp(`(?<![\\w-])bg-${bg[1]}/[0-9]+`).test(list)) out.push(list.trim());
    }
  }
  return out;
}

describe('colour pairs', () => {
  it('no element has text and background of the same colour', () => {
    const bad = Object.entries(files)
      .filter(([f]) => !f.endsWith('.test.tsx'))
      .flatMap(([f, src]) => samePair(src).map((l) => `${f}: ${l}`));
    expect(bad).toEqual([]);
  });

  it('uses the colour tokens, not the raw zinc, slate or gray palettes', () => {
    const bad = Object.entries(files)
      .filter(([f]) => !f.endsWith('.test.tsx'))
      .filter(([, src]) => /\b(?:bg|text|border)-(?:zinc|slate|gray|neutral|stone)-\d{2,3}\b/.test(src))
      .map(([f]) => f);
    expect(bad).toEqual([]);
  });
});
