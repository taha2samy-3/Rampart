import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const css = readFileSync(join(process.cwd(), 'src/styles/tokens.css'), 'utf8');
const block = (start: string) => {
  const i = css.indexOf(start);
  const body = css.slice(css.indexOf('{', i) + 1, css.indexOf('}', i));
  return Object.fromEntries([...body.matchAll(/--([\w-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1]!, m[2]!]));
};
const lum = (hex: string) => {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0]! + 0.7152 * c[1]! + 0.0722 * c[2]!;
};
const ratio = (a: string, b: string) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x! + 0.05) / (y! + 0.05);
};

const light = block(':root {');
const dark = block(":root[data-theme='dark']");

describe.each([['light', light], ['dark', dark]] as const)('contrast, %s theme', (_n, t) => {
  it('text meets 4.5:1 on both surfaces', () => {
    for (const fg of ['ink', 'ink-2', 'accent']) for (const bg of ['surface', 'chrome']) expect(ratio(t[fg]!, t[bg]!), `${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
    expect(ratio(t['accent-contrast']!, t['accent']!)).toBeGreaterThanOrEqual(4.5);
  });
  it('risk shapes and score-bar segments meet 3:1 on the work surface (info ring is documented as lower)', () => {
    for (const k of ['band-critical', 'band-high', 'band-low', 'seg-severity', 'seg-threat', 'seg-context', 'seg-reduction']) {
      expect(ratio(t[k]!, t['surface']!), k).toBeGreaterThanOrEqual(3);
    }
    // Doc 13 fixes medium at #C99A1A (2.6:1 on white). The square shape and the printed score carry the meaning.
    expect(ratio(t['band-medium']!, t['surface']!)).toBeGreaterThanOrEqual(2.5);
  });
});
