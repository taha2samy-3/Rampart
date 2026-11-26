import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

// docs/51 step 3.2: a colour or size class that @theme does not define compiles to nothing, so a severity written
// as `text-danger` or a size written as `text-11` silently has no colour or size. This test reads the tokens from
// index.css and fails on any colour or type-scale utility in the screens that names something else. Tailwind's
// own palette (rose, amber, blue, ...) is refused too: colour is for risk and comes from the tokens (docs/13).

const root = process.cwd();
const css = readFileSync(join(root, 'src/styles/index.css'), 'utf8');
const theme = css.slice(css.indexOf('@theme'), css.indexOf('}', css.indexOf('@theme')));
const COLORS = new Set([...theme.matchAll(/--color-([a-z0-9-]+):/g)].map((m) => m[1]!));
const SIZES = new Set([...theme.matchAll(/--text-(\d+):/g)].map((m) => m[1]!));
// Keywords Tailwind accepts in a colour position that are not palette colours.
const KEYWORDS = new Set(['transparent', 'current', 'inherit']);
// Left as they are on purpose: the NO-BUILTIN badge waits for the owner's decision (docs/51 Q6). Remove these
// entries when it is decided.
const PENDING = new Set(['src/components/Logo.tsx: text-10', 'src/routes/login/LoginPage.tsx: text-10']);

// What may follow a colour prefix and is not a colour.
const NOT_COLOR: Record<string, RegExp> = {
  text: /^(left|center|right|start|end|justify|wrap|nowrap|balance|pretty|ellipsis|clip)$/,
  bg: /^(none|cover|contain|auto|center|top|bottom|left|right|fixed|local|scroll|repeat|no-repeat|repeat-x|repeat-y|clip-.*|origin-.*|blend-.*|linear-.*|radial|conic|gradient-.*)$/,
  border: /^(\d+|x|y|t|b|l|r|s|e|solid|dashed|dotted|double|hidden|none|collapse|separate|spacing.*|x-\d+|y-\d+|t-\d+|b-\d+|l-\d+|r-\d+|s-\d+|e-\d+)$/,
  ring: /^(\d+|inset|offset-\d+)$/,
  outline: /^(\d+|none|hidden|solid|dashed|dotted|double|offset-.+)$/,
  fill: /^none$/,
  stroke: /^(\d+|none)$/,
  divide: /^(x|y|x-\d+|y-\d+|x-reverse|y-reverse|solid|dashed|dotted|double|none)$/,
  decoration: /^(\d+|solid|double|dotted|dashed|wavy|auto|from-font|clone|slice)$/,
  placeholder: /^$/,
};
const PREFIX = /^(text|bg|border(?:-[xytblrse])?|ring(?:-offset)?|outline|fill|stroke|divide|decoration|placeholder|from|via|to)-(.+)$/;

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith('.tsx') && !/\.test\.tsx$/.test(p)) out.push(p);
  }
  return out;
}

/** Each class-looking token in the string literals of a file, without variants (`dark:`, `hover:`) or opacity. */
function classTokens(src: string): string[] {
  const out: string[] = [];
  for (const m of src.matchAll(/(["'`])((?:(?!\1)[^\\\n]|\\.)*)\1/g)) {
    for (const raw of m[2]!.split(/[\s${}]+/)) {
      const base = raw.replace(/^[^a-z![]+|[^a-z0-9\])%]+$/g, '').replace(/^!/, '').split(':').pop()!.replace(/\/\d+$/, '');
      if (PREFIX.test(base)) out.push(base);
    }
  }
  return out;
}

export function offTheme(token: string): string | null {
  const m = PREFIX.exec(token);
  if (!m) return null;
  const prefix = m[1]!.replace(/-[xytblrse]$/, '').replace(/-offset$/, '');
  const rest = m[2]!;
  if (rest.startsWith('[') || rest.startsWith('(')) return null; // arbitrary values are a deliberate choice
  if (prefix === 'text' && /^\d+(\.\d+)?$/.test(rest)) return SIZES.has(rest) ? null : `size ${rest} is not in the type scale`;
  if (prefix === 'text' && /^(xs|sm|base|lg|xl|\dxl)$/.test(rest)) return `size ${rest} is Tailwind's scale, not ours`;
  if (NOT_COLOR[prefix]?.test(rest)) return null;
  if (prefix === 'border' && /^\d+$/.test(rest)) return null;
  if (COLORS.has(rest) || KEYWORDS.has(rest)) return null;
  if (prefix === 'from' || prefix === 'via' || prefix === 'to') return `gradient stop ${rest}`;
  return `colour ${rest} is not a theme token`;
}

describe('classes against the theme', () => {
  it('reads the tokens from index.css', () => {
    expect(COLORS.has('critical')).toBe(true);
    expect(SIZES.has('13')).toBe(true);
  });

  it('flags a class the theme does not define', () => {
    expect(offTheme('text-danger')).not.toBeNull();
    expect(offTheme('bg-rose-500')).not.toBeNull();
    expect(offTheme('text-11')).not.toBeNull();
    expect(offTheme('text-critical')).toBeNull();
    expect(offTheme('border-e')).toBeNull();
    expect(offTheme('text-[11.5px]')).toBeNull();
  });

  it('every screen uses only colour and size tokens from @theme', () => {
    const files = walk(join(root, 'src')).filter((f) => !f.includes(`${join('routes', 'styleguide')}`));
    const problems: string[] = [];
    for (const f of files) {
      const seen = new Set<string>();
      for (const tok of classTokens(readFileSync(f, 'utf8'))) {
        const why = offTheme(tok);
        if (why && !seen.has(tok) && !PENDING.has(`${relative(root, f)}: ${tok}`)) {
          seen.add(tok);
          problems.push(`${relative(root, f)}: ${tok} (${why})`);
        }
      }
    }
    expect(problems).toEqual([]);
  });
});
