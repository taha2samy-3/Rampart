/**
 * Query grammar (docs/16 D16): terms are ANDed, `-` negates, `field:a,b` ORs
 * values, `>30d` style ranges, `CVE-2024-*` prefix wildcards, "quoted text".
 * The Go parser lives in internal/query/grammar; this one also keeps the
 * source text of every term so the filter bar can remove a single term.
 */
export type ValueKind = 'bare' | 'range' | 'wildcard';
export interface QueryValue {
  raw: string;
  kind: ValueKind;
  op?: '>' | '>=' | '<' | '<=';
  operand?: string;
}
export interface QueryTerm {
  negated: boolean;
  field?: string;
  values: QueryValue[];
  text?: string;
  /** exact source slice, quotes included, so removing a term is lossless */
  source: string;
}
export interface ParsedQuery {
  terms: QueryTerm[];
  error?: string;
}

/** Fields accepted in Phase 1 (D16). */
export const KNOWN_FIELDS = [
  'state', 'severity', 'risk', 'score', 'category', 'scanner', 'rule', 'cve', 'cwe', 'app', 'asset',
  'assettype', 'env', 'track', 'path', 'purl', 'tag', 'owner', 'kev', 'fix', 'sla', 'age', 'seen',
  'source', 'run',
] as const;

function splitOutsideQuotes(input: string, sep: (ch: string) => boolean): { parts: string[]; open: boolean } {
  const parts: string[] = [];
  let cur = '';
  let inQuote = false;
  for (const ch of input) {
    if (ch === '"') inQuote = !inQuote;
    if (!inQuote && sep(ch)) {
      if (cur) parts.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (cur) parts.push(cur);
  return { parts, open: inQuote };
}

const unquote = (s: string) => s.replace(/"/g, '');

function parseValue(rawSource: string): QueryValue {
  const raw = unquote(rawSource);
  const quoted = rawSource.includes('"');
  const m = !quoted ? /^(>=|<=|>|<)(.+)$/.exec(raw) : null;
  if (m) return { raw, kind: 'range', op: m[1] as QueryValue['op'], operand: m[2] };
  if (!quoted && raw.endsWith('*') && raw.length > 1) return { raw, kind: 'wildcard', operand: raw.slice(0, -1) };
  return { raw, kind: 'bare' };
}

export function parseQuery(q: string): ParsedQuery {
  const { parts, open } = splitOutsideQuotes(q, (c) => /\s/.test(c));
  const terms: QueryTerm[] = [];
  let error: string | undefined = open ? 'A quote is not closed.' : undefined;
  for (const source of parts) {
    let body = source;
    let negated = false;
    if (body.startsWith('-') && body.length > 1) {
      negated = true;
      body = body.slice(1);
    }
    const m = /^([A-Za-z_]+):(.*)$/.exec(body);
    if (m) {
      const field = (m[1] ?? '').toLowerCase();
      const { parts: vals } = splitOutsideQuotes(m[2] ?? '', (c) => c === ',');
      if (vals.length === 0) {
        error ??= `Add a value after ${field}:`;
        continue;
      }
      terms.push({ negated, field, values: vals.map(parseValue), source });
    } else {
      terms.push({ negated, text: unquote(body), values: [], source });
    }
  }
  return { terms, error };
}

export function removeTerm(q: string, index: number): string {
  const { parts } = splitOutsideQuotes(q, (c) => /\s/.test(c));
  // parts and parsed terms line up except for terms dropped as errors; match by source.
  const parsed = parseQuery(q).terms;
  const target = parsed[index]?.source;
  const at = target === undefined ? -1 : parts.indexOf(target);
  if (at >= 0) parts.splice(at, 1);
  return parts.join(' ');
}

/** Values currently selected for `field` in non-negated terms (used by facets). */
export function fieldValues(q: string, field: string): string[] {
  return parseQuery(q)
    .terms.filter((t) => t.field === field && !t.negated)
    .flatMap((t) => t.values.map((v) => v.raw));
}

/** Toggle one value of a field, keeping other terms untouched. */
export function toggleFieldValue(q: string, field: string, value: string): string {
  const { parts } = splitOutsideQuotes(q, (c) => /\s/.test(c));
  const rest: string[] = [];
  let current: string[] = [];
  for (const p of parts) {
    const m = /^([A-Za-z_]+):(.*)$/.exec(p);
    if (m && (m[1] ?? '').toLowerCase() === field) current = splitOutsideQuotes(m[2] ?? '', (c) => c === ',').parts;
    else rest.push(p);
  }
  const next = current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
  if (next.length) rest.push(`${field}:${next.join(',')}`);
  return rest.join(' ');
}

export function describeTerm(t: QueryTerm): string {
  const neg = t.negated ? 'not ' : '';
  if (!t.field) return `${neg}${t.text ?? ''}`;
  return `${neg}${t.field}: ${t.values.map((v) => (v.kind === 'range' ? `${v.op}${v.operand}` : v.raw)).join(' or ')}`;
}
