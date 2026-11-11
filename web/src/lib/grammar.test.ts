import { describe, expect, it } from 'vitest';
import { describeTerm, fieldValues, parseQuery, removeTerm, toggleFieldValue } from './grammar';

describe('query grammar (D16)', () => {
  it('parses fields, OR values, negation, ranges, wildcards and text', () => {
    const { terms, error } = parseQuery('severity:critical,high -state:fixed age:>30d cve:CVE-2024-* "sql injection"');
    expect(error).toBeUndefined();
    expect(terms).toHaveLength(5);
    expect(terms[0]).toMatchObject({ field: 'severity', negated: false });
    expect(terms[0]?.values.map((v) => v.raw)).toEqual(['critical', 'high']);
    expect(terms[1]).toMatchObject({ field: 'state', negated: true });
    expect(terms[2]?.values[0]).toMatchObject({ kind: 'range', op: '>', operand: '30d' });
    expect(terms[3]?.values[0]).toMatchObject({ kind: 'wildcard', operand: 'CVE-2024-' });
    expect(terms[4]).toMatchObject({ text: 'sql injection' });
  });
  it('reports an unclosed quote and an empty value', () => {
    expect(parseQuery('title "abc').error).toMatch(/quote/);
    expect(parseQuery('state:').error).toMatch(/value/);
  });
  it('removes one term without touching the rest', () => {
    expect(removeTerm('risk:high state:open "a b"', 1)).toBe('risk:high "a b"');
  });
  it('toggles facet values inside one term', () => {
    expect(toggleFieldValue('state:open', 'risk', 'high')).toBe('state:open risk:high');
    expect(toggleFieldValue('risk:high', 'risk', 'critical')).toBe('risk:high,critical');
    expect(toggleFieldValue('risk:high,critical', 'risk', 'high')).toBe('risk:critical');
    expect(toggleFieldValue('risk:high', 'risk', 'high')).toBe('');
    expect(fieldValues('risk:high,low state:open', 'risk')).toEqual(['high', 'low']);
  });
  it('describes terms in words', () => {
    expect(describeTerm(parseQuery('-state:fixed').terms[0]!)).toBe('not state: fixed');
  });
});
