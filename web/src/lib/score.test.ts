import { describe, expect, it } from 'vitest';
import type { ScoreBreakdown } from '@/api/types';
import { describeScore, factorKind, scoreSegments } from './score';

const b: ScoreBreakdown = {
  base_severity: 'critical', base_points: 600, total_score: 970, band: 'critical',
  factors: [
    { name: 'KEV', points: 300, reason: '' },
    { name: 'EPSS_HIGH', points: 150, reason: '' },
    { name: 'INTERNET_FACING', points: 100, reason: '' },
    { name: 'COMPENSATING_CONTROL', points: -80, reason: '' },
  ],
};

describe('score bar math', () => {
  it('groups factors into severity, threat, context and an outlined reduction', () => {
    const s = scoreSegments(b);
    expect(s.map((x) => [x.kind, x.points])).toEqual([['severity', 600], ['threat', 450], ['context', 100], ['reduction', 80]]);
    expect(s[0]?.fraction).toBeCloseTo(0.6);
    expect(s[3]?.fraction).toBeCloseTo(0.08);
  });
  it('classifies factors', () => {
    expect(factorKind('KEV', 300)).toBe('threat');
    expect(factorKind('EPSS_MODERATE', 60)).toBe('threat');
    expect(factorKind('PRODUCTION_ENV', 60)).toBe('context');
    expect(factorKind('UNREACHABLE', -200)).toBe('reduction');
  });
  it('tolerates null factors and a missing breakdown', () => {
    expect(scoreSegments({ ...b, factors: null }).map((x) => x.kind)).toEqual(['severity']);
    expect(scoreSegments(undefined)).toEqual([]);
  });
  it('writes a text alternative with the numbers', () => {
    expect(describeScore(b, 970)).toBe('Score 970 of 1000: 600 scanner severity, 450 threat intelligence, 100 exposure and context, 80 removed by compensating controls.');
  });
});
