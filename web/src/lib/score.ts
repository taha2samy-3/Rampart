import type { ScoreBreakdown } from '@/api/types';

export type SegmentKind = 'severity' | 'threat' | 'context' | 'reduction';
export interface Segment {
  kind: SegmentKind;
  points: number;
  /** share of the scale, 0..1 */
  fraction: number;
}

/** Full scale of the score (docs/06: 0..1000). */
export const SCORE_SCALE = 1000;

const THREAT = new Set(['KEV', 'EPSS_HIGH', 'EPSS_MODERATE', 'SECRET_VERIFIED']);

export function factorKind(name: string, points: number): SegmentKind {
  if (points < 0) return 'reduction';
  return THREAT.has(name) || name.startsWith('EPSS') || name.startsWith('EXPLOIT') ? 'threat' : 'context';
}

/**
 * Turns a breakdown into bar segments, in reading order: severity, threat,
 * context, then the outlined reduction. Segment length is its points over the
 * 1000 scale. A reduction is drawn as the points that were taken away, after
 * the filled segments, so filled length always equals the score before caps.
 */
export function scoreSegments(b: ScoreBreakdown | undefined | null): Segment[] {
  if (!b) return [];
  const sums: Record<SegmentKind, number> = {
    severity: Math.max(0, b.base_points ?? 0),
    threat: 0,
    context: 0,
    reduction: 0,
  };
  for (const f of b.factors ?? []) {
    const kind = factorKind(f.name, f.points);
    sums[kind] += kind === 'reduction' ? Math.abs(f.points) : f.points;
  }
  return (['severity', 'threat', 'context', 'reduction'] as const)
    .filter((k) => sums[k] > 0)
    .map((k) => ({ kind: k, points: sums[k], fraction: Math.min(1, sums[k] / SCORE_SCALE) }));
}

export function describeScore(b: ScoreBreakdown | undefined | null, score: number): string {
  const seg = scoreSegments(b);
  if (seg.length === 0) return `Score ${score} of ${SCORE_SCALE}.`;
  const label: Record<SegmentKind, string> = {
    severity: 'scanner severity',
    threat: 'threat intelligence',
    context: 'exposure and context',
    reduction: 'removed by compensating controls',
  };
  return `Score ${score} of ${SCORE_SCALE}: ${seg.map((s) => `${s.points} ${label[s.kind]}`).join(', ')}.`;
}

const FACTOR_LABELS: Record<string, string> = {
  KEV: 'Known exploited',
  EPSS_HIGH: 'Exploit likelihood 50% or more',
  EPSS_MODERATE: 'Exploit likelihood 10% or more',
  SECRET_VERIFIED: 'Secret verified live',
  INTERNET_FACING: 'Internet-facing',
  SENSITIVE_DATA: 'Handles sensitive data',
  APP_CRITICAL: 'Critical application',
  APP_HIGH: 'High-criticality application',
  PRODUCTION_ENV: 'Runs in production',
  FIX_AVAILABLE: 'Fix available',
  AGING_DEBT: 'Open for a long time',
  UNREACHABLE: 'Code is not reachable',
  COMPENSATING_CONTROL: 'Compensating control in place',
};

export function factorLabel(name: string): string {
  return FACTOR_LABELS[name] ?? name.charAt(0) + name.slice(1).toLowerCase().replace(/_/g, ' ');
}
