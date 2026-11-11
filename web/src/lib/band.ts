export const BANDS = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Band = (typeof BANDS)[number];

export function toBand(value: string | undefined | null): Band {
  const v = (value ?? '').toLowerCase();
  return (BANDS as readonly string[]).includes(v) ? (v as Band) : 'info';
}

/** Score bands from docs/06; the API sends the band, this is only a fallback. */
export function bandFromScore(score: number): Band {
  if (score >= 800) return 'critical';
  if (score >= 600) return 'high';
  if (score >= 400) return 'medium';
  if (score >= 100) return 'low';
  return 'info';
}
