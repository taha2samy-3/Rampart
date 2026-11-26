/** The bands a shape and colour exist for. `info` is a severity (a scanner may say it), never a score band. */
export const BANDS = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Band = (typeof BANDS)[number];

/** The bands a risk score is cut into (docs/06): the server has no `info` band for a score. */
export const SCORE_BANDS = ['critical', 'high', 'medium', 'low'] as const;
export type ScoreBand = (typeof SCORE_BANDS)[number];

export function toBand(value: string | undefined | null): Band {
  const v = (value ?? '').toLowerCase();
  return (BANDS as readonly string[]).includes(v) ? (v as Band) : 'info';
}

/**
 * The lower bound of each band in the risk policy in force, as GET /api/v1/scoring sends it (`risk.bands`; low
 * starts at 0). A RiskPolicy can move them, so the UI never keeps its own copy (docs/51 step 3.1).
 */
export interface BandThresholds {
  critical: number;
  high: number;
  medium: number;
}

/** The thresholds from the scoring response, or null when the server did not send a usable set. */
export function thresholdsFrom(bands: Record<string, number> | undefined | null): BandThresholds | null {
  if (!bands) return null;
  const { critical, high, medium } = bands;
  if (typeof critical !== 'number' || typeof high !== 'number' || typeof medium !== 'number') return null;
  return { critical, high, medium };
}
