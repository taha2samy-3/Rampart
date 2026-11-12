import type { TFunction } from 'i18next';
import type { OpenBand } from '@/api/types';

const ORDER: OpenBand[] = ['critical', 'high', 'medium', 'low'];

/** "2 critical, 5 high" for the bands that have findings, worst first; "" when none. */
export function openText(open: Record<OpenBand, number>, t: TFunction): string {
  return ORDER.filter((b) => (open[b] ?? 0) > 0)
    .map((b) => t(`apps.band_${b}`, { count: open[b] }))
    .join(', ');
}

/** The worst band with an open finding, for the shape next to a name. */
export function worstBand(open: Record<OpenBand, number>): OpenBand | undefined {
  return ORDER.find((b) => (open[b] ?? 0) > 0);
}
