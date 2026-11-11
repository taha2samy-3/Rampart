import type { Band } from '@/lib/band';

const COLOR: Record<Band, string> = {
  critical: 'text-critical',
  high: 'text-high',
  medium: 'text-medium',
  low: 'text-low',
  info: 'text-info',
};

export const BAND_LABEL: Record<Band, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

/**
 * One shape per risk band so colour is never the only signal:
 * critical diamond, high triangle, medium square, low circle, info ring.
 * Decorative unless `label` is set (then role="img"). The text next to it
 * normally carries the band name.
 */
export function BandShape({ band, size = 12, label }: { band: Band; size?: number; label?: boolean }) {
  const a11y = label ? { role: 'img', 'aria-label': BAND_LABEL[band] } : { 'aria-hidden': true as const };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 12 12"
      className={`${COLOR[band]} shrink-0`}
      data-band={band}
      focusable="false"
      {...a11y}
    >
      {band === 'critical' && <path d="M6 .5 11.5 6 6 11.5.5 6Z" fill="currentColor" />}
      {band === 'high' && <path d="M6 1 11.5 10.5h-11Z" fill="currentColor" />}
      {band === 'medium' && <rect x="1.5" y="1.5" width="9" height="9" fill="currentColor" />}
      {band === 'low' && <circle cx="6" cy="6" r="4.75" fill="currentColor" />}
      {band === 'info' && <circle cx="6" cy="6" r="4" fill="none" stroke="currentColor" strokeWidth="1.75" />}
    </svg>
  );
}
