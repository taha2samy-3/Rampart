import type { ScoreBreakdown } from '@/api/types';
import { describeScore, scoreSegments, type SegmentKind } from '@/lib/score';
import type { Band } from '@/lib/band';
import { cn } from '@/lib/cn';

const FILL: Record<SegmentKind, string> = {
  severity: 'bg-[var(--seg-severity)]',
  threat: 'bg-[var(--seg-threat)]',
  context: 'bg-[var(--seg-context)]',
  reduction: 'border-[1.5px] border-[var(--seg-reduction)] bg-transparent',
};

const BAND_FILL: Record<Band, string> = {
  critical: 'bg-critical',
  high: 'bg-high',
  medium: 'bg-medium',
  low: 'bg-low',
  info: 'bg-[var(--seg-severity)]',
};

/**
 * The signature element. Segments are scanner severity (slate), threat
 * intelligence (red), exposure and context (orange) and an outlined segment
 * for points removed by compensating controls. Length is points over the
 * 1000 scale. `size="row"` is the 72 px bar in the table; `size="full"`
 * fills its container in the inspector.
 */
export function ScoreBar({
  breakdown,
  score,
  size = 'row',
  className,
  band,
}: {
  breakdown: ScoreBreakdown | null | undefined;
  score: number;
  size?: 'row' | 'full';
  className?: string;
  band?: Band;
}) {
  // Without a breakdown (an application's score is the highest of its findings, D43) the bar still shows the
  // score's length on the 1000 scale, as one segment, instead of an empty track (D61).
  const parts = scoreSegments(breakdown);
  const segments = parts.length > 0 || score <= 0 ? parts : [{ kind: 'severity' as SegmentKind, fraction: Math.min(1, score / 1000) }];

  return (
    <span
      role="img"
      aria-label={describeScore(breakdown, score)}
      className={cn(
        'flex items-stretch overflow-hidden bg-[color-mix(in_srgb,var(--rule)_45%,transparent)]',
        size === 'row' ? 'h-2 w-[72px]' : 'h-3.5 w-full',
        className,
      )}
    >
      {segments.map((s) => (
        <span
          key={s.kind}
          data-segment={s.kind}
          className={cn(
            'block h-full shrink-0 border-e border-e-[var(--surface)] box-border',
            // No breakdown: the band the server gave colours the one segment; without one it stays slate, never a guess.
            parts.length > 0 ? FILL[s.kind] : band ? BAND_FILL[band] : FILL.severity,
          )}
          style={{ inlineSize: `${(s.fraction * 100).toFixed(2)}%`, minInlineSize: '2px' }}
        />
      ))}
    </span>
  );
}
