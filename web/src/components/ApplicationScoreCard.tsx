import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import type { ApplicationPage } from '@/api/types';
import { SCORE_BANDS, type BandThresholds, type ScoreBand } from '@/lib/band';
import { worstBand } from '@/lib/apps';
import { BandShape, BAND_LABEL, BAND_TEXT_CLASS } from './BandShape';
import { cn } from '@/lib/cn';

interface ApplicationScoreCardProps {
  app: ApplicationPage;
  appQuerySlug: string;
  /** The band bounds of the policy in force (GET /api/v1/scoring). Without them no marker is drawn. */
  thresholds?: BandThresholds | null;
  className?: string;
}

const FILL: Record<ScoreBand, string> = {
  critical: 'bg-critical',
  high: 'bg-high',
  medium: 'bg-medium',
  low: 'bg-low',
};

const ACTIVE = 'state:open,under_investigation,affected';

/**
 * Where an application stands: its score, the band the server gave it, the band bounds of the policy in force, and
 * the open findings by band (the deadlines have their own section on the page). Every number comes from the API; the band is the worst band among the open findings
 * (the score is the highest of their scores, D43), and the markers are the policy's bounds, not a copy of them.
 */
export function ApplicationScoreCard({ app, appQuerySlug, thresholds, className }: ApplicationScoreCardProps) {
  const { t } = useTranslation();
  const score = Math.max(0, Math.min(1000, app.risk_score ?? 0));
  const band = worstBand(app.open);
  const markers = thresholds
    ? (['medium', 'high', 'critical'] as const).map((b) => ({ band: b, from: thresholds[b] }))
    : [];
  const totalOpen = SCORE_BANDS.reduce((n, b) => n + (app.open?.[b] ?? 0), 0);

  return (
    <section
      data-testid="application-score-card"
      aria-labelledby="score-card-title"
      className={cn('border-y border-rule py-4', className)}
    >
      <h2 id="score-card-title" className="sr-only">{t('apps.scoreTitle')}</h2>
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        {band && <BandShape band={band} size={14} />}
        <span className={cn('text-28 font-semibold leading-none tnum', band ? BAND_TEXT_CLASS[band] : 'text-ink-2')}>{score}</span>
        <span className="text-13 text-ink-2">{t('apps.scoreOf')}</span>
        <span className="text-14 font-semibold text-ink">{band ? BAND_LABEL[band] : t('apps.scoreNoBand')}</span>
      </div>

      <div className="mt-3">
        <div
          role="meter"
          aria-valuenow={score}
          aria-valuemin={0}
          aria-valuemax={1000}
          aria-valuetext={band ? t('apps.scoreValueText', { score, band: BAND_LABEL[band] }) : t('apps.scoreValueTextNone', { score })}
          aria-label={t('apps.scoreTitle')}
          className="relative h-2 w-full bg-[color-mix(in_srgb,var(--rule)_45%,transparent)]"
        >
          <div className={cn('h-full', band ? FILL[band] : 'bg-[var(--seg-severity)]')} style={{ inlineSize: `${score / 10}%` }} />
          {markers.map((m) => (
            <div
              key={m.band}
              data-testid={`band-marker-${m.band}`}
              aria-hidden="true"
              className="pointer-events-none absolute -inset-y-1 w-px bg-ink-2"
              style={{ insetInlineStart: `${m.from / 10}%` }}
            />
          ))}
        </div>
        {markers.length > 0 && (
          <div className="relative mt-1 h-4 text-12 text-ink-2 tnum" aria-hidden="true">
            {markers.map((m) => (
              <span key={m.band} className="absolute -translate-x-1/2 whitespace-nowrap rtl:translate-x-1/2" style={{ insetInlineStart: `${m.from / 10}%` }}>
                {m.from}
              </span>
            ))}
          </div>
        )}
        <p className="m-0 mt-1 text-12 text-ink-2">
          {thresholds
            ? t('apps.scoreBounds', { medium: thresholds.medium, high: thresholds.high, critical: thresholds.critical })
            : t('apps.scoreBoundsMissing')}{' '}
          <Link to="/about" className="text-12">{t('apps.scoreHow')}</Link>
        </p>
      </div>

      <p className="m-0 mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-13">
        <span className="text-ink-2">{totalOpen > 0 ? t('apps.scoreOpen', { count: totalOpen }) : t('apps.noOpen')}</span>
        {SCORE_BANDS.map((b) => {
          const n = app.open?.[b] ?? 0;
          return (
            <Link
              key={b}
              to="/findings"
              search={{ q: `app:${appQuerySlug} risk:${b} ${ACTIVE}` }}
              className={cn('inline-flex items-center gap-1 no-underline hover:underline', n > 0 ? 'text-ink' : 'text-ink-2')}
            >
              <BandShape band={b} size={10} />
              <span className="tnum">{t(`apps.band_${b}`, { count: n })}</span>
            </Link>
          );
        })}
      </p>

    </section>
  );
}
