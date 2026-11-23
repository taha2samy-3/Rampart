import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import type { ApplicationPage } from '@/api/types';
import { bandFromScore } from '@/lib/band';
import { BandShape, BAND_LABEL, BAND_TEXT_CLASS } from './BandShape';
import { cn } from '@/lib/cn';

interface ApplicationScoreCardProps {
  app: ApplicationPage;
  appQuerySlug: string;
  className?: string;
}

const BAND_BADGE_STYLES: Record<string, string> = {
  critical: 'border-critical/30 bg-critical/10 text-critical',
  high: 'border-high/30 bg-high/10 text-high',
  medium: 'border-medium/30 bg-medium/10 text-medium',
  low: 'border-low/30 bg-low/10 text-low',
  info: 'border-rule bg-chrome text-ink-2',
};

const BAND_TRACK_FILLS: Record<string, string> = {
  critical: 'bg-critical',
  high: 'bg-high',
  medium: 'bg-medium',
  low: 'bg-low',
  info: 'bg-[var(--seg-severity)]',
};

/**
 * Standard Application Security Posture & Risk Score Card.
 * Adheres to Rampart design tokens: clean card border, calibrated 1000-point scale,
 * accessibility glyphs (BandShape), and zero artificial decorations.
 */
export function ApplicationScoreCard({ app, appQuerySlug, className }: ApplicationScoreCardProps) {
  const { t } = useTranslation();
  const score = Math.max(0, Math.min(1000, app.risk_score ?? 0));
  const band = bandFromScore(score);
  const percentage = (score / 1000) * 100;

  const totalOpen =
    (app.open?.critical ?? 0) +
    (app.open?.high ?? 0) +
    (app.open?.medium ?? 0) +
    (app.open?.low ?? 0);

  const adherence =
    app.sla?.adherence !== undefined
      ? `${Math.round(app.sla.adherence * 100)}%`
      : '—';

  return (
    <article
      data-testid="application-score-card"
      aria-label={t('apps.scoreCardAria', { defaultValue: 'Application Risk Posture and Score' })}
      className={cn(
        'rounded-ctl border border-rule bg-surface p-5 shadow-xs transition-colors',
        className,
      )}
    >
      {/* Top Meta Row */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule/60 pb-3">
        <div className="flex items-center gap-2">
          <span className="text-12 font-medium tracking-wide uppercase text-ink-2">
            Security Risk Posture
          </span>
          <span
            className={cn(
              'inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-11 font-semibold border uppercase tracking-wider',
              BAND_BADGE_STYLES[band],
            )}
          >
            <BandShape band={band} size={10} />
            <span>{BAND_LABEL[band]} Risk</span>
          </span>
        </div>

        <div className="flex items-center gap-2 text-12 text-ink-2">
          <span>{t('apps.criticality', { level: app.business_criticality })}</span>
          <span>•</span>
          <span>{app.internet_facing ? t('apps.internetFacing') : 'internal'}</span>
        </div>
      </div>

      {/* Main Score Hero & Stats Row */}
      <div className="mt-4 grid grid-cols-1 gap-6 md:grid-cols-12 md:items-center">
        {/* Left: Score Number & Summary */}
        <div className="md:col-span-5">
          <div className="flex items-baseline gap-2">
            <span
              className={cn(
                'font-mono text-38 font-bold leading-none tracking-tight tnum',
                BAND_TEXT_CLASS[band],
              )}
            >
              {score}
            </span>
            <span className="text-14 font-medium text-ink-2">/ 1000</span>
          </div>
          <p className="mt-2 text-12 leading-relaxed text-ink-2">
            {t('apps.scoreCardDesc', {
              defaultValue:
                'Evaluated from peak finding severity, threat feeds (KEV/EPSS), and active attack surface exposure.',
            })}
          </p>
        </div>

        {/* Right: Quick Stat Tiles */}
        <div className="grid grid-cols-3 gap-3 md:col-span-7">
          <div className="rounded-ctl border border-rule/70 bg-chrome/40 p-2.5">
            <span className="block text-11 font-medium text-ink-2">Exposures</span>
            <span
              className={cn(
                'mt-1 block font-mono text-16 font-semibold tnum',
                app.exposure_count > 0 ? 'text-critical' : 'text-ink',
              )}
            >
              {app.exposure_count}
            </span>
            <span className="block text-[11px] text-ink-2">Critical / High</span>
          </div>

          <div className="rounded-ctl border border-rule/70 bg-chrome/40 p-2.5">
            <span className="block text-11 font-medium text-ink-2">Open Issues</span>
            <span
              className={cn(
                'mt-1 block font-mono text-16 font-semibold tnum',
                totalOpen > 0 ? 'text-ink' : 'text-ink-2',
              )}
            >
              {totalOpen}
            </span>
            <span className="block text-[11px] text-ink-2">Total findings</span>
          </div>

          <div className="rounded-ctl border border-rule/70 bg-chrome/40 p-2.5">
            <span className="block text-11 font-medium text-ink-2">SLA Adherence</span>
            <span
              className={cn(
                'mt-1 block font-mono text-16 font-semibold tnum',
                app.sla_breached > 0 ? 'text-critical' : 'text-ink',
              )}
            >
              {adherence}
            </span>
            <span className="block text-[11px] text-ink-2">
              {app.sla_breached > 0 ? `${app.sla_breached} breached` : 'In policy'}
            </span>
          </div>
        </div>
      </div>

      {/* Calibrated 1000-Point Spectrum Bar */}
      <div className="mt-5">
        <div className="flex items-center justify-between text-11 font-medium text-ink-2">
          <span>Risk Spectrum</span>
          <span className="font-mono tnum text-ink">{percentage.toFixed(1)}% of scale</span>
        </div>

        <div
          role="progressbar"
          aria-valuenow={score}
          aria-valuemin={0}
          aria-valuemax={1000}
          aria-valuetext={`${score} of 1000, ${BAND_LABEL[band]} risk posture`}
          aria-label={`Risk score ${score} of 1000 (${BAND_LABEL[band]} risk)`}
          className="relative mt-1.5 h-2.5 w-full overflow-hidden rounded-full bg-chrome border border-rule/50"
        >
          {/* Active Fill */}
          <div
            className={cn('h-full transition-all duration-300', BAND_TRACK_FILLS[band])}
            style={{ width: `${Math.max(1, percentage)}%` }}
          />

          {/* Calibrated Segment Markers (100, 400, 600, 800) */}
          <div
            className="absolute inset-y-0 w-px bg-rule/80 pointer-events-none"
            style={{ left: '10%' }}
            title="Low threshold (100)"
          />
          <div
            className="absolute inset-y-0 w-px bg-rule/80 pointer-events-none"
            style={{ left: '40%' }}
            title="Medium threshold (400)"
          />
          <div
            className="absolute inset-y-0 w-px bg-rule/80 pointer-events-none"
            style={{ left: '60%' }}
            title="High threshold (600)"
          />
          <div
            className="absolute inset-y-0 w-px bg-rule/80 pointer-events-none"
            style={{ left: '80%' }}
            title="Critical threshold (800)"
          />
        </div>

        {/* Spectrum Threshold Labels */}
        <div className="mt-1 flex justify-between text-[10.5px] text-ink-2 tnum">
          <span>0</span>
          <span className={band === 'low' ? 'font-semibold text-low' : ''}>Low 100</span>
          <span className={band === 'medium' ? 'font-semibold text-medium' : ''}>Med 400</span>
          <span className={band === 'high' ? 'font-semibold text-high' : ''}>High 600</span>
          <span className={band === 'critical' ? 'font-semibold text-critical' : ''}>Crit 800</span>
          <span>1000</span>
        </div>
      </div>

      {/* Finding Breakdown Pills Row */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-rule/60 pt-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-12 font-medium text-ink-2">Active Findings:</span>
          <Link
            to="/findings"
            search={{ q: `app:${appQuerySlug} risk:critical state:open,under_investigation,affected` }}
            className="inline-flex items-center gap-1 rounded border border-rule/60 bg-chrome/50 px-2 py-0.5 text-11 text-ink no-underline hover:border-critical/50 hover:bg-critical/5 transition-colors"
          >
            <BandShape band="critical" size={10} />
            <span className="font-semibold tnum">{app.open?.critical ?? 0}</span>
            <span className="text-ink-2">Critical</span>
          </Link>

          <Link
            to="/findings"
            search={{ q: `app:${appQuerySlug} risk:high state:open,under_investigation,affected` }}
            className="inline-flex items-center gap-1 rounded border border-rule/60 bg-chrome/50 px-2 py-0.5 text-11 text-ink no-underline hover:border-high/50 hover:bg-high/5 transition-colors"
          >
            <BandShape band="high" size={10} />
            <span className="font-semibold tnum">{app.open?.high ?? 0}</span>
            <span className="text-ink-2">High</span>
          </Link>

          <Link
            to="/findings"
            search={{ q: `app:${appQuerySlug} risk:medium state:open,under_investigation,affected` }}
            className="inline-flex items-center gap-1 rounded border border-rule/60 bg-chrome/50 px-2 py-0.5 text-11 text-ink no-underline hover:border-medium/50 hover:bg-medium/5 transition-colors"
          >
            <BandShape band="medium" size={10} />
            <span className="font-semibold tnum">{app.open?.medium ?? 0}</span>
            <span className="text-ink-2">Medium</span>
          </Link>

          <Link
            to="/findings"
            search={{ q: `app:${appQuerySlug} risk:low state:open,under_investigation,affected` }}
            className="inline-flex items-center gap-1 rounded border border-rule/60 bg-chrome/50 px-2 py-0.5 text-11 text-ink no-underline hover:border-low/50 hover:bg-low/5 transition-colors"
          >
            <BandShape band="low" size={10} />
            <span className="font-semibold tnum">{app.open?.low ?? 0}</span>
            <span className="text-ink-2">Low</span>
          </Link>
        </div>

        <Link
          to="/findings"
          search={{ q: `app:${appQuerySlug} state:open,under_investigation,affected` }}
          className="text-12 font-medium text-accent hover:underline inline-flex items-center gap-1"
        >
          {t('apps.seeAll', { defaultValue: 'See all findings' })} →
        </Link>
      </div>
    </article>
  );
}
