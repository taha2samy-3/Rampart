import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { getOverview, getTrend, qk, toProblem } from '@/api';
import type { Overview, TrendPoint } from '@/api/types';
import { BandShape, EmptyState, ProblemMessage, Skeleton } from '@/components';
import { openText } from '@/lib/apps';
import { toBand } from '@/lib/band';
import { absoluteDate, shortAge } from '@/lib/format';

const DAY = 86_400_000;

/**
 * It opens with what changed and what is overdue (docs/13), not with a row of numbers. Below: the trend of open
 * findings, how the deadlines are going, the applications ranked by risk, and those that were not scanned lately.
 */
export function OverviewRoute() {
  const { t } = useTranslation();
  useEffect(() => {
    document.title = `${t('overview.title')} - Rampart`;
  }, [t]);
  const ov = useQuery({ queryKey: qk.overview(), queryFn: ({ signal }) => getOverview(signal), refetchInterval: 60_000 });
  const trend = useQuery({ queryKey: qk.trend('open', 30), queryFn: ({ signal }) => getTrend('open', 30, signal) });

  if (ov.isPending) {
    return (
      <div className="p-6" aria-busy="true" aria-label={t('common.loading')}>
        <Skeleton className="mb-3 h-5 w-72" />
        <Skeleton className="h-3 w-96" />
      </div>
    );
  }
  if (ov.isError) {
    return <div className="p-6"><ProblemMessage problem={toProblem(ov.error)} title={t('overview.loadFailed')} onRetry={() => void ov.refetch()} /></div>;
  }
  return <Body ov={ov.data} trend={trend.data ?? []} />;
}

function Body({ ov, trend }: { ov: Overview; trend: TrendPoint[] }) {
  const { t } = useTranslation();
  const open = openText(ov.open, t);
  const [now] = useState(() => Date.now()); // the clock the page was opened at
  const ch = ov.changes;
  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-[900px] px-6 py-5">
        <h1 className="display text-28 leading-tight">{t('overview.title')}</h1>

        <section className="mt-5" aria-labelledby="ov-changed">
          <h2 id="ov-changed" className="mb-1 text-14 font-semibold">{t('overview.changed')}</h2>
          <p className="m-0 text-16">{t('overview.changedLine', { new: ch.new, reopened: ch.reopened, fixed: ch.fixed })}</p>
          {ch.new > 0 && <Link to="/findings" search={{ q: 'age:<1d' }} className="mt-1 inline-block text-13">{t('overview.seeNew')}</Link>}
        </section>

        <section className="mt-6" aria-labelledby="ov-overdue">
          <h2 id="ov-overdue" className="mb-1 text-14 font-semibold">{t('overview.overdue')}</h2>
          {ov.overdue.length === 0 ? (
            <p className="m-0 text-13 text-ink-2">{t('overview.overdueEmpty')}</p>
          ) : (
            <>
              {ov.overdue_total > ov.overdue.length && (
                <p className="m-0 mb-1 text-12 text-ink-2">{t('overview.overdueMore', { count: ov.overdue_total, shown: ov.overdue.length })}</p>
              )}
              <ol className="m-0 list-none border-t border-rule p-0 text-13">
                {ov.overdue.map((f) => (
                  <li key={f.id} className="flex items-center gap-3 border-b border-rule py-2">
                    <BandShape band={toBand(f.band)} size={12} />
                    <Link to="/findings" search={{ sel: f.id }} className="min-w-0 flex-1 truncate font-medium text-ink no-underline hover:underline">{f.title}</Link>
                    <span className="hidden text-ink-2 sm:inline">{f.app_name}</span>
                    <span className="font-semibold">{t('overview.overdueBy', { days: Math.max(1, Math.floor((now - Date.parse(f.due)) / DAY)) })}</span>
                  </li>
                ))}
              </ol>
            </>
          )}
        </section>

        <section className="mt-6" aria-labelledby="ov-trend">
          <h2 id="ov-trend" className="mb-1 text-14 font-semibold">{t('overview.trend')}</h2>
          <TrendChart points={trend} />
        </section>

        <section className="mt-6" aria-labelledby="ov-deadlines">
          <h2 id="ov-deadlines" className="mb-1 text-14 font-semibold">{t('overview.deadlines')}</h2>
          <p className="m-0 text-13">
            {ov.sla.adherence === undefined ? t('apps.noDeadlines') : t('apps.adherence', { percent: Math.round(ov.sla.adherence * 100) })}
          </p>
          <p className="m-0 mt-1 text-13 text-ink-2">{open ? t('overview.byBand', { parts: open }) : t('overview.nothingOpen')}</p>
        </section>

        <section className="mt-6" aria-labelledby="ov-apps">
          <h2 id="ov-apps" className="mb-1 text-14 font-semibold">{t('overview.apps')}</h2>
          {ov.top_apps.length === 0 ? (
            <p className="m-0 text-13 text-ink-2">{t('overview.appsEmpty')}</p>
          ) : (
            <ol className="m-0 list-none border-t border-rule p-0 text-13">
              {ov.top_apps.map((a) => (
                <li key={a.id} className="flex items-center gap-3 border-b border-rule py-2">
                  <span className="w-9 text-end text-14 font-semibold tnum">{a.risk_score}</span>
                  <Link to="/applications/$id" params={{ id: a.id }} className="min-w-0 flex-1 truncate font-medium text-ink no-underline hover:underline">{a.name}</Link>
                  <span className="text-ink-2">{openText(a.open, t)}</span>
                </li>
              ))}
            </ol>
          )}
        </section>

        <section className="mt-6 pb-8" aria-labelledby="ov-gaps">
          <h2 id="ov-gaps" className="mb-1 text-14 font-semibold">{t('overview.gaps')}</h2>
          <p className="m-0 mb-1 text-12 text-ink-2">{t('overview.gapsHelp')}</p>
          {ov.coverage_gaps.length === 0 ? (
            <p className="m-0 text-13 text-ink-2">{t('overview.gapsEmpty')}</p>
          ) : (
            <ul className="m-0 list-none border-t border-rule p-0 text-13">
              {ov.coverage_gaps.map((a) => (
                <li key={a.id} className="flex items-center gap-3 border-b border-rule py-2">
                  <Link to="/applications/$id" params={{ id: a.id }} className="min-w-0 flex-1 truncate font-medium text-ink no-underline hover:underline">{a.name}</Link>
                  <span className="text-ink-2" title={a.last_scan ? absoluteDate(a.last_scan) : undefined}>{a.last_scan ? shortAge(a.last_scan) : t('apps.never')}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}

/** A plain line over the days, with the numbers one click away. Not coloured: colour is for risk. */
function TrendChart({ points }: { points: TrendPoint[] }) {
  const { t } = useTranslation();
  const W = 840;
  const H = 120;
  const path = useMemo(() => {
    if (points.length < 2) return '';
    const max = Math.max(1, ...points.map((p) => p.value));
    return points.map((p, i) => `${i === 0 ? 'M' : 'L'}${((i / (points.length - 1)) * W).toFixed(1)} ${(H - 6 - (p.value / max) * (H - 12)).toFixed(1)}`).join(' ');
  }, [points]);
  if (points.length === 0) return <EmptyState className="p-0 text-left" title={t('overview.nothingOpen')} />;
  const first = points[0]!;
  const last = points[points.length - 1]!;
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-[120px] w-full text-ink" role="img" aria-label={t('overview.trendLabel', { from: first.value, start: first.day, to: last.value, end: last.day })}>
        <line x1="0" y1={H - 0.5} x2={W} y2={H - 0.5} stroke="var(--rule)" strokeWidth="1" />
        <path d={path} fill="none" stroke="currentColor" strokeWidth="1.75" vectorEffect="non-scaling-stroke" />
      </svg>
      <details className="mt-1 text-12">
        <summary className="cursor-pointer text-ink-2">{t('overview.trendTable')}</summary>
        <table className="mt-1 text-12">
          <thead>
            <tr><th className="pe-4 text-start font-medium">{t('overview.colDay')}</th><th className="text-end font-medium">{t('overview.colOpen')}</th></tr>
          </thead>
          <tbody>
            {points.map((p) => (
              <tr key={p.day}><td className="pe-4">{p.day}</td><td className="text-end tnum">{p.value}</td></tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  );
}
