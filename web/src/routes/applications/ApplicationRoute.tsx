import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { getApplication, qk, toProblem } from '@/api';
import type { ApplicationPage } from '@/api/types';
import { BandShape, EmptyState, ProblemMessage, Skeleton, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { openText } from '@/lib/apps';
import { toBand } from '@/lib/band';
import { absoluteDate, dueShort, shortAge } from '@/lib/format';

/** One application: where it stands, its deadlines, how fast things get fixed, its worst findings and its coverage. */
export function ApplicationRoute({ id }: { id: string }) {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: qk.applications.one(id), queryFn: ({ signal }) => getApplication(id, signal), retry: false });
  useEffect(() => {
    document.title = `${q.data?.name ?? t('apps.title')} - Rampart`;
  }, [q.data?.name, t]);

  if (q.isPending) {
    return (
      <div className="p-6" aria-busy="true" aria-label={t('common.loading')}>
        <Skeleton className="mb-4 h-6 w-64" />
        <Skeleton className="h-3 w-96" />
      </div>
    );
  }
  if (q.isError) {
    const p = toProblem(q.error);
    return (
      <div className="p-6">
        <Link to="/applications" className="text-13">{t('apps.back')}</Link>
        <div className="mt-4"><ProblemMessage problem={p} title={t('apps.pageFailed')} onRetry={p.status === 404 ? undefined : () => void q.refetch()} /></div>
      </div>
    );
  }
  return <Page app={q.data} />;
}

function Page({ app }: { app: ApplicationPage }) {
  const { t } = useTranslation();
  const text = openText(app.open, t);
  const [now] = useState(() => Date.now()); // the clock the page was opened at
  return (
    <div className="h-full overflow-y-auto">
      <article className="mx-auto max-w-[860px] px-6 py-5">
        <Link to="/applications" className="text-13">{t('apps.back')}</Link>
        <h1 className="display mt-2 text-28 leading-tight">{app.name}</h1>
        <p className="mt-1 text-13 text-ink-2">
          {t('apps.criticality', { level: app.business_criticality })}
          {app.internet_facing ? `, ${t('apps.internetFacing')}` : ''}
          {app.last_scan ? `. ${t('apps.colScan')}: ${absoluteDate(app.last_scan)}` : `. ${t('apps.never')}`}
        </p>

        <section className="mt-6" aria-labelledby="app-summary">
          <h2 id="app-summary" className="mb-1 text-14 font-semibold">{t('apps.summary')}</h2>
          <p className="m-0 text-13">
            <span className="font-medium">{t('apps.openFindings')}: </span>
            {text || t('apps.noOpen')}.
          </p>
          <p className="m-0 mt-1 text-13 text-ink-2">{t('apps.riskLine', { score: app.risk_score, exposure: app.exposure_count })}</p>
          <Link to="/findings" search={{ q: `app:${app.slug} state:open,under_investigation,affected` }} className="mt-1 inline-block text-13">{t('apps.seeAll')}</Link>
        </section>

        <section className="mt-6" aria-labelledby="app-deadlines">
          <h2 id="app-deadlines" className="mb-1 text-14 font-semibold">{t('apps.deadlines')}</h2>
          <p className="m-0 text-13">
            {app.sla.adherence === undefined ? t('apps.noDeadlines') : t('apps.adherence', { percent: Math.round(app.sla.adherence * 100) })}
          </p>
          {app.sla.adherence !== undefined && (
            <p className="m-0 mt-1 text-13 text-ink-2">{t('apps.standing', { within: app.sla.within, late: app.sla.late, breached: app.sla.breached })}</p>
          )}
        </section>

        <section className="mt-6" aria-labelledby="app-mttr">
          <h2 id="app-mttr" className="mb-1 text-14 font-semibold">{t('apps.mttr')}</h2>
          {app.mttr.length === 0 ? (
            <p className="m-0 text-13 text-ink-2">{t('apps.mttrEmpty')}</p>
          ) : (
            <ul className="m-0 list-none p-0 text-13">
              {app.mttr.map((m) => (
                <li key={m.band} className="py-0.5">{t('apps.mttrLine', { band: t(`apps.band_${m.band}`, { count: '' }).trim(), days: m.days.toFixed(1), count: m.fixed })}</li>
              ))}
            </ul>
          )}
        </section>

        <section className="mt-6" aria-labelledby="app-top">
          <h2 id="app-top" className="mb-1 text-14 font-semibold">{t('apps.top')}</h2>
          {app.top_findings.length === 0 ? (
            <p className="m-0 text-13 text-ink-2">{t('apps.topEmpty')}</p>
          ) : (
            <ol className="m-0 list-none border-t border-rule p-0 text-13">
              {app.top_findings.map((f) => {
                const due = dueShort(f.sla_due_date, now);
                return (
                  <li key={f.id} className="flex items-center gap-3 border-b border-rule py-2">
                    <BandShape band={toBand(f.band)} size={12} />
                    <span className="w-9 text-end text-14 font-semibold tnum">{f.risk_score}</span>
                    <Link to="/findings" search={{ sel: f.id }} className="min-w-0 flex-1 truncate font-medium text-ink no-underline hover:underline">{f.title}</Link>
                    <span className={due.late ? 'font-semibold' : 'text-ink-2'}>{due.text}</span>
                  </li>
                );
              })}
            </ol>
          )}
        </section>

        <section className="mt-6" aria-labelledby="app-coverage">
          <h2 id="app-coverage" className="mb-1 text-14 font-semibold">{t('apps.coverage')}</h2>
          <p className="m-0 mb-2 text-12 text-ink-2">{t('apps.coverageHelp')}</p>
          {app.coverage.length === 0 ? (
            <EmptyState className="p-0 text-left" title={t('apps.coverageEmpty')} />
          ) : (
            <Table aria-label={t('apps.coverage')}>
              <THead>
                <tr>
                  <Th>{t('apps.colAsset')}</Th>
                  <Th>{t('apps.colScanner')}</Th>
                  <Th align="end">{t('apps.colWhen')}</Th>
                </tr>
              </THead>
              <TBody>
                {app.coverage.map((c) => (
                  <Tr key={`${c.asset_id}-${c.scanner}`} className="h-9">
                    <Td className="font-mono text-12" title={c.asset}>{c.asset}</Td>
                    <Td>{c.scanner}</Td>
                    <Td align="end" className="text-ink-2" title={absoluteDate(c.last_scan)}>{shortAge(c.last_scan)}</Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </section>

        <section className="mt-6" aria-labelledby="app-vex">
          <h2 id="app-vex" className="mb-1 text-14 font-semibold">{t('apps.vex')}</h2>
          <p className="m-0 mb-1 text-12 text-ink-2">{t('apps.vexHelp')}</p>
          <p className="m-0 flex gap-4 text-13">
            <a href={`/api/v1/applications/${encodeURIComponent(app.id)}/vex?format=openvex`} download>{t('apps.vexOpen')}</a>
            <a href={`/api/v1/applications/${encodeURIComponent(app.id)}/vex?format=cyclonedx`} download>{t('apps.vexCdx')}</a>
          </p>
        </section>
      </article>
    </div>
  );
}
