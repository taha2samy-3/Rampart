import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { getApplication, getApplicationTrend, qk, toProblem } from '@/api';
import type { ApplicationPage } from '@/api/types';
import { AgeBars, BandBars, BandShape, BandTrendPanels, DeadlineBar, EmptyState, ProblemMessage, Select, Skeleton, Table, TBody, Td, Th, THead, Tr, VelocityBars, toWeeks, Tabs, TabsContent, TabsList, TabsTrigger } from '@/components';
import type { ChartBand } from '@/components';
import { openText } from '@/lib/apps';
import { ChangesSection, FindingDetailModal, type FindingDetailTarget } from './ChangesSection';
import { ComplianceSummary } from './ComplianceSummary';
import { ScanCoverage } from './ScanCoverage';
import { ApplicationSBOMSection } from './ApplicationSBOMSection';
import { ApplicationAttestSection } from './ApplicationAttestSection';
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
  const [selectedFinding, setSelectedFinding] = useState<FindingDetailTarget | null>(null);
  const appQuerySlug = app.slug || `"${app.name}"`;

  const totalOpenFindings = app.open ? app.open.critical + app.open.high + app.open.medium + app.open.low : 0;

  return (
    <div className="h-full overflow-y-auto">
      <article className="mx-auto max-w-[860px] px-6 py-5">
        <Link to="/applications" className="text-13">{t('apps.back')}</Link>
        <div className="mt-2 flex flex-wrap items-baseline justify-between gap-3">
          <div>
            <h1 className="display text-28 leading-tight">{app.name}</h1>
            <p className="mt-1 text-13 text-ink-2">
              {t('apps.criticality', { level: app.business_criticality })}
              {app.internet_facing ? `, ${t('apps.internetFacing')}` : ''}
              {app.last_scan ? `. ${t('apps.colScan')}: ${absoluteDate(app.last_scan)}` : `. ${t('apps.never')}`}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-ctl border border-rule bg-surface px-2.5 py-1 text-12 font-medium text-ink">
              Risk Score: <span className="font-mono font-semibold text-accent">{app.risk_score}</span>
            </span>
            {app.open && (
              <span className="inline-flex items-center gap-1.5 rounded-ctl border border-rule bg-surface px-2.5 py-1 text-12 font-medium text-ink">
                Open Findings: <span className="font-semibold text-critical">{totalOpenFindings}</span>
              </span>
            )}
          </div>
        </div>

        {/* Top-Level Tabs Navigation */}
        <section className="mt-6" aria-labelledby="app-main-tabs">
          <Tabs defaultValue="overview">
            <TabsList label={t('apps.sectionsNav', { defaultValue: 'Application Sections' })}>
              <TabsTrigger value="overview">
                {t('apps.tabOverview', { defaultValue: 'Overview' })}
              </TabsTrigger>
              <TabsTrigger value="cves">
                {t('apps.tabCVEs', { defaultValue: 'CVEs & Activity' })}
              </TabsTrigger>
              <TabsTrigger value="sbom">
                {t('apps.tabSBOM', { defaultValue: 'SBOM & Packages' })}
              </TabsTrigger>
              <TabsTrigger value="attest">
                {t('apps.tabAttest', { defaultValue: 'Compliance Attestations' })}
              </TabsTrigger>
            </TabsList>

            <TabsContent value="overview" forceMount className="mt-4 data-[state=inactive]:hidden focus-visible:outline-none">
              <section className="mt-2" aria-labelledby="app-summary">
                <h2 id="app-summary" className="mb-1 text-14 font-semibold">{t('apps.summary')}</h2>
                <p className="m-0 text-13">
                  <span className="font-medium">{t('apps.openFindings')}: </span>
                  {text || t('apps.noOpen')}.
                </p>
                <p className="m-0 mt-1 text-13 text-ink-2">{t('apps.riskLine', { score: app.risk_score, exposure: app.exposure_count })}</p>
                <Link to="/findings" search={{ q: `app:${appQuerySlug} state:open,under_investigation,affected` }} className="mt-1 inline-block text-13">{t('apps.seeAll')}</Link>
              </section>

              <ComplianceSummary appId={app.id} />

              <RiskOverTime id={app.id} />

              <section className="mt-6" aria-labelledby="app-deadlines">
                <h2 id="app-deadlines" className="mb-1 text-14 font-semibold">{t('apps.deadlines')}</h2>
                <p className="m-0 text-13">
                  {app.sla.adherence === undefined ? t('apps.noDeadlines') : t('apps.adherence', { percent: Math.round(app.sla.adherence * 100) })}
                </p>
                {app.sla.adherence !== undefined && (
                  <div className="mt-2">
                    <DeadlineBar within={app.sla.within} late={app.sla.late} breached={app.sla.breached} />
                  </div>
                )}
              </section>

              <section className="mt-6" aria-labelledby="app-mttr">
                <h2 id="app-mttr" className="mb-1 text-14 font-semibold">{t('apps.mttr')}</h2>
                {app.mttr.length === 0 ? (
                  <p className="m-0 text-13 text-ink-2">{t('apps.mttrEmpty')}</p>
                ) : (
                  <BandBars
                    rows={app.mttr.map((m) => ({ band: m.band as ChartBand, value: m.days }))}
                    unit="days"
                    describe={(r) => {
                      const m = app.mttr.find((x) => x.band === r.band)!;
                      return `${m.days.toFixed(1)} days on average, ${m.fixed} fixed`;
                    }}
                  />
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
                          <Link
                            to="/findings"
                            search={{ q: `app:${appQuerySlug}`, sel: f.id }}
                            onClick={(e) => {
                              e.preventDefault();
                              setSelectedFinding({
                                id: f.id,
                                title: f.title,
                                severity: f.band,
                                risk_score: f.risk_score,
                                state: f.state,
                              });
                            }}
                            className="min-w-0 flex-1 truncate font-medium text-ink no-underline hover:underline"
                          >
                            {f.title}
                          </Link>
                          <span className={due.late ? 'font-semibold' : 'text-ink-2'}>{due.text}</span>
                        </li>
                      );
                    })}
                  </ol>
                )}
              </section>

              {app.scan_coverage && app.scan_coverage.length > 0 && <ScanCoverage rows={app.scan_coverage} />}

              <details className="mt-3">
                <summary id="app-coverage" className="cursor-pointer text-13 text-ink-2">{t('apps.coverage')}</summary>
                <p className="m-0 mb-2 mt-1 text-12 text-ink-2">{t('apps.coverageHelp')}</p>
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
              </details>
            </TabsContent>

            <TabsContent value="cves" forceMount className="mt-4 data-[state=inactive]:hidden focus-visible:outline-none">
              <ChangesSection appId={app.id} onSelectFinding={(f) => setSelectedFinding(f)} />
            </TabsContent>

            <TabsContent value="sbom" forceMount className="mt-4 data-[state=inactive]:hidden focus-visible:outline-none">
              <ApplicationSBOMSection app={app} onSelectFinding={(f) => setSelectedFinding(f)} />
            </TabsContent>

            <TabsContent value="attest" forceMount className="mt-4 data-[state=inactive]:hidden focus-visible:outline-none">
              <ApplicationAttestSection app={app} />
            </TabsContent>
          </Tabs>
        </section>

        {selectedFinding && (
          <FindingDetailModal change={selectedFinding} onClose={() => setSelectedFinding(null)} />
        )}
      </article>
    </div>
  );
}

/**
 * The application over time (D93): open findings by band, what arrived against what was fixed, and how long the
 * open ones have waited. The three answer whether the risk of this application is going down.
 */
function RiskOverTime({ id }: { id: string }) {
  const [days, setDays] = useState(90);
  const q = useQuery({ queryKey: qk.applications.trend(id, days), queryFn: ({ signal }) => getApplicationTrend(id, days, signal), retry: false });
  return (
    <>
      <section className="mt-6" aria-labelledby="app-trend">
        <div className="mb-2 flex items-baseline gap-3">
          <h2 id="app-trend" className="text-14 font-semibold">Open findings over time</h2>
          <Select
            label="Period"
            className="ms-auto"
            value={String(days)}
            onValueChange={(v) => setDays(Number(v))}
            options={[
              { value: '30', label: 'Last 30 days' },
              { value: '90', label: 'Last 90 days' },
              { value: '180', label: 'Last 180 days' },
            ]}
          />
        </div>
        {q.isPending ? (
          <Skeleton className="h-40 w-full" />
        ) : q.isError ? (
          <ProblemMessage problem={toProblem(q.error)} title="The trend could not be read" onRetry={() => void q.refetch()} />
        ) : (
          <>
            <BandTrendPanels points={q.data.points} days={q.data.days} />
            <p className="m-0 mt-1 text-12 text-ink-2">Each finding is counted in the band it has today.</p>
          </>
        )}
      </section>
      {q.isSuccess && (
        <>
          <section className="mt-6" aria-labelledby="app-velocity">
            <h2 id="app-velocity" className="mb-1 text-14 font-semibold">Arriving and fixed</h2>
            <VelocityBars weeks={toWeeks(q.data.points)} />
          </section>
          <section className="mt-6" aria-labelledby="app-age">
            <h2 id="app-age" className="mb-1 text-14 font-semibold">How long open findings have waited</h2>
            <AgeBars aging={q.data.aging} />
          </section>
        </>
      )}
    </>
  );
}
