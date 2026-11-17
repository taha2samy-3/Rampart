import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { get, getApplicationChanges, qk, toProblem } from '@/api';
import type { ApplicationChanges, ChangeDay, FindingChange, FindingRow, Reporter } from '@/api/types';
import {
  BandShape,
  Button,
  Dialog,
  DialogContent,
  Input,
  ProblemMessage,
  Select,
  Skeleton,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components';
import { toBand } from '@/lib/band';
import { absoluteDate, absoluteDateTime } from '@/lib/format';

type Preset = '7' | '30' | '90' | 'custom';

/** A day as YYYY-MM-DD in UTC, `back` days before `now`. */
export const dayString = (now: Date, back = 0) => new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - back)).toISOString().slice(0, 10);

/**
 * What changed in an application between two days: the vulnerabilities that appeared, the ones that were closed and how,
 * the ones that came back, and what was still open at the end, with the numbers of the period before to compare. Snyk
 * calls it "new and resolved issues" and Tenable "discovered and remediated"; the lists are the CVEs themselves.
 */
export function ChangesSection({
  appId,
  now = new Date(),
  onSelectFinding,
}: {
  appId: string;
  now?: Date;
  onSelectFinding?: (f: FindingDetailTarget) => void;
}) {
  const { t } = useTranslation();
  const [preset, setPreset] = useState<Preset>('30');
  const [custom, setCustom] = useState({ from: dayString(now, 29), to: dayString(now) });
  const range = useMemo(() => {
    if (preset === 'custom') return custom;
    return { from: dayString(now, Number(preset) - 1), to: dayString(now) };
  }, [preset, custom, now]);
  const valid = range.from <= range.to;
  const q = useQuery({
    queryKey: qk.applications.changes(appId, range.from, range.to),
    queryFn: ({ signal }) => getApplicationChanges(appId, range, signal),
    enabled: valid,
    retry: false,
  });
  return (
    <section className="mt-6" aria-labelledby="app-changes">
      <div className="mb-1 flex flex-wrap items-baseline gap-3">
        <h2 id="app-changes" className="text-14 font-semibold">{t('apps.changesTitle')}</h2>
        <Select
          label={t('apps.changesRange')}
          className="ms-auto"
          value={preset}
          onValueChange={(v) => setPreset(v as Preset)}
          options={[
            { value: '7', label: t('apps.range7') },
            { value: '30', label: t('apps.range30') },
            { value: '90', label: t('apps.range90') },
            { value: 'custom', label: t('apps.rangeCustom') },
          ]}
        />
      </div>
      <p className="m-0 mb-2 text-12 text-ink-2">{t('apps.changesHelp')}</p>
      {preset === 'custom' && (
        <div className="mb-3 flex flex-wrap items-end gap-3">
          <label className="text-12">
            <span className="mb-1 block font-medium">{t('apps.changesFrom')}</span>
            <Input type="date" value={custom.from} max={custom.to} onChange={(e) => setCustom({ ...custom, from: e.target.value })} />
          </label>
          <label className="text-12">
            <span className="mb-1 block font-medium">{t('apps.changesTo')}</span>
            <Input type="date" value={custom.to} min={custom.from} max={dayString(now)} onChange={(e) => setCustom({ ...custom, to: e.target.value })} />
          </label>
        </div>
      )}
      {q.isPending && valid && <Skeleton className="h-32 w-full" />}
      {q.isError && <ProblemMessage problem={toProblem(q.error)} title={t('apps.changesFailed')} onRetry={() => void q.refetch()} />}
      {q.data && <Body data={q.data} onSelectFinding={onSelectFinding} />}
    </section>
  );
}

function Body({
  data,
  onSelectFinding,
}: {
  data: ApplicationChanges;
  onSelectFinding?: (f: FindingDetailTarget) => void;
}) {
  const { t } = useTranslation();
  const s = data.summary;
  const [selectedChange, setSelectedChange] = useState<FindingChange | null>(null);
  const handleSelect = onSelectFinding ?? setSelectedChange;

  return (
    <>
      <p className="m-0 text-13">
        {t('apps.changesSummary', { new: s.new, prevNew: s.previous.new, closed: s.closed, prevClosed: s.previous.closed, reopened: s.reopened, start: s.open_at_start, end: s.open_at_end })}
      </p>
      <ChangeBars days={data.daily} label={t('apps.changesChartLabel', { new: s.new, closed: s.closed, days: data.days })} />
      <p className="m-0 mt-0.5 text-11 text-ink-2">{t('apps.changesChart')}</p>
      <Tabs defaultValue="new" className="mt-3">
        <TabsList label={t('apps.changesTitle')}>
          <TabsTrigger value="new">{t('apps.tabNew')} ({s.new})</TabsTrigger>
          <TabsTrigger value="closed">{t('apps.tabClosed')} ({s.closed})</TabsTrigger>
          <TabsTrigger value="reopened">{t('apps.tabReopened')} ({s.reopened})</TabsTrigger>
          <TabsTrigger value="open">{t('apps.tabOpen')} ({s.open_at_end})</TabsTrigger>
        </TabsList>
        <TabsContent value="new"><List rows={data.new} kind="new" cut={data.truncated.includes('new')} onSelect={handleSelect} /></TabsContent>
        <TabsContent value="closed"><List rows={data.closed} kind="closed" cut={data.truncated.includes('closed')} onSelect={handleSelect} /></TabsContent>
        <TabsContent value="reopened"><List rows={data.reopened} kind="reopened" cut={data.truncated.includes('reopened')} onSelect={handleSelect} /></TabsContent>
        <TabsContent value="open"><List rows={data.open} kind="open" cut={data.truncated.includes('open')} onSelect={handleSelect} /></TabsContent>
      </Tabs>

      {!onSelectFinding && selectedChange && (
        <FindingDetailModal change={selectedChange} onClose={() => setSelectedChange(null)} />
      )}
    </>
  );
}

/** One bar for each day: what came above the line, what was closed below it. Flat, two colours, no axis labels to read. */
export function ChangeBars({ days, label }: { days: ChangeDay[]; label: string }) {
  const max = Math.max(1, ...days.map((d) => Math.max(d.new, d.closed)));
  const W = 600;
  const H = 72;
  const mid = H / 2;
  const step = W / Math.max(days.length, 1);
  const bar = Math.max(1, Math.min(14, step - 1));
  return (
    <figure className="m-0 mt-2" role="img" aria-label={label}>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-[72px] w-full" preserveAspectRatio="none" aria-hidden="true">
        <line x1="0" x2={W} y1={mid} y2={mid} stroke="var(--rule)" strokeWidth="1" vectorEffect="non-scaling-stroke" />
        {days.map((d, i) => {
          const x = i * step + (step - bar) / 2;
          const up = (d.new / max) * (mid - 2);
          const down = (d.closed / max) * (mid - 2);
          return (
            <g key={d.day}>
              <title>{`${d.day}: ${d.new} new, ${d.closed} closed`}</title>
              {d.new > 0 && <rect x={x} y={mid - up} width={bar} height={up} fill="var(--seg-threat)" />}
              {d.closed > 0 && <rect x={x} y={mid} width={bar} height={down} fill="var(--resolved)" />}
            </g>
          );
        })}
      </svg>
    </figure>
  );
}

function List({
  rows,
  kind,
  cut,
  onSelect,
}: {
  rows: FindingChange[];
  kind: 'new' | 'closed' | 'reopened' | 'open';
  cut: boolean;
  onSelect: (f: FindingChange) => void;
}) {
  const { t } = useTranslation();
  if (rows.length === 0) return <p className="m-0 mt-2 text-13 text-ink-2">{t('apps.changesNone')}</p>;
  const when = kind === 'closed' ? t('apps.colClosed') : kind === 'reopened' ? t('apps.colBack') : t('apps.colSeen');
  return (
    <>
      <Table aria-label={`${t('apps.changesTitle')}: ${kind}`}>
        <THead>
          <tr>
            <Th>{t('apps.colVuln')}</Th>
            <Th>{t('apps.colSeverity')}</Th>
            <Th>{t('apps.colAsset')}</Th>
            <Th>{when}</Th>
            {kind === 'closed' && <Th>{t('apps.colHow')}</Th>}
          </tr>
        </THead>
        <TBody>
          {rows.map((r) => (
            <Tr
              key={`${r.id}-${kind}`}
              className="h-9 cursor-pointer transition-colors hover:bg-surface-2"
              onClick={() => onSelect(r)}
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onSelect(r);
                }
              }}
            >
              <Td>
                <Link
                  to="/findings"
                  search={{
                    q: r.vulnerability_id ? `cve:${r.vulnerability_id}` : `rule:${r.rule_id}`,
                    sel: r.id,
                  }}
                  onClick={(e) => {
                    e.preventDefault();
                    onSelect(r);
                  }}
                  className="font-mono text-12 font-medium no-underline hover:underline"
                >
                  {r.vulnerability_id || r.rule_id}
                </Link>
                <span className="block max-w-[34rem] truncate text-12 text-ink-2" title={r.title}>{r.title}</span>
              </Td>
              <Td>
                <span className="inline-flex items-center gap-1.5 text-12">
                  <BandShape band={toBand(r.risk_band)} size={11} />
                  {r.severity}
                </span>
              </Td>
              <Td className="max-w-[14rem] truncate text-12 text-ink-2" title={r.asset}>{r.asset}</Td>
              <Td className="text-12 text-ink-2">{absoluteDate(kind === 'closed' ? r.resolved_at : kind === 'reopened' ? r.at : r.first_seen)}</Td>
              {kind === 'closed' && <Td className="text-12">{t(`apps.how_${r.resolution}`, { defaultValue: r.resolution || r.state })}</Td>}
            </Tr>
          ))}
        </TBody>
      </Table>
      {cut && <p className="m-0 mt-1 text-12 text-ink-2">{t('apps.changesCut', { count: rows.length })}</p>}
    </>
  );
}

export interface FindingDetailTarget {
  id: string;
  vulnerability_id?: string | null;
  rule_id?: string;
  title?: string;
  severity?: string;
  risk_band?: string;
  risk_score?: number;
  state?: string;
  asset?: string;
  first_seen?: string;
  resolved_at?: string | null;
  resolution?: string;
}

export interface FindingDetailData extends FindingRow {
  reported_by?: Reporter[] | null;
  occurrences?: Array<{ scanner?: string }> | null;
}

export function FindingDetailModal({ change, onClose }: { change: FindingDetailTarget; onClose: () => void }) {
  const q = useQuery({
    queryKey: ['findings', 'detail', change.id],
    queryFn: ({ signal }) => get<FindingDetailData>(`/api/v1/findings/${encodeURIComponent(change.id)}`, { signal }),
    enabled: !!change.id,
    retry: false,
  });

  const row = q.data;
  const f = row?.finding;
  const loc = f?.location;
  const where = loc?.purl ?? (loc?.file_path ? (loc.start_line ? `${loc.file_path}:${loc.start_line}` : loc.file_path) : '');
  const reporters: Reporter[] = row?.reported_by ?? [];
  const occurrences = row?.occurrences ?? [];

  const vulnId = change.vulnerability_id || f?.vulnerability_id;
  const ruleId = change.rule_id || f?.rule_id;
  const targetQuery = vulnId ? `cve:${vulnId}` : (ruleId ? `rule:${ruleId}` : (change.asset ? `app:${change.asset}` : ''));

  return (
    <Dialog open={true} onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        title={vulnId || ruleId || 'Finding Details'}
        description={change.title || f?.title || 'Security vulnerability details and provenance'}
        className="w-[700px] max-w-[95vw]"
      >
        <div className="flex flex-col gap-4">
          {/* Header Badges */}
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-3">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded bg-surface-2 px-2.5 py-1 text-12 font-medium">
                <BandShape band={toBand(change.risk_band || f?.severity)} size={12} />
                <span className="capitalize">{change.severity || f?.severity || 'medium'}</span>
              </span>
              <span className="rounded bg-surface-2 px-2 py-0.5 text-11 font-mono uppercase text-ink-2">
                {change.state || f?.state || 'open'}
              </span>
              {vulnId && (
                <span className="rounded border border-border bg-surface px-2 py-0.5 text-11 font-mono text-accent">
                  {vulnId}
                </span>
              )}
            </div>
            {(row?.risk || change.risk_score !== undefined) && (
              <span className="text-12 font-semibold">
                Risk Score: <span className="font-mono text-14">{row?.risk?.total_score ?? change.risk_score}</span>
              </span>
            )}
          </div>

          {/* Where it came from & where it was found */}
          <div className="rounded-md border border-border bg-surface-2 p-3 text-13">
            <h4 className="mb-2 text-12 font-semibold uppercase tracking-wider text-ink-2">
              Source & Location Details
            </h4>
            <dl className="grid grid-cols-[140px_1fr] gap-x-3 gap-y-2 text-12">
              <dt className="text-ink-2">Asset / Service:</dt>
              <dd className="font-mono font-medium text-ink">{change.asset || 'default-repository'}</dd>

              <dt className="text-ink-2">Location / Path:</dt>
              <dd className="break-all font-mono text-ink">
                {where || 'Repository root / package manifest'}
              </dd>

              {loc?.component_name && (
                <>
                  <dt className="text-ink-2">Component:</dt>
                  <dd className="font-mono text-ink">
                    {loc.component_name}
                    {loc.installed_version ? ` @ ${loc.installed_version}` : ''}
                    {loc.fixed_version ? ` (Fixed in ${loc.fixed_version})` : ''}
                  </dd>
                </>
              )}

              <dt className="text-ink-2">Detected By:</dt>
              <dd className="text-ink">
                {reporters.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {reporters.map((rep) => (
                      <span key={rep.name || rep.scanner} className="rounded border border-border bg-surface px-1.5 py-0.5 text-11 font-medium">
                        {rep.name || rep.scanner} {rep.present ? '(Active)' : '(Past)'}
                      </span>
                    ))}
                  </div>
                ) : occurrences.length > 0 ? (
                  <span>{occurrences.map((o) => o.scanner).filter(Boolean).join(', ')}</span>
                ) : (
                  <span>Automated CI/CD Scanner</span>
                )}
              </dd>

              <dt className="text-ink-2">First Seen:</dt>
              <dd className="text-ink">{absoluteDateTime(change.first_seen || f?.first_seen)}</dd>

              {change.resolved_at && (
                <>
                  <dt className="text-ink-2">Resolved At:</dt>
                  <dd className="text-ink">{absoluteDateTime(change.resolved_at)}</dd>
                </>
              )}

              {change.resolution && (
                <>
                  <dt className="text-ink-2">Resolution:</dt>
                  <dd className="capitalize text-ink">{change.resolution}</dd>
                </>
              )}

              {/* External Advisory References */}
              {vulnId && (
                <>
                  <dt className="text-ink-2">Security Advisories:</dt>
                  <dd className="flex flex-wrap gap-2 text-ink">
                    {vulnId.startsWith('CVE-') && (
                      <>
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vulnId)}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-accent underline hover:opacity-80"
                        >
                          NVD NIST Advisory ↗
                        </a>
                        <a
                          href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${encodeURIComponent(vulnId)}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-accent underline hover:opacity-80"
                        >
                          MITRE CVE ↗
                        </a>
                      </>
                    )}
                    {vulnId.startsWith('GHSA-') && (
                      <a
                        href={`https://github.com/advisories/${encodeURIComponent(vulnId)}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-accent underline hover:opacity-80"
                      >
                        GitHub Advisory Database ↗
                      </a>
                    )}
                  </dd>
                </>
              )}
            </dl>
          </div>

          {/* Description if available */}
          {(f?.description || change.title) && (
            <div className="text-12">
              <h4 className="mb-1 text-12 font-semibold uppercase tracking-wider text-ink-2">
                Description & Impact
              </h4>
              <p className="max-h-36 overflow-auto whitespace-pre-wrap rounded border border-border bg-surface p-2.5 text-ink-2">
                {f?.description || change.title}
              </p>
            </div>
          )}

          {/* Actions Footer */}
          <div className="mt-1 flex items-center justify-between border-t border-border pt-3">
            <Link
              to="/findings"
              search={{
                q: targetQuery || undefined,
                sel: change.id,
              }}
              onClick={onClose}
              className="inline-flex items-center gap-1.5 text-13 font-semibold text-accent hover:underline"
            >
              Open in Findings Explorer →
            </Link>
            <Button variant="secondary" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
