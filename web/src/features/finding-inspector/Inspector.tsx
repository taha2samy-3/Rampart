import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Link } from '@tanstack/react-router';
import { getAcceptance, getFindingEvents, getFindingSources, qk, toProblem } from '@/api';
import type { FindingEvent, FindingRow } from '@/api/types';
import { BAND_LABEL, BandShape, Button, EmptyState, Kbd, ProblemMessage, ScoreBar } from '@/components';
import { toBand } from '@/lib/band';
import { absoluteDate, dueShort, relativeDays, shortAge } from '@/lib/format';
import { factorKind, factorLabel, type SegmentKind } from '@/lib/score';

const SWATCH: Record<SegmentKind, string> = {
  severity: 'bg-[var(--seg-severity)]',
  threat: 'bg-[var(--seg-threat)]',
  context: 'bg-[var(--seg-context)]',
  reduction: 'border-[1.5px] border-[var(--seg-reduction)]',
};

/** Docked inspector: the same score bar at full width, then the ledger of factors. */
export function Inspector({ row, selectedId, onTriage, onAccept }: { row: FindingRow | undefined; selectedId?: string; onTriage?: () => void; onAccept?: () => void }) {
  const { t } = useTranslation();
  if (!row && selectedId) return <EmptyState title={t('findings.selectTitle')}>{t('findings.inspectorMissing')}</EmptyState>;
  if (!row) return <EmptyState title={t('findings.selectTitle')}>{t('findings.selectBody')}</EmptyState>;

  const f = row.finding;
  const score = row.risk?.total_score ?? f.risk_score;
  const band = toBand(row.risk?.band ?? f.severity);
  const due = dueShort(row.sla_due_date);
  const dueText = row.sla_due_date ? (due.late ? `overdue by ${due.text.replace(' late', '')}` : `due ${relativeDays(row.sla_due_date)}`) : t('findings.noDue').toLowerCase();
  const status = t('findings.statusLine', { state: t(`state.${f.state}`, { defaultValue: f.state }), band: BAND_LABEL[band].toLowerCase(), due: dueText });
  const factors = row.risk?.factors ?? [];
  const loc = f.location;
  const where = loc?.purl ?? (loc?.file_path ? (loc.start_line ? `${loc.file_path}:${loc.start_line}` : loc.file_path) : '');

  return (
    <article aria-label={t('findings.inspector')} className="px-4 py-3">
      <h2 className="display text-16 leading-snug [overflow-wrap:anywhere]">{f.title}</h2>
      <p className="mt-1 text-13 text-ink-2">{status}</p>
      {onTriage && (
        <div className="mt-3 flex items-center gap-2">
          <Button onClick={onTriage}>{t('triage.action')}</Button>
          <span className="text-12 text-ink-2" aria-hidden="true"><Kbd>s</Kbd></span>
          {onAccept && ['open', 'under_investigation', 'affected'].includes(f.state) && (
            <>
              <Button onClick={onAccept}>{t('acceptance.action')}</Button>
              <span className="text-12 text-ink-2" aria-hidden="true"><Kbd>e</Kbd></span>
            </>
          )}
        </div>
      )}
      {f.risk_acceptance_id && <AcceptedLine id={f.risk_acceptance_id} />}
      {(f.justification || f.impact_statement || f.state_reason) && (
        <dl className="m-0 mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-13">
          {f.justification && <Fact label={t('triage.justifiedAs')} value={t(`triage.justifications.${f.justification}`, { defaultValue: f.justification })} />}
          {f.impact_statement && <Fact label={t('triage.impactLabel')} value={f.impact_statement} />}
          {f.state_reason && <Fact label={t('triage.reasonLabel')} value={f.state_reason} />}
        </dl>
      )}

      <section className="mt-4" aria-labelledby="why-score">
        <div className="mb-1.5 flex items-baseline gap-2">
          <BandShape band={band} size={14} />
          <span className="text-28 font-semibold leading-none tnum">{score}</span>
          <h3 id="why-score" className="text-13 font-semibold">{t('findings.whyScore')}</h3>
        </div>
        <ScoreBar breakdown={row.risk} score={score} size="full" />
        <ul className="m-0 mt-3 list-none p-0 text-13">
          <li className="flex items-center gap-2 border-b border-rule py-1.5">
            <span className={`size-2.5 shrink-0 ${SWATCH.severity}`} aria-hidden="true" />
            <span className="flex-1">{t('findings.legendSeverity')}</span>
            <span className="tnum text-ink-2">{t('findings.points', { points: row.risk?.base_points ?? 0 })}</span>
          </li>
          {factors.map((fa) => {
            const kind = factorKind(fa.name, fa.points);
            return (
              <li key={fa.name} className="border-b border-rule py-1.5">
                <div className="flex items-center gap-2">
                  <span className={`size-2.5 shrink-0 ${SWATCH[kind]}`} aria-hidden="true" />
                  <span className="flex-1 font-medium">{factorLabel(fa.name)}</span>
                  <span className="tnum text-ink-2">
                    {fa.points < 0 ? t('findings.pointsRemoved', { points: -fa.points }) : t('findings.points', { points: fa.points })}
                  </span>
                </div>
                {fa.reason && <p className="ms-[18px] text-12 text-ink-2">{fa.reason}</p>}
              </li>
            );
          })}
        </ul>
        {factors.length === 0 && <p className="mt-2 text-12 text-ink-2">{t('findings.noFactors')}</p>}
      </section>

      <section className="mt-5" aria-labelledby="facts">
        <h3 id="facts" className="mb-1 text-13 font-semibold">{t('findings.facts')}</h3>
        <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-13">
          <Fact label={t('findings.detectedBy')} value={f.rule_scanner_family} />
          <Fact label={t('findings.rule')} value={f.rule_id} mono />
          <Fact label={t('findings.location')} value={where} mono />
          <Fact label={t('findings.firstSeen')} value={absoluteDate(f.first_seen)} />
          <Fact label={t('findings.lastSeen')} value={absoluteDate(f.last_seen)} />
        </dl>
      </section>

      <ReportedBy findingId={f.id} version={f.version} />

      <Timeline findingId={f.id} version={f.version} />
    </article>
  );
}

/** While a finding is risk_accepted: until when, and who owns the decision. */
function AcceptedLine({ id }: { id: string }) {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: qk.acceptances.one(id), queryFn: ({ signal }) => getAcceptance(id, signal), retry: false });
  if (!q.data) return null;
  return (
    <p className="m-0 mt-3 text-13">
      <span className="font-semibold">{t('acceptance.accepted', { date: absoluteDate(q.data.expires_at) })}.</span>{' '}
      {t('acceptance.acceptedBy', { owner: q.data.owner.replace(/^user:/, ''), why: q.data.justification })}
    </p>
  );
}

/** Who did what to this finding, oldest first. Reloads when the finding's version changes. */
function Timeline({ findingId, version }: { findingId: string; version?: number }) {
  const { t } = useTranslation();
  const q = useQuery({
    queryKey: [...qk.findings.events(findingId), version],
    queryFn: ({ signal }) => getFindingEvents(findingId, signal),
    retry: false,
  });
  return (
    <section className="mt-5" aria-labelledby="timeline">
      <h3 id="timeline" className="mb-1 text-13 font-semibold">{t('triage.timeline')}</h3>
      {q.isPending && <p className="m-0 text-12 text-ink-2">{t('common.loading')}</p>}
      {q.isError && <ProblemMessage problem={toProblem(q.error)} title={t('triage.timelineFailed')} onRetry={() => void q.refetch()} />}
      {q.data && q.data.length === 0 && <p className="m-0 text-12 text-ink-2">{t('triage.timelineEmpty')}</p>}
      {q.data && q.data.length > 0 && (
        <ol className="m-0 list-none p-0 text-13">
          {q.data.map((e) => (
            <li key={e.id} className="border-b border-rule py-1.5">
              <p className="m-0">{describe(e, t)}</p>
              <p className="m-0 text-12 text-ink-2">
                <time dateTime={e.at} title={absoluteDate(e.at)}>{shortAge(e.at)}</time>
                {e.note ? ` - ${e.note}` : ''}
              </p>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function describe(e: FindingEvent, t: TFunction): string {
  const actor = e.actor.startsWith('user:') ? e.actor.slice(5) : e.actor.startsWith('system') ? t('triage.scanActor') : e.actor;
  const str = (v: unknown) => (typeof v === 'string' ? v : Array.isArray(v) ? v.join(', ') : '');
  const known = ['created', 'reactivated', 'closed_by_rescan', 'updated', 'recheck_needed', 'state_changed', 'severity_changed', 'tags_changed', 'note_added',
    'risk_acceptance_requested', 'risk_acceptance_approved', 'risk_acceptance_rejected', 'risk_acceptance_revoked', 'risk_acceptance_expired', 'no_longer_detected'];
  const key = known.includes(e.type) ? e.type : 'default';
  const from = e.type === 'state_changed' ? t(`state.${str(e.from)}`, { defaultValue: str(e.from) }) : str(e.from);
  const to = e.type === 'state_changed' ? t(`state.${str(e.to)}`, { defaultValue: str(e.to) }) : str(e.to);
  return t(`triage.events.${key}`, { actor, from, to, type: e.type });
}

function Fact({ label, value, mono }: { label: string; value: string | undefined; mono?: boolean }) {
  if (!value) return null;
  return (
    <>
      <dt className="text-ink-2">{label}</dt>
      <dd className={`m-0 min-w-0 [overflow-wrap:anywhere] ${mono ? 'font-mono text-12' : ''}`}>{value}</dd>
    </>
  );
}

const TOOL_NAME: Record<string, string> = { trivy: 'Trivy', grype: 'Grype', semgrep: 'Semgrep', gitleaks: 'Gitleaks', trufflehog: 'TruffleHog' };
const toolName = (family: string) => TOOL_NAME[family] ?? family;

/**
 * Which tools reported this finding, when each first and last did, and whether each still does; then the same
 * issue as found by other tools. Written as sentences, oldest report first: "found by Trivy, later by Grype".
 */
function ReportedBy({ findingId, version }: { findingId: string; version?: number }) {
  const { t } = useTranslation();
  const q = useQuery({
    queryKey: [...qk.findings.sources(findingId), version],
    queryFn: ({ signal }) => getFindingSources(findingId, signal),
    retry: false,
  });
  const own = q.data?.reported_by ?? [];
  const others = q.data?.also_reported_by ?? [];
  return (
    <section className="mt-5" aria-labelledby="reported-by">
      <h3 id="reported-by" className="mb-1 text-13 font-semibold">{t('reportedBy.title')}</h3>
      {q.isPending && <p className="m-0 text-12 text-ink-2">{t('common.loading')}</p>}
      {q.isError && <ProblemMessage problem={toProblem(q.error)} title={t('reportedBy.failed')} onRetry={() => void q.refetch()} />}
      {q.data && own.length === 0 && others.length === 0 && <p className="m-0 text-12 text-ink-2">{t('reportedBy.none')}</p>}
      {(own.length > 0 || others.length > 0) && (
        <ul className="m-0 list-none p-0 text-13">
          {own.map((r) => (
            <li key={r.scanner} className="border-b border-rule py-1.5">
              <p className="m-0">
                <span className="font-semibold">{toolName(r.scanner)}</span>
                {r.version ? <span className="text-ink-2"> {r.version}</span> : null}
                {' '}{r.present ? t('reportedBy.stillReports') : t('reportedBy.stopped')}
              </p>
              <p className="m-0 text-12 text-ink-2">
                {t('reportedBy.span', { first: absoluteDate(r.first_seen), last: absoluteDate(r.last_seen), count: r.reports })}
                {r.tool_severity ? ` ${t('reportedBy.toolSaid', { severity: r.tool_severity })}` : ''}
              </p>
            </li>
          ))}
          {others.map((o) => (
            <li key={o.id} className="border-b border-rule py-1.5">
              <p className="m-0">
                <span className="font-semibold">{toolName(o.scanner)}</span>{' '}
                {t('reportedBy.alsoFound', { state: t(`state.${o.state}`, { defaultValue: o.state }).toLowerCase() })}{' '}
                <Link to="/findings" search={{ sel: o.id }} className="text-13">{t('reportedBy.open')}</Link>
              </p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
