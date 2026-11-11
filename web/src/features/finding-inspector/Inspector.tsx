import { useTranslation } from 'react-i18next';
import type { FindingRow } from '@/api/types';
import { BAND_LABEL, BandShape, EmptyState, ScoreBar } from '@/components';
import { toBand } from '@/lib/band';
import { absoluteDate, dueShort, relativeDays } from '@/lib/format';
import { factorKind, factorLabel, type SegmentKind } from '@/lib/score';

const SWATCH: Record<SegmentKind, string> = {
  severity: 'bg-[var(--seg-severity)]',
  threat: 'bg-[var(--seg-threat)]',
  context: 'bg-[var(--seg-context)]',
  reduction: 'border-[1.5px] border-[var(--seg-reduction)]',
};

/** Docked inspector: the same score bar at full width, then the ledger of factors. */
export function Inspector({ row, selectedId }: { row: FindingRow | undefined; selectedId?: string }) {
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
    </article>
  );
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
