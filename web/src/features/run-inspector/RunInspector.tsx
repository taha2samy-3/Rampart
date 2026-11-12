import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getRun, qk } from '@/api';
import type { RunRow, RunStatus } from '@/api/types';
import { EmptyState } from '@/components';
import { absoluteDate } from '@/lib/format';
import { useAccess } from '@/app/useAccess';

/** The steps of one run, in order (docs/16: queued, parsing, merging, enriching, scoring, completed). */
const STEPS: RunStatus[] = ['queued', 'parsing', 'merging', 'enriching', 'scoring', 'completed'];
const TERMINAL = new Set<RunStatus>(['completed', 'completed_with_errors', 'failed', 'stale']);

function stepIndex(status: RunStatus): number {
  if (status === 'completed_with_errors') return STEPS.indexOf('completed');
  return STEPS.indexOf(status);
}

/** Docked detail for one ingest run: how far it got, what it did, where it came from, what went wrong. */
export function RunInspector({ run, selectedId }: { run: RunRow | undefined; selectedId?: string }) {
  const { t } = useTranslation();
  const { canAnywhere } = useAccess();
  // The list does not carry the unreadable records; the run asks for them when it has any.
  const detail = useQuery({ queryKey: qk.runs.one(run?.id ?? ''), queryFn: ({ signal }) => getRun(run!.id, signal), enabled: !!run && run.stats.record_errors > 0, retry: false });
  if (!run && selectedId) return <EmptyState title={t('ingestion.selectTitle')}>{t('ingestion.missing')}</EmptyState>;
  if (!run) return <EmptyState title={t('ingestion.selectTitle')}>{t('ingestion.selectBody')}</EmptyState>;

  const done = TERMINAL.has(run.status);
  const reached = stepIndex(run.status);
  const failed = run.status === 'failed' || run.status === 'stale';
  const st = run.stats;
  const ctx = run.context;
  const stats: [string, number][] = [
    [t('ingestion.statParsed'), st.parsed],
    [t('ingestion.statCreated'), st.created],
    [t('ingestion.statUpdated'), st.updated],
    [t('ingestion.statUntouched'), st.untouched],
    [t('ingestion.statReactivated'), st.reactivated],
    [t('ingestion.statClosed'), st.closed],
    [t('ingestion.statErrors'), st.record_errors],
    [t('ingestion.statWeak'), st.weak_fingerprints],
  ];

  return (
    <article aria-label={t('ingestion.inspector')} className="px-4 py-3">
      <h2 className="display text-16 leading-snug [overflow-wrap:anywhere]">
        {run.scanners.join(', ') || run.scanner_family || run.format}
      </h2>
      <p className="mt-1 text-13 text-ink-2">{t(`ingestion.summary.${run.status}`)}</p>
      {run.ephemeral && <p className="mt-2 text-13">{t('ingestion.ephemeralNote')}</p>}

      {run.error && (
        <section className="mt-4" aria-labelledby="run-error">
          <h3 id="run-error" className="mb-1 text-13 font-semibold">{t('ingestion.error')}</h3>
          <p className="m-0 text-13">{t(`ingestion.errors.${run.error}`, { defaultValue: t('ingestion.errors.default') })}</p>
          <p className="m-0 mt-1 font-mono text-12 text-ink-2">{run.error}</p>
        </section>
      )}

      {run.stats.record_errors > 0 && (
        <section className="mt-4" aria-labelledby="run-unread">
          <h3 id="run-unread" className="mb-1 text-13 font-semibold">{t('ingestion.unreadRecords')}</h3>
          <ul className="m-0 list-none p-0 text-13">
            {(detail.data?.record_error_list ?? []).map((e, i) => (
              <li key={i} className="border-b border-rule py-1.5">
                <span className="font-mono text-12">{e.where}</span>
                <span className="block text-12 text-ink-2 [overflow-wrap:anywhere]">{e.message}</span>
              </li>
            ))}
          </ul>
          {run.stats.record_errors > (detail.data?.record_error_list?.length ?? 0) && detail.data && (
            <p className="m-0 mt-1 text-12 text-ink-2">{t('ingestion.unreadMore', { count: detail.data.record_error_list?.length ?? 0 })}</p>
          )}
        </section>
      )}

      <section className="mt-5" aria-labelledby="run-progress">
        <h3 id="run-progress" className="mb-1 text-13 font-semibold">{t('ingestion.timeline')}</h3>
        <ol className="m-0 list-none p-0 text-13">
          {STEPS.map((step, i) => {
            const isNow = !done && i === reached;
            const isDone = done ? !failed && i <= reached : i < reached;
            return (
              <li
                key={step}
                aria-current={isNow ? 'step' : undefined}
                className={`flex items-center gap-2 border-b border-rule py-1.5 ${isNow ? 'font-semibold' : isDone ? '' : 'text-ink-2'}`}
              >
                <span className="w-4 shrink-0 text-center" aria-hidden="true">{isDone ? '✓' : isNow ? '›' : ''}</span>
                <span>{t(`ingestion.status.${step}`)}</span>
              </li>
            );
          })}
        </ol>
        {failed && (
          <p className="m-0 mt-2 text-13 font-semibold">{t(`ingestion.status.${run.status}`)}</p>
        )}
        {run.status === 'completed_with_errors' && (
          <p className="m-0 mt-2 text-13 font-semibold">{t('ingestion.status.completed_with_errors')}</p>
        )}
      </section>

      <section className="mt-5" aria-labelledby="run-stats">
        <h3 id="run-stats" className="mb-1 text-13 font-semibold">{t('ingestion.stats')}</h3>
        <dl className="m-0 grid grid-cols-[1fr_auto] gap-x-4 gap-y-1 text-13">
          {stats.map(([label, value]) => (
            <Row key={label} label={label} value={String(value)} num />
          ))}
        </dl>
      </section>

      <section className="mt-5" aria-labelledby="run-context">
        <h3 id="run-context" className="mb-1 text-13 font-semibold">{t('ingestion.context')}</h3>
        <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-13">
          <Row label={t('ingestion.repository')} value={ctx.repository} mono />
          <Row label={t('ingestion.branch')} value={ctx.branch ?? run.track} mono />
          <Row label={t('ingestion.commit')} value={ctx.commit} mono />
          <Row label={t('ingestion.image')} value={ctx.image_ref ?? ctx.image_digest} mono />
          <Row label={t('ingestion.environment')} value={ctx.environment} />
          <Row label={t('ingestion.build')} value={ctx.build_id} />
          <Row label={t('ingestion.pipeline')} value={ctx.pipeline_url} mono />
          <Row label={t('ingestion.colWhen')} value={absoluteDate(run.created_at)} />
        </dl>
      </section>

      {run.has_report && canAnywhere('maintainer') && (
        <p className="m-0 mt-5 text-13">
          <a href={`/api/v1/runs/${encodeURIComponent(run.id)}/report`} download>{t('ingestion.rawReport')}</a>
          <span className="mt-0.5 block text-12 text-ink-2">{t('ingestion.rawReportHelp')}</span>
        </p>
      )}
    </article>
  );
}

function Row({ label, value, mono, num }: { label: string; value: string | undefined; mono?: boolean; num?: boolean }) {
  if (!value) return null;
  return (
    <>
      <dt className="text-ink-2">{label}</dt>
      <dd className={`m-0 min-w-0 [overflow-wrap:anywhere] ${mono ? 'font-mono text-12' : ''} ${num ? 'text-end tnum' : ''}`}>{value}</dd>
    </>
  );
}
