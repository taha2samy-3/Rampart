import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { listTrackerEvents, qk, toProblem } from '@/api';
import type { TrackerContainerItem, TrackerEvent, TrackerTestResult } from '@/api/types';
import { Button, ProblemMessage, Spinner } from '@/components';
import { IconWarning } from '@/components/icons';
import { cn } from '@/lib/cn';
import { absoluteDateTime } from '@/lib/format';

function Row({ label, children, stacked }: { label: string; children: React.ReactNode; stacked?: boolean }) {
  return (
    <div className={stacked ? 'flex flex-col' : 'flex gap-3'}>
      <dt className={stacked ? 'text-ink-2' : 'w-32 shrink-0 text-ink-2'}>{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

function Outcome({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return (
    <span className={cn('inline-flex items-start gap-1.5', !ok && 'text-critical')}>
      {!ok && <IconWarning className="mt-0.5 size-3.5 shrink-0" />}
      <span className="break-words">{children}</span>
    </span>
  );
}

function eventLabel(e: Pick<TrackerEvent, 'event' | 'outcome'>): string {
  if (e.outcome === 'succeeded') return e.event === 'test' ? 'Probe succeeded' : 'Check succeeded';
  return e.event === 'test' ? 'Probe failed' : 'Check failed';
}

export function TrackerInspector({
  tracker,
  mayManage,
  testing,
  result,
  testError,
  onTest,
}: {
  tracker: TrackerContainerItem | null;
  mayManage: boolean;
  testing: boolean;
  result?: TrackerTestResult;
  testError?: string | null;
  onTest: (item: TrackerContainerItem) => void;
}) {
  const { t } = useTranslation();
  const events = useQuery({
    queryKey: qk.trackers.events(tracker ?? { scope: '', name: '' }),
    queryFn: ({ signal }) => listTrackerEvents(tracker as TrackerContainerItem, signal),
    enabled: !!tracker,
  });

  if (!tracker) {
    return <p className="p-4 text-13 text-ink-2">{t('ticketing.inspectorEmpty')}</p>;
  }

  const capabilities = result?.capabilities ?? (tracker.last_event?.detail?.capabilities ? tracker.last_event.detail.capabilities.split(',').filter(Boolean) : []);

  return (
    <div className="space-y-5 p-4 text-13">
      <header>
        <h2 className="text-14 font-semibold break-words">{tracker.name}</h2>
        <p className="mt-0.5 text-ink-2">
          {t(`ticketing.scope_${tracker.scope}`, { defaultValue: tracker.scope })}
          {tracker.namespace ? ` · ${tracker.namespace}` : ''}
        </p>
      </header>

      {tracker.state === 'refused' && tracker.reason && (
        <section aria-labelledby="tr-refused">
          <h3 id="tr-refused" className="font-semibold">Refused by server</h3>
          <p className="mt-1 break-words text-critical">{tracker.reason}</p>
        </section>
      )}
      {tracker.state === 'disabled' && <p className="text-ink-2">This tracker resource is disabled and will not serve bindings.</p>}

      <section aria-labelledby="tr-setup">
        <h3 id="tr-setup" className="font-semibold">Configuration</h3>
        <dl className="mt-1.5 space-y-1.5">
          {tracker.target && (
            <Row label="Endpoint" stacked>
              <span className="font-mono text-12">{tracker.target}</span>
            </Row>
          )}
          <Row label="Protocol"><span className="font-mono text-12">{tracker.protocol}</span></Row>
          <Row label="Transport">{tracker.tls === 'tls' ? 'Encrypted (TLS)' : 'Plaintext (cluster network)'}</Row>
          <Row label="Timeout">{tracker.timeout_seconds}s</Row>
          <Row label="Bindings">{tracker.bound_connectors}</Row>
          {capabilities.length > 0 && (
            <Row label="Capabilities" stacked>
              <span className="font-mono text-12">{capabilities.join(', ')}</span>
            </Row>
          )}
        </dl>
      </section>

      <div className="flex flex-wrap items-center gap-2">
        <Button variant="primary" onClick={() => onTest(tracker)} disabled={!mayManage || testing} loading={testing}>
          {testing ? t('ticketing.testing') : t('ticketing.testButton')}
        </Button>
        {!mayManage && <span className="text-ink-2">{t('ticketing.onlyAdmin')}</span>}
      </div>

      {(result || testError) && (
        <section aria-labelledby="tr-result" aria-live="polite">
          <h3 id="tr-result" className="font-semibold">Last probe result</h3>
          {testError ? (
            <p role="alert" className="mt-1 break-words text-critical">{t('ticketing.testFailed')}: {testError}</p>
          ) : result ? (
            <div className="mt-1 space-y-2">
              <p><Outcome ok={result.ok}>{result.message}</Outcome></p>
              <p className="text-12 text-ink-2">{result.latency_ms} ms round-trip</p>
              {result.declared_secrets && result.declared_secrets.length > 0 && (
                <div>
                  <p className="text-12 font-medium text-ink">Declared secrets</p>
                  <ul className="mt-1 space-y-0.5 font-mono text-12 text-ink-2">
                    {result.declared_secrets.map((s) => (
                      <li key={s.name}>
                        {s.name}{s.required ? ' (required)' : ''}{s.holds ? ` — ${s.holds}` : ''}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : null}
        </section>
      )}

      <section aria-labelledby="tr-history">
        <h3 id="tr-history" className="font-semibold">Recent probes</h3>
        {events.isPending ? (
          <div className="mt-2"><Spinner size={14} /></div>
        ) : events.isError ? (
          <ProblemMessage problem={toProblem(events.error)} title="Could not load probe history" onRetry={() => void events.refetch()} className="mt-2" />
        ) : (events.data ?? []).length === 0 ? (
          <p className="mt-1 text-ink-2">No probes recorded yet.</p>
        ) : (
          <ul className="mt-1 divide-y divide-rule border-y border-rule">
            {(events.data ?? []).map((e) => (
              <li key={e.id} className="py-2">
                <Outcome ok={e.outcome === 'succeeded'}>
                  <span className="font-medium">{eventLabel(e)}</span>
                </Outcome>
                <p className="mt-0.5 break-words text-ink-2">{e.message}</p>
                <p className="mt-0.5 font-mono text-12 text-ink-2">
                  {absoluteDateTime(e.at)}
                  {e.actor ? `, by ${e.actor}` : ''}
                  {`, ${e.latency_ms} ms`}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
