import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { listAnalyzerEvents, qk, toProblem } from '@/api';
import type { AnalyzerEvent, AnalyzerItem, AnalyzerTestResult } from '@/api/types';
import { Button, ProblemMessage, Spinner } from '@/components';
import { IconWarning } from '@/components/icons';
import { absoluteDateTime } from '@/lib/format';
import { cn } from '@/lib/cn';

/** What an event says in one phrase: "Test worked", "Analysis failed". */
export function eventPhrase(t: (k: string) => string, e: Pick<AnalyzerEvent, 'event' | 'outcome'>): string {
  return t(`analyzers.eventOutcome.${e.event}_${e.outcome}`);
}

/** A label and its value side by side; a long value (an address) goes under its label, where it has the whole width. */
function Row({ label, children, stacked }: { label: string; children: React.ReactNode; stacked?: boolean }) {
  return (
    <div className={stacked ? 'flex flex-col' : 'flex gap-3'}>
      <dt className={stacked ? 'text-ink-2' : 'w-36 shrink-0 text-ink-2'}>{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

function Setup({ a }: { a: AnalyzerItem }) {
  const { t } = useTranslation();
  if (a.kind === 'external') {
    return (
      <dl className="mt-1 space-y-1">
        {a.target && <Row label={t('analyzers.address')} stacked><span className="font-mono text-12">{a.target}</span></Row>}
        <Row label={t('analyzers.connection')}>{a.secure ? t('analyzers.connectionSecure') : t('analyzers.connectionPlain')}</Row>
        {a.timeout_seconds ? <Row label={t('analyzers.timeLimit')}>{t('analyzers.timeLimitValue', { seconds: a.timeout_seconds })}</Row> : null}
      </dl>
    );
  }
  const sources = Object.entries(a.sources ?? {}).filter(([, on]) => on).map(([k]) => t(`analyzers.source.${k}`, { defaultValue: k }));
  return (
    <dl className="mt-1 space-y-1">
      <Row label={t('analyzers.engine')}><span className="font-mono text-12">{a.engine}</span></Row>
      {a.min_confidence !== undefined && <Row label={t('analyzers.minConfidence')}>{a.min_confidence}</Row>}
      {sources.length > 0 && <Row label={t('analyzers.advisorySources')}>{sources.join(', ')}</Row>}
      {a.schedule && <Row label={t('analyzers.schedule')}><span className="font-mono text-12">{a.schedule}</span></Row>}
      <Row label={t('analyzers.preRelease')}>{a.include_pre_release ? t('analyzers.preReleaseIncluded') : t('analyzers.preReleaseSkipped')}</Row>
      <Row label={t('analyzers.directOnly')}>{a.match_direct_only ? t('analyzers.directOnlyYes') : t('analyzers.directOnlyNo')}</Row>
    </dl>
  );
}

/** The detail the server returned with a test, in plain labels; a key this page does not know is shown as it is. */
function DetailList({ detail }: { detail?: Record<string, string> }) {
  const { t } = useTranslation();
  const entries = Object.entries(detail ?? {}).filter(([, v]) => v !== '');
  if (entries.length === 0) return null;
  return (
    <dl className="mt-2 space-y-1 text-12">
      {entries.map(([k, v]) => (
        <Row key={k} label={t(`analyzers.detail.${k}`, { defaultValue: k })} stacked={v.length > 24}>
          <span className="font-mono">{v}</span>
        </Row>
      ))}
    </dl>
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

/** How the selected analyzer is set up, whether it answers, and the last things it did. An administrator can test it. */
export function AnalyzerInspector({
  analyzer, mayManage, testing, result, testError, onTest, analyzing, queued, analyzeError, onAnalyze,
}: {
  analyzer: AnalyzerItem | null;
  mayManage: boolean;
  testing: boolean;
  result?: AnalyzerTestResult;
  testError?: string | null;
  onTest: (a: AnalyzerItem) => void;
  analyzing: boolean;
  /** How many analyses the last request queued. */
  queued?: number;
  analyzeError?: string | null;
  onAnalyze: (a: AnalyzerItem) => void;
}) {
  const { t } = useTranslation();
  const events = useQuery({
    queryKey: qk.analyzers.events(analyzer ?? { kind: '', scope: '', name: '' }),
    queryFn: ({ signal }) => listAnalyzerEvents(analyzer as AnalyzerItem, signal),
    enabled: !!analyzer,
  });
  if (!analyzer) return <p className="p-4 text-13 text-ink-2">{t('analyzers.inspectorEmpty')}</p>;

  return (
    <div className="space-y-5 p-4 text-13">
      <header>
        <h3 className="text-14 font-semibold break-words">{analyzer.name}</h3>
        <p className="mt-0.5 text-ink-2">
          {t(`analyzers.kind_${analyzer.kind}`)}, {t(`analyzers.scope_${analyzer.scope}`)}
          {analyzer.namespace ? `, ${analyzer.namespace}` : ''}
        </p>
        <p className="mt-1 text-ink-2">{t(`analyzers.kindHelp_${analyzer.kind}`)}</p>
      </header>

      {!analyzer.ready && (
        <section aria-labelledby="an-refused">
          <h4 id="an-refused" className="font-semibold">{t('analyzers.refused')}</h4>
          <p className="mt-1 break-words text-critical">{analyzer.error}</p>
          <p className="mt-1 text-ink-2">{t('analyzers.refusedHint')}</p>
        </section>
      )}
      {analyzer.ready && !analyzer.enabled && <p className="text-ink-2">{t('analyzers.switchedOff')}</p>}

      <section aria-labelledby="an-setup">
        <h4 id="an-setup" className="font-semibold">{t('analyzers.setup')}</h4>
        <Setup a={analyzer} />
        {analyzer.kind === 'sbom' && <p className="mt-2 text-12 text-ink-2">{t('analyzers.matcherNote')}</p>}
      </section>

      <div className="flex flex-wrap items-center gap-2">
        <Button variant="primary" onClick={() => onTest(analyzer)} disabled={!mayManage || testing} loading={testing}>
          {testing ? t('analyzers.testing') : t('analyzers.testButton')}
        </Button>
        <Button onClick={() => onAnalyze(analyzer)} disabled={!mayManage || analyzing || !analyzer.ready || !analyzer.enabled} loading={analyzing}>
          {analyzing ? t('analyzers.analyzing') : t('analyzers.analyzeButton')}
        </Button>
        {!mayManage && <span className="text-ink-2">{t('analyzers.onlyAdmin')}</span>}
      </div>
      <p className="-mt-3 text-12 text-ink-2">{t('analyzers.analyzeHelp')}</p>
      {(queued !== undefined || analyzeError) && (
        <p role={analyzeError ? 'alert' : 'status'} className={analyzeError ? 'break-words text-critical' : 'text-ink'}>
          {analyzeError
            ? `${t('analyzers.analyzeFailed')}: ${analyzeError}`
            : queued === 0
              ? t('analyzers.analyzeNothing')
              : t('analyzers.analyzeQueued', { count: queued })}
        </p>
      )}

      {(result || testError) && (
        <section aria-labelledby="an-result" aria-live="polite">
          <h4 id="an-result" className="font-semibold">{t('analyzers.lastResult')}</h4>
          {testError ? (
            <p role="alert" className="mt-1 break-words text-critical">{t('analyzers.testFailedToRun')}: {testError}</p>
          ) : result ? (
            <>
              <p className="mt-1"><Outcome ok={result.ok}>{result.message}</Outcome></p>
              <p className="mt-0.5 text-12 text-ink-2">{t('analyzers.tookMs', { ms: result.latency_ms })}</p>
              <DetailList detail={result.detail} />
            </>
          ) : null}
        </section>
      )}

      <section aria-labelledby="an-history">
        <h4 id="an-history" className="font-semibold">{t('analyzers.history')}</h4>
        {events.isPending ? (
          <div className="mt-2"><Spinner size={14} /></div>
        ) : events.isError ? (
          <ProblemMessage problem={toProblem(events.error)} title={t('analyzers.historyFailed')} onRetry={() => void events.refetch()} className="mt-2" />
        ) : (events.data ?? []).length === 0 ? (
          <p className="mt-1 text-ink-2">{t('analyzers.noEvents')}</p>
        ) : (
          <ul className="mt-1 divide-y divide-rule border-y border-rule">
            {(events.data ?? []).map((e) => (
              <li key={e.id} className="py-2">
                <Outcome ok={e.outcome === 'succeeded'}>
                  <span className="font-medium">{eventPhrase(t, e)}</span>
                </Outcome>
                <p className="mt-0.5 break-words text-ink-2">{e.message}</p>
                <p className="mt-0.5 font-mono text-12 text-ink-2">
                  {absoluteDateTime(e.created_at)}
                  {e.actor ? `, ${t('analyzers.by', { who: e.actor })}` : ''}
                  {`, ${t('analyzers.tookMs', { ms: e.duration_ms })}`}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
