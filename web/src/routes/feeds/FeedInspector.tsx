import { useTranslation } from 'react-i18next';
import type { FeedItem, FeedTestResult } from '@/api/types';
import { Button, Spinner } from '@/components';
import { absoluteDateTime } from '@/lib/format';
import { cn } from '@/lib/cn';

/** What is known about the selected feed, and what can be done with it. */
export function FeedInspector({
  feed, probe, mayManage, busy, probing, onSync, onTest,
}: {
  feed: FeedItem | null;
  probe?: FeedTestResult;
  mayManage: boolean;
  /** Any sync is running or starting: one runs at a time. */
  busy: boolean;
  probing: boolean;
  onSync: (name: string) => void;
  onTest: (name: string) => void;
}) {
  const { t } = useTranslation();
  if (!feed) return <p className="p-4 text-13 text-ink-2">{t('feeds.inspectorEmpty')}</p>;
  const off = !feed.enabled;

  return (
    <div className="space-y-5 p-4 text-13">
      <header>
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-14 font-semibold">{feed.display_name}</h3>
          <span className={cn(
            'inline-flex items-center rounded-full px-2 py-0.5 text-11 font-medium',
            feed.enabled ? 'bg-success/15 text-success' : 'bg-surface-3 text-ink-2',
          )}>
            {feed.enabled ? t('feeds.enabled') : t('feeds.disabled')}
          </span>
        </div>
        <p className="mt-0.5 text-ink-2">{feed.description}</p>
      </header>

      <section aria-labelledby="f-source">
        <h4 id="f-source" className="font-semibold">{t('feeds.source')}</h4>
        <p className="mt-1 break-all font-mono text-12 text-ink-2">{feed.url}</p>
        {feed.is_mirror && <p className="mt-1 text-ink-2">{t('feeds.mirror')}</p>}
      </section>

      <section aria-labelledby="f-last">
        <h4 id="f-last" className="font-semibold">{t('feeds.lastResult')}</h4>
        <p className="mt-1">{t(`feeds.status_${feed.status}`)}</p>
        <p className="text-ink-2">
          {feed.last_sync ? t('feeds.lastSyncAt', { when: absoluteDateTime(feed.last_sync) }) : t('feeds.neverSynced')}
        </p>
        {feed.status === 'error' && feed.error && <p className="mt-1 break-words text-critical">{feed.error}</p>}
        {off && <p className="mt-1 text-ink-2">{t(feed.disabled_reason ? `feeds.off_${feed.disabled_reason}` : 'feeds.offBecause')}</p>}
      </section>

      {probe && (
        <section aria-labelledby="f-conn">
          <h4 id="f-conn" className="font-semibold">{t('feeds.colConnection')}</h4>
          <p className="mt-1">
            {probe.reachable ? t('feeds.reachable', { code: probe.status_code, ms: probe.latency_ms }) : t('feeds.notReachable', { message: probe.error || probe.message })}
          </p>
          {feed.status === 'error' && probe.reachable && <p className="mt-1 text-ink-2">{t('feeds.addressAnswers', { code: probe.status_code })}</p>}
        </section>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={() => onTest(feed.name)} disabled={off || probing} loading={probing}>
          {probing ? t('feeds.testing') : t('feeds.testOne')}
        </Button>
        {mayManage && (
          <Button variant="primary" onClick={() => onSync(feed.name)} disabled={off || busy}>
            {feed.status === 'syncing' ? <><Spinner size={12} />{t('feeds.syncing')}</> : t('feeds.syncOne')}
          </Button>
        )}
      </div>
      {!mayManage && <p className="text-ink-2">{t('feeds.onlyAdmin')}</p>}
    </div>
  );
}
