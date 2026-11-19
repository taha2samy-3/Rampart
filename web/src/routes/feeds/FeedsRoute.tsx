import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { get, post, qk, toProblem } from '@/api';
import type { FeedItem, FeedsResponse, FeedSyncResponse, FeedTestConnectionResponse, FeedTestResult } from '@/api/types';
import {
  Button, Dialog, DialogContent, EmptyState, ProblemMessage, SearchField, Select, Spinner, Table, TBody, Td, Th, THead, Tr,
} from '@/components';
import { IconCopy, IconWarning } from '@/components/icons';
import { useAccess } from '@/app/useAccess';
import { absoluteDateTime, shortAge } from '@/lib/format';
import { cn } from '@/lib/cn';
import { FeedInspector } from './FeedInspector';
import { buildManifest } from './manifest';

type Filter = 'all' | 'success' | 'error' | 'disabled';

/**
 * The vulnerability feeds: what each one did, and the two things an administrator does with them, Sync and Test. The list
 * follows the server: a sync is answered at once, the feed says "syncing" until it ends, and the row then shows what the
 * server recorded.
 */
export function FeedsRoute() {
  const { t } = useTranslation();
  const { can } = useAccess();
  const mayManage = can(undefined, 'admin'); // a sync is global: the API needs an administrator
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const [selected, setSelected] = useState<string | null>(null);
  const [probes, setProbes] = useState<Record<string, FeedTestResult>>({});
  const [probing, setProbing] = useState<string | null>(null); // a feed name, or '*' for all
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [manifestOpen, setManifestOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  useEffect(() => { document.title = `${t('nav.feeds')} · Rampart`; }, [t]);

  const q = useQuery({
    queryKey: qk.feeds.list(),
    queryFn: ({ signal }) => get<FeedsResponse>('/api/v1/feeds', { signal }),
    // The server marks a feed "syncing" before it answers the sync request; follow it until it ends.
    refetchInterval: (query) => (query.state.data?.items.some((i) => i.status === 'syncing' || i.status === 'queued') ? 2000 : false),
  });
  const items = useMemo(() => q.data?.items ?? [], [q.data?.items]);
  const mirror = q.data?.mirror;
  const syncing = items.filter((f) => f.status === 'syncing').map((f) => f.display_name);
  const queued = items.filter((f) => f.status === 'queued').length;
  const busy = syncing.length > 0 || queued > 0 || starting;

  const sync = async (feed?: string) => {
    if (busy) return;
    setStarting(true);
    setError(null);
    setProbes({}); // what a probe said before this sync says nothing about the sync
    try {
      await post<FeedSyncResponse>(`/api/v1/feeds/sync${feed ? `?feed=${encodeURIComponent(feed)}` : ''}`, {});
    } catch (e) {
      const p = toProblem(e);
      setError(p.detail ?? p.title ?? t('feeds.syncStartFailed'));
    } finally {
      setStarting(false);
    }
    await q.refetch(); // shows "syncing" at once, and the polling takes over
  };

  const test = async (feed?: string) => {
    setProbing(feed ?? '*');
    setError(null);
    try {
      const res = await post<FeedTestConnectionResponse>(`/api/v1/feeds/test-connection${feed ? `?feed=${encodeURIComponent(feed)}` : ''}`, {});
      setProbes((cur) => ({ ...cur, ...Object.fromEntries(res.results.map((r) => [r.name, r])) }));
    } catch (e) {
      const p = toProblem(e);
      setError(p.detail ?? p.title ?? t('feeds.testFailed'));
    } finally {
      setProbing(null);
    }
  };

  const shown = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return items.filter((f) =>
      (filter === 'all' || f.status === filter) &&
      (!needle || [f.name, f.display_name, f.category, f.description].some((v) => v.toLowerCase().includes(needle))));
  }, [items, search, filter]);
  const selectedFeed = items.find((f) => f.name === selected) ?? null;

  const synced = items.filter((f) => f.status === 'success').length;
  const failed = items.filter((f) => f.status === 'error').length;
  const off = items.filter((f) => !f.enabled).length;
  const records = items.reduce((n, f) => n + (f.records || 0), 0);
  const full = mirror?.storageMode === 'full' || mirror?.storageMode === 'standalone';
  const manifest = useMemo(() => buildManifest(mirror), [mirror]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(manifest);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked: the text stays selectable */
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto px-6 py-5">
      <header className="max-w-[80ch]">
        <h1 className="display text-20 font-semibold">{t('feeds.title')}</h1>
        <p className="mt-1 text-13 text-ink-2">{t('feeds.subtitle')}</p>
      </header>

      {q.isError ? (
        <ProblemMessage problem={toProblem(q.error)} title={t('feeds.loadFailed')} onRetry={() => void q.refetch()} className="mt-4" />
      ) : q.isPending ? (
        <div className="flex h-48 items-center justify-center"><Spinner size={24} /></div>
      ) : (
        <>
          <div className="mt-4 max-w-[80ch] space-y-1 text-13 text-ink-2">
            <p>
              {t('feeds.summary', { count: items.length, synced, failed, off, records: records.toLocaleString() })}{' '}
              {synced === 0 && items.length > 0 && t('feeds.summaryNothingSynced')}
            </p>
            <p>{t(mirror?.egress === 'deny' ? 'feeds.egressDeny' : 'feeds.egressAllow')} {t(full ? 'feeds.storageFull' : 'feeds.storageLightweight')}</p>
          </div>

          {(syncing.length > 0 || queued > 0) && (
            <p role="status" className="mt-3 flex items-center gap-2 text-13">
              <Spinner size={14} />
              <span>
                {syncing.length > 0 ? t('feeds.syncingBanner', { names: syncing.join(', ') }) : t('feeds.queuedBanner')}
                {syncing.length > 0 && queued > 0 && ` ${t('feeds.waitingCount', { count: queued })}`}
              </span>
            </p>
          )}
          {error && (
            <p role="alert" className="mt-3 flex items-center gap-2 text-13 text-critical">
              <IconWarning className="size-4 shrink-0" />
              <span>{error}</span>
            </p>
          )}

          <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-2 border-y border-rule py-2">
            <SearchField className="w-64" aria-label={t('feeds.searchLabel')} placeholder={t('feeds.searchPlaceholder')} value={search} onChange={(e) => setSearch(e.target.value)} />
            <Select
              label={t('feeds.filterLabel')}
              value={filter}
              onValueChange={(v) => setFilter(v as Filter)}
              options={[
                { value: 'all', label: t('feeds.filterAll') },
                { value: 'success', label: t('feeds.filterSuccess') },
                { value: 'error', label: t('feeds.filterError') },
                { value: 'disabled', label: t('feeds.filterDisabled') },
              ]}
            />
            <div className="ms-auto flex flex-wrap items-center gap-2">
              <Button variant="ghost" onClick={() => setManifestOpen(true)}>{t('feeds.viewManifest')}</Button>
              <Button onClick={() => void test()} disabled={probing !== null} loading={probing === '*'}>
                {probing === '*' ? t('feeds.testing') : t('feeds.testAll')}
              </Button>
              {mayManage && (
                <Button variant="primary" onClick={() => void sync()} disabled={busy} loading={busy}>
                  {busy ? t('feeds.syncing') : t('feeds.syncAll')}
                </Button>
              )}
            </div>
          </div>

          <div className="grid min-h-0 grid-cols-1 border-b border-rule lg:grid-cols-[minmax(0,1fr)_20rem]">
            <div className="min-w-0 overflow-x-auto">
              {items.length === 0 ? (
                <EmptyState title={t('feeds.noneConfigured')}>{t('feeds.noneConfiguredHint')}</EmptyState>
              ) : shown.length === 0 ? (
                <EmptyState title={t('feeds.noMatch')}>{t('feeds.noMatchHint')}</EmptyState>
              ) : (
                <Table aria-label={t('feeds.tableLabel')} className="min-w-[44rem]">
                  <THead>
                    <tr>
                      <Th className="w-[34%]">{t('feeds.colFeed')}</Th>
                      <Th className="w-[22%]">{t('feeds.colStatus')}</Th>
                      <Th className="w-[16%]">{t('feeds.colLastSync')}</Th>
                      <Th align="end" className="w-[10%]">{t('feeds.colRecords')}</Th>
                      <Th className="w-[18%]">{t('feeds.colConnection')}</Th>
                    </tr>
                  </THead>
                  <TBody>
                    {shown.map((f) => (
                      <FeedRow key={f.name} feed={f} probe={probes[f.name]} selected={f.name === selected} onSelect={() => setSelected(f.name)} />
                    ))}
                  </TBody>
                </Table>
              )}
            </div>
            <aside aria-label={t('feeds.inspectorLabel')} className="border-t border-rule lg:border-s lg:border-t-0">
              <FeedInspector
                feed={selectedFeed}
                probe={selectedFeed ? probes[selectedFeed.name] : undefined}
                mayManage={mayManage}
                busy={busy}
                probing={probing === selectedFeed?.name || probing === '*'}
                onSync={(n) => void sync(n)}
                onTest={(n) => void test(n)}
              />
            </aside>
          </div>
        </>
      )}

      <Dialog open={manifestOpen} onOpenChange={setManifestOpen}>
        <DialogContent className="w-[720px] max-w-[95vw]" title={t('feeds.manifestTitle')} description={t('feeds.manifestBody')} closeLabel={t('common.close')}>
          <div className="flex flex-col gap-3">
            <pre className="max-h-72 overflow-auto border border-rule bg-chrome p-3 font-mono text-12">{manifest}</pre>
            <p className="text-12 text-ink-2">{t('feeds.storageHelp')}</p>
            <p className="text-12 text-ink-2">{t('feeds.kubectl')} <code className="font-mono">kubectl get clusterfeeds</code></p>
            <div className="flex justify-end gap-2">
              <Button variant="ghost" onClick={() => void copy()}><IconCopy className="size-4" />{copied ? t('feeds.manifestCopied') : t('feeds.manifestCopy')}</Button>
              <Button variant="primary" onClick={() => setManifestOpen(false)}>{t('feeds.manifestDone')}</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function FeedRow({ feed, probe, selected, onSelect }: { feed: FeedItem; probe?: FeedTestResult; selected: boolean; onSelect: () => void }) {
  const { t } = useTranslation();
  const failed = feed.status === 'error';
  return (
    <Tr selected={selected} className="h-12 align-middle">
      <Td className="whitespace-normal">
        <button type="button" onClick={onSelect} aria-pressed={selected} className="block max-w-full text-start hover:text-accent">
          <span className="block truncate font-medium">{feed.display_name}</span>
          <span className="block truncate text-12 text-ink-2">{feed.category}</span>
        </button>
      </Td>
      <Td className="whitespace-normal">
        <span className={cn('inline-flex items-center gap-1.5', failed && 'text-critical')}>
          {feed.status === 'syncing' && <Spinner size={12} />}
          {failed && <IconWarning className="size-3.5 shrink-0" />}
          {t(`feeds.status_${feed.status}`)}
        </span>
        {failed && feed.error && <span className="block break-words text-12 text-ink-2" title={feed.error}>{feed.error}</span>}
        {failed && probe?.reachable && <span className="block text-12 text-ink-2">{t('feeds.addressAnswers', { code: probe.status_code })}</span>}
      </Td>
      <Td className="text-ink-2" title={feed.last_sync ? absoluteDateTime(feed.last_sync) : undefined}>
        {feed.last_sync ? shortAge(feed.last_sync) : '—'}
      </Td>
      <Td align="end">{feed.records.toLocaleString()}</Td>
      <Td className="text-ink-2 whitespace-normal">
        {probe ? (probe.reachable ? t('feeds.reachable', { code: probe.status_code, ms: probe.latency_ms }) : t('feeds.notReachable', { message: probe.error || probe.message })) : '—'}
      </Td>
    </Tr>
  );
}
