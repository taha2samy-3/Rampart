import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { get, post, qk, toProblem } from '@/api';
import type { FeedItem, FeedsResponse, FeedTestConnectionResponse, FeedTestResult, FeedSyncResponse } from '@/api/types';
import {
  Button,
  Dialog,
  DialogContent,
  EmptyState,
  Input,
  Spinner,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
} from '@/components';
import { IconCheck, IconCopy, IconRefresh, IconSearch, IconWarning } from '@/components/icons';
import { absoluteDateTime } from '@/lib/format';
import { useAccess } from '@/app/useAccess';

export function FeedsView() {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'success' | 'error' | 'disabled'>('all');
  const [crdOpen, setCrdOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [testResults, setTestResults] = useState<Record<string, FeedTestResult>>({});
  const [testingFeed, setTestingFeed] = useState<string | null>(null);
  const [testingAll, setTestingAll] = useState(false);
  const [testSummary, setTestSummary] = useState<string | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false); // the sync request is in flight
  const { can } = useAccess();
  const mayManage = can(undefined, 'admin'); // starting a sync is global: the API needs an administrator

  const feedsQuery = useQuery({
    queryKey: qk.feeds.list(),
    queryFn: async ({ signal }): Promise<FeedsResponse> =>
      get<FeedsResponse>('/api/v1/feeds', { signal }),
    // The server marks a feed "syncing" before it answers the sync request; follow it until it ends.
    refetchInterval: (q) => (q.state.data?.items.some((i) => i.status === 'syncing') ? 2000 : false),
  });

  const feedsData = feedsQuery.data;
  const items = useMemo(() => feedsData?.items ?? [], [feedsData?.items]);
  const mirror = feedsData?.mirror;

  const handleSyncNow = async (feedName?: string) => {
    if (starting) return;
    setStarting(true);
    setSyncError(null);
    // What a probe said before this sync says nothing about the sync, and would stay on screen for hours.
    setTestResults({});
    setTestSummary(null);
    try {
      const queryParam = feedName ? `?feed=${encodeURIComponent(feedName)}` : '';
      await post<FeedSyncResponse>(`/api/v1/feeds/sync${queryParam}`, {});
    } catch (e) {
      const p = toProblem(e);
      setSyncError(p.detail ?? p.title ?? 'Failed to start the sync.');
    } finally {
      setStarting(false);
    }
    await feedsQuery.refetch(); // shows "syncing" at once, and the polling takes over
  };

  const handleTestConnection = async (feedName?: string) => {
    try {
      if (feedName) {
        setTestingFeed(feedName);
      } else {
        setTestingAll(true);
      }
      setTestError(null);
      const queryParam = feedName ? `?feed=${encodeURIComponent(feedName)}` : '';
      const res = await post<FeedTestConnectionResponse>(`/api/v1/feeds/test-connection${queryParam}`, {});
      setTestResults((prev) => {
        const next = { ...prev };
        for (const r of res.results) {
          next[r.name] = r;
        }
        return next;
      });
      if (!feedName) {
        const reachable = res.results.filter((r) => r.reachable).length;
        setTestSummary(
          `Live probe verified: ${reachable} of ${res.results.length} upstream feeds reachable (responded in real-time).`
        );
      }
    } catch (e) {
      const p = toProblem(e);
      setTestError(p.detail ?? p.title ?? 'The connectivity test could not run.');
    } finally {
      setTestingFeed(null);
      setTestingAll(false);
    }
  };

  const filtered = useMemo(() => {
    return items.filter((f) => {
      if (statusFilter !== 'all' && f.status !== statusFilter) return false;
      if (!search.trim()) return true;
      const q = search.toLowerCase();
      return (
        f.name.toLowerCase().includes(q) ||
        f.display_name.toLowerCase().includes(q) ||
        f.category.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q)
      );
    });
  }, [items, search, statusFilter]);

  const totalRecords = useMemo(() => {
    return items.reduce((acc, curr) => acc + (curr.records || 0), 0);
  }, [items]);

  const syncingNames = useMemo(() => items.filter((f) => f.status === 'syncing').map((f) => f.display_name), [items]);
  const anySyncing = syncingNames.length > 0;

  const errorCount = useMemo(() => {
    return items.filter((f) => f.status === 'error').length;
  }, [items]);
  // "Healthy" is said only of feeds that did sync: nothing loaded, or nothing synced yet, is not health.
  const enabledItems = items.filter((f) => f.enabled);
  const health: 'unknown' | 'degraded' | 'healthy' | 'pending' =
    feedsQuery.isError || enabledItems.length === 0 ? 'unknown'
      : errorCount > 0 ? 'degraded'
        : enabledItems.every((f) => f.status === 'success') ? 'healthy' : 'pending';

  // Only what the live resource sets. A source listed here is switched on (the optional ones) or counts as a mirror
  // (kev, epss, nvd, osv), and under egress: deny a feed with a url is the only kind that is still read, so printing
  // the public defaults would defeat an air gap and turn on sources nobody chose.
  const crdYaml = useMemo(() => {
    const m = (mirror ?? {}) as Record<string, unknown>;
    const lines = [
      '# ClusterFeed (the ClusterFeedMirror alias is accepted too). Shown: what this server has. Add a source to turn it on;',
      '# add a url to read a feed from an internal mirror. kev, epss, nvd and osv run by default without any block.',
      'apiVersion: rampart.aspm.dev/v1alpha1',
      'kind: ClusterFeed',
      'metadata:',
      '  name: default',
      'spec:',
      `  egress: ${String(m.egress ?? 'allow')} # allow | deny: with deny only a feed that has a url (a mirror) is read`,
      `  storageMode: ${String(m.storageMode ?? 'lightweight')} # lightweight | full`,
    ];
    for (const k of ['kev', 'epss', 'nvd', 'osv', 'vulnrichment', 'exploitdb', 'metasploit', 'euvd', 'vulncheckKev']) {
      const v = m[k] as { url?: string; tokenFile?: string } | undefined;
      if (!v) continue;
      lines.push(`  ${k}:`);
      if (v.url) lines.push(`    url: "${v.url}"`);
      if (v.tokenFile) lines.push(`    tokenFile: "${v.tokenFile}"`);
      if (!v.url && !v.tokenFile) lines.push('    {}');
    }
    const custom = (m.custom as Array<{ name: string; url?: string; format: string; tokenFile?: string; pushTokenFile?: string }> | undefined) ?? [];
    if (custom.length) {
      lines.push('  custom:');
      for (const c of custom) {
        lines.push(`    - name: ${c.name}`, `      format: ${c.format}`);
        if (c.url) lines.push(`      url: "${c.url}"`);
        if (c.tokenFile) lines.push(`      tokenFile: "${c.tokenFile}"`);
        if (c.pushTokenFile) lines.push(`      pushTokenFile: "${c.pushTokenFile}"`);
      }
    }
    return lines.join('\n') + '\n';
  }, [mirror]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(crdYaml);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
    }
  };

  return (
    <div className="flex flex-col gap-6">
      {/* Intro & Overview */}
      <div className="flex flex-col gap-3 rounded-md border border-border bg-surface p-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-15 font-semibold text-ink">
              {t('feeds.title', { defaultValue: 'Threat Intelligence & Vulnerability Feeds' })}
            </h2>
            <p className="mt-1 text-13 text-ink-2">
              {t('feeds.subtitle', {
                defaultValue:
                  'Vulnerability feeds enrich findings with CVSS metrics, exploit predictions (EPSS), active exploitation catalogs (CISA KEV), and open-source advisories. Feeds are declaratively managed via ClusterFeed Custom Resources in Kubernetes.',
              })}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {mayManage && <Button
              variant="secondary"
              onClick={() => handleSyncNow()}
              disabled={anySyncing || starting}
              className="flex items-center gap-1.5"
            >
              {anySyncing ? (
                <>
                  <Spinner size={14} />
                  <span>{t('feeds.syncing', { defaultValue: 'Syncing...' })}</span>
                </>
              ) : (
                <>
                  <IconRefresh className="h-4 w-4" />
                  <span>{t('feeds.syncAll', { defaultValue: 'Sync Now' })}</span>
                </>
              )}
            </Button>}
            <Button
              variant="secondary"
              onClick={() => handleTestConnection()}
              disabled={testingAll || !!testingFeed}
              className="flex items-center gap-1.5"
            >
              {testingAll ? (
                <>
                  <Spinner size={14} />
                  <span>{t('feeds.testing', { defaultValue: 'Testing...' })}</span>
                </>
              ) : (
                <>
                  <IconRefresh className="h-4 w-4" />
                  <span>{t('feeds.testAll', { defaultValue: 'Test Live Connectivity' })}</span>
                </>
              )}
            </Button>
            <Button variant="primary" onClick={() => setCrdOpen(true)}>
              {t('feeds.viewCrd', { defaultValue: 'Declarative CRD Spec' })}
            </Button>
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5 pt-2 border-t border-border">
          <div className="flex flex-col">
            <span className="text-11 text-ink-2 uppercase tracking-wider">{t('feeds.totalFeeds', { defaultValue: 'Total Feeds' })}</span>
            <span className="text-18 font-semibold text-ink">{items.length}</span>
          </div>
          <div className="flex flex-col">
            <span className="text-11 text-ink-2 uppercase tracking-wider">{t('feeds.totalRecords', { defaultValue: 'Synced Records' })}</span>
            <span className="text-18 font-semibold text-ink">{totalRecords.toLocaleString()}</span>
          </div>
          <div className="flex flex-col">
            <span className="text-11 text-ink-2 uppercase tracking-wider">{t('feeds.health', { defaultValue: 'Feed Health' })}</span>
            <span className={`text-18 font-semibold ${health === 'degraded' ? 'text-amber-600 dark:text-amber-400' : health === 'healthy' ? 'text-emerald-600 dark:text-emerald-400' : 'text-ink-2'}`}>
              {health === 'degraded' ? `${errorCount} Degraded` : health === 'healthy' ? 'Healthy' : health === 'pending' ? 'Not synced yet' : '—'}
            </span>
          </div>
          <div className="flex flex-col">
            <span className="text-11 text-ink-2 uppercase tracking-wider">{t('feeds.egressMode', { defaultValue: 'Egress Policy' })}</span>
            <span className="text-18 font-semibold text-ink capitalize">
              {mirror?.egress === 'deny' ? 'Air-gapped (Deny)' : 'Standard (Allow)'}
            </span>
          </div>
          <div className="flex flex-col">
            <span className="text-11 text-ink-2 uppercase tracking-wider">{t('feeds.storageStrategy', { defaultValue: 'Storage Mode' })}</span>
            <span className="text-18 font-semibold text-ink capitalize">
              {mirror?.storageMode === 'full' || mirror?.storageMode === 'standalone' ? 'Full Local DB' : 'Lightweight'}
            </span>
          </div>
        </div>

        {/* Storage Strategy Explanation Banner */}
        <div className="flex items-center gap-2 rounded bg-surface-2 px-3 py-2 text-12 text-ink-2">
          <span className="font-medium text-ink">
            {mirror?.storageMode === 'full' || mirror?.storageMode === 'standalone'
              ? 'Full Local Mirror Active:'
              : 'Lightweight Stream Active:'}
          </span>
          <span>
            {mirror?.storageMode === 'full' || mirror?.storageMode === 'standalone'
              ? 'Vulnerability databases (NVD, OSV, KEV, EPSS) are fully cached and stored offline in PostgreSQL (Dependency-Track style) for zero-latency, isolated operation.'
              : 'Feeds sync incrementally and scores are streamed daily to keep database footprint minimal. Switch to "storageMode: full" in ClusterFeed if you require a complete offline database mirror.'}
          </span>
        </div>
      </div>

      {/* Live Probe Feedback Banner */}
      {testSummary && (
        <div className="flex items-center justify-between rounded border border-emerald-500/30 bg-emerald-500/10 px-3.5 py-2.5 text-12 text-emerald-800 dark:text-emerald-300">
          <div className="flex items-center gap-2">
            <IconCheck className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
            <span className="font-medium">{testSummary}</span>
          </div>
          <button
            onClick={() => setTestSummary(null)}
            className="text-11 text-ink-2 hover:text-ink px-1 font-bold"
            aria-label="Dismiss test summary"
          >
            ✕
          </button>
        </div>
      )}

      {/* The banner follows the server: it is there while a feed says "syncing", and it is gone when it ends. */}
      {anySyncing && (
        <div role="status" className="flex items-center gap-2 rounded border border-blue-500/30 bg-blue-500/10 px-3.5 py-2.5 text-12 text-blue-800 dark:text-blue-300">
          <Spinner size={14} />
          <span className="font-medium">Syncing {syncingNames.join(', ')}. The table shows the result when it ends, and everyone gets a notification.</span>
        </div>
      )}
      {testError && (
        <div role="alert" className="flex items-center justify-between rounded border border-red-500/30 bg-red-500/10 px-3.5 py-2.5 text-12 text-red-800 dark:text-red-300">
          <span className="font-medium">{testError}</span>
          <button onClick={() => setTestError(null)} className="px-1 text-11 font-bold text-ink-2 hover:text-ink" aria-label="Dismiss test error">✕</button>
        </div>
      )}
      {syncError && (
        <div role="alert" className="flex items-center justify-between rounded border border-red-500/30 bg-red-500/10 px-3.5 py-2.5 text-12 text-red-800 dark:text-red-300">
          <span className="font-medium">{syncError}</span>
          <button onClick={() => setSyncError(null)} className="px-1 text-11 font-bold text-ink-2 hover:text-ink" aria-label="Dismiss sync error">✕</button>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="relative w-64">
            <Input
              aria-label="Search threat feeds"
              placeholder="Search feeds..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8"
            />
            <span className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-2">
              <IconSearch className="h-4 w-4" />
            </span>
          </div>
          <div className="flex rounded-md border border-border bg-surface p-0.5 text-12">
            {(['all', 'success', 'error', 'disabled'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setStatusFilter(mode)}
                className={`rounded px-2.5 py-1 font-medium capitalize transition-colors ${
                  statusFilter === mode ? 'bg-primary text-primary-contrast' : 'text-ink-2 hover:text-ink'
                }`}
              >
                {mode === 'all' ? 'All' : mode === 'success' ? 'Active' : mode}
              </button>
            ))}
          </div>
        </div>
        <span className="text-12 text-ink-2">
          Showing {filtered.length} of {items.length} feeds
        </span>
      </div>

      {/* Main Table */}
      {feedsQuery.isError ? (
        <div role="alert" className="flex items-center gap-2 rounded-md border border-border p-4 text-13 text-ink-2">
          <IconWarning className="h-5 w-5 text-amber-500" />
          <span>The vulnerability feeds could not be loaded from the server.</span>
        </div>
      ) : feedsQuery.isLoading ? (
        <div className="flex h-48 items-center justify-center">
          <Spinner />
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState title="No matching feeds found">
          {search || statusFilter !== 'all' ? 'Try clearing the search or the status filter.' : 'No threat intelligence feeds are currently configured.'}
        </EmptyState>
      ) : (
        <Table aria-label="Vulnerability feeds table">
          <THead>
            <tr>
              <Th>Feed</Th>
              <Th>Category</Th>
              <Th>Status</Th>
              <Th>Records</Th>
              <Th>Upstream / Mirror URL</Th>
              <Th>Last Sync</Th>
              <Th className="text-right">Live Connectivity</Th>
            </tr>
          </THead>
          <TBody>
            {filtered.map((feed: FeedItem) => {
              const probe = testResults[feed.name];
              const isPinging = testingFeed === feed.name;
              const isSyncing = feed.status === 'syncing';

              return (
                <Tr key={feed.name} className="h-14">
                  <Td>
                    <div className="flex flex-col">
                      <span className="font-medium text-ink">{feed.display_name}</span>
                      <span className="text-11 text-ink-2 truncate max-w-xs">{feed.description}</span>
                    </div>
                  </Td>
                  <Td>
                    <span className="text-12 text-ink-2">{feed.category}</span>
                  </Td>
                  <Td>
                    <div className="flex items-center gap-1.5">
                      {feed.status === 'success' && (
                        <>
                          <IconCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                          <span className="text-12 font-medium text-ink">Synced</span>
                        </>
                      )}
                      {feed.status === 'syncing' && (
                        <>
                          <Spinner size={14} />
                          <span className="text-12 text-ink-2">Syncing...</span>
                        </>
                      )}
                      {feed.status === 'idle' && (
                        <span className="text-12 text-ink-2">
                          {feed.name === 'osv' && feed.records === 0 ? 'Off until an ecosystem is chosen (feeds.osvEcosystems)' : 'Not synced yet'}
                        </span>
                      )}
                      {feed.status === 'disabled' && (
                        <span className="text-12 text-ink-2">Disabled (Airgap)</span>
                      )}
                      {feed.status === 'error' && (
                        <div className="flex items-center gap-1 text-amber-600 dark:text-amber-400">
                          <IconWarning className="h-4 w-4" />
                          <div className="flex max-w-xs flex-col">
                            <span className="text-12 font-medium">Sync failed</span>
                            <span className="break-words text-11 text-ink-2" title={feed.error ?? ''}>{feed.error ?? ''}</span>
                            {probe?.reachable && (
                              <span className="text-11 text-ink-2">The address answers (HTTP {probe.status_code}); the failure is in the sync itself.</span>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </Td>
                  <Td className="text-12 text-ink font-mono">
                    {feed.records.toLocaleString()}
                  </Td>
                  <Td>
                    <div className="flex items-center gap-2 max-w-xs truncate text-12 font-mono text-ink-2" title={feed.url}>
                      <span className="truncate">{feed.url}</span>
                      {feed.is_mirror && (
                        <span className="rounded bg-surface-2 px-1.5 py-0.5 text-10 font-sans text-ink uppercase">
                          Mirror
                        </span>
                      )}
                    </div>
                  </Td>
                  <Td className="text-12 text-ink-2 whitespace-nowrap font-mono">
                    {feed.last_sync ? (
                      <span title={feed.last_sync}>{absoluteDateTime(feed.last_sync)}</span>
                    ) : (
                      '—'
                    )}
                  </Td>
                  <Td className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      {probe && (
                        <span
                          className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-11 font-mono ${
                            !probe.reachable && probe.status_code === 0 && probe.latency_ms === 0
                              ? 'bg-surface-2 text-ink-2 border border-border'
                              : probe.reachable
                              ? probe.status_code >= 400
                                ? 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20'
                                : 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20'
                              : 'bg-red-500/10 text-red-700 dark:text-red-400 border border-red-500/20'
                          }`}
                          title={`${probe.message} (${probe.latency_ms}ms)`}
                        >
                          {!probe.reachable && probe.status_code === 0 && probe.latency_ms === 0 ? (
                            <span className="font-sans">{probe.message}</span>
                          ) : (
                            <>
                              <span className="font-semibold">
                                {probe.status_code > 0 ? `HTTP ${probe.status_code}` : 'Unreachable'}
                              </span>
                              <span>• {probe.latency_ms}ms</span>
                            </>
                          )}
                        </span>
                      )}
                      <Button
                        variant="ghost"
                        disabled={isPinging || testingAll || !feed.enabled}
                        onClick={() => handleTestConnection(feed.name)}
                        className="text-11 flex items-center gap-1 px-2.5 py-1"
                        title={`Test live connectivity to ${feed.url}`}
                      >
                        {isPinging ? (
                          <>
                            <Spinner size={12} />
                            <span>Pinging...</span>
                          </>
                        ) : (
                          <span>Test</span>
                        )}
                      </Button>
                      {mayManage && <Button
                        variant="ghost"
                        disabled={anySyncing || starting || !feed.enabled}
                        onClick={() => handleSyncNow(feed.name)}
                        className="text-11 flex items-center gap-1 px-2.5 py-1"
                        title={`Trigger immediate sync for ${feed.display_name}`}
                      >
                        {isSyncing ? (
                          <>
                            <Spinner size={12} />
                            <span>Syncing...</span>
                          </>
                        ) : (
                          <span>Sync</span>
                        )}
                      </Button>}
                    </div>
                  </Td>
                </Tr>
              );
            })}
          </TBody>
        </Table>
      )}

      {/* Declarative CRD Dialog */}
      <Dialog open={crdOpen} onOpenChange={setCrdOpen}>
        <DialogContent
          className="w-[720px] max-w-[95vw]"
          title="Declarative ClusterFeed Specification"
          description="Vulnerability feeds are first-class Kubernetes Custom Resources."
        >
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <span className="text-12 font-medium text-ink-2">Kubernetes Manifest</span>
              <Button variant="ghost" onClick={handleCopy} className="text-12 flex items-center gap-1.5">
                <IconCopy className="h-4 w-4" />
                {copied ? 'Copied!' : 'Copy YAML'}
              </Button>
            </div>
            <p className="text-13 text-ink-2">
              Rampart treats vulnerability feeds as declarative Custom Resources.
              You can inspect, customize, or remove this resource via <code className="font-mono text-12">kubectl</code> or Helm values to configure air-gapped internal mirrors, private feeds, or opt-in ecosystem databases.
            </p>

            <pre className="max-h-64 overflow-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-12 text-ink">
              {crdYaml}
            </pre>

            <div className="rounded-md border border-border bg-surface p-3 text-12 text-ink-2 flex flex-col gap-1.5">
              <span className="font-medium text-ink">Storage Strategies:</span>
              <div>
                <strong className="text-ink">storageMode: lightweight (Default)</strong>: Synchronizes changes incrementally and daily scores via lightweight streams to save disk and memory.
              </div>
              <div>
                <strong className="text-ink">storageMode: full</strong>: Mirrors and stores the complete open-source and global vulnerability intelligence database locally in PostgreSQL (Dependency-Track style) for strict air-gapped / sovereign environments.
              </div>
            </div>

            <div className="rounded-md border border-border bg-surface p-3 text-12 text-ink-2 flex flex-col gap-1.5">
              <span className="font-medium text-ink">Kubectl Commands:</span>
              <code className="font-mono">kubectl get clusterfeeds</code>
              <code className="font-mono">kubectl describe clusterfeed default</code>
              <code className="font-mono">kubectl edit clusterfeed default</code>
            </div>

            <div className="flex justify-end pt-2">
              <Button variant="primary" onClick={() => setCrdOpen(false)}>
                Done
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
