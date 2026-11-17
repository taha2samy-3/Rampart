import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { get, qk } from '@/api';
import type { FeedItem, FeedsResponse } from '@/api/types';
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
import { IconCheck, IconCopy, IconSearch, IconWarning } from '@/components/icons';
import { absoluteDate, shortAge } from '@/lib/format';

export function FeedsView() {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'success' | 'error' | 'disabled'>('all');
  const [crdOpen, setCrdOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const feedsQuery = useQuery({
    queryKey: qk.feeds.list(),
    queryFn: async ({ signal }): Promise<FeedsResponse> =>
      get<FeedsResponse>('/api/v1/feeds', { signal }),
  });

  const feedsData = feedsQuery.data;
  const items = useMemo(() => feedsData?.items ?? [], [feedsData?.items]);
  const mirror = feedsData?.mirror;

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

  const errorCount = useMemo(() => {
    return items.filter((f) => f.status === 'error').length;
  }, [items]);

  const crdYaml = useMemo(() => {
    return `# Threat Intelligence Feeds CRD (ClusterFeed)
apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterFeed
metadata:
  name: default
spec:
  egress: ${mirror?.egress ?? 'allow'} # allow | deny (air-gapped)
  storageMode: ${mirror?.storageMode ?? 'lightweight'} # lightweight (stream) | full (offline local DB like Dependency-Track)
  kev:
    url: "${mirror?.kev?.url ?? 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'}"
  epss:
    url: "${mirror?.epss?.url ?? 'https://epss.cyentia.com/epss_scores-current.csv.gz'}"
  nvd:
    url: "${mirror?.nvd?.url ?? 'https://services.nvd.nist.gov/rest/json/cves/2.0'}"
  osv:
    url: "${mirror?.osv?.url ?? 'https://osv-vulnerabilities.storage.googleapis.com'}"
  vulnrichment:
    url: "${mirror?.vulnrichment?.url ?? 'https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.zip'}"
  exploitdb:
    url: "${mirror?.exploitdb?.url ?? 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'}"
`;
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
          <Button variant="primary" onClick={() => setCrdOpen(true)}>
            {t('feeds.viewCrd', { defaultValue: 'Declarative CRD Spec' })}
          </Button>
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
            <span className={`text-18 font-semibold ${errorCount > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
              {errorCount > 0 ? `${errorCount} Degraded` : 'Healthy'}
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
          {search ? 'Try clearing your search filter.' : 'No threat intelligence feeds are currently configured.'}
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
            </tr>
          </THead>
          <TBody>
            {filtered.map((feed: FeedItem) => {
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
                        <span className="text-12 text-ink-2">Idle</span>
                      )}
                      {feed.status === 'disabled' && (
                        <span className="text-12 text-ink-2">Disabled (Airgap)</span>
                      )}
                      {feed.status === 'error' && (
                        <div className="flex items-center gap-1 text-amber-600 dark:text-amber-400">
                          <IconWarning className="h-4 w-4" />
                          <span className="text-12 font-medium" title={feed.error ?? ''}>
                            {feed.error ? 'Error: ' + feed.error.slice(0, 30) + '...' : 'Sync Failed'}
                          </span>
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
                  <Td className="text-12 text-ink-2">
                    {feed.last_sync ? (
                      <span title={absoluteDate(feed.last_sync)}>{shortAge(feed.last_sync)}</span>
                    ) : (
                      '—'
                    )}
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

            <pre className="overflow-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-12 text-ink">
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
