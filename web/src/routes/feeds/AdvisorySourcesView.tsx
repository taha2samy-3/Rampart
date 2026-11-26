import { useMemo, useState } from 'react';
import type { AdvisorySourceItem } from '@/api/types';
import {
  Button,
  Dialog,
  DialogContent,
  EmptyState,
  Input,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
} from '@/components';
import { IconCopy } from '@/components/icons';
import { cn } from '@/lib/cn';
import { AdvisoryInspector } from './AdvisoryInspector';
import { buildAdvisoryManifest } from './advisoryManifest';

const DEFAULT_SOURCES: AdvisorySourceItem[] = [
  {
    name: 'osv',
    display_name: 'OSV.dev & GitHub Advisories',
    provider: 'Google / OpenSSF',
    category: 'open',
    description: 'Bulk GCS archives and open REST query API for npm, PyPI, Maven, Go, crates.io, NuGet, and Packagist.',
    url: 'https://osv-vulnerabilities.storage.googleapis.com',
    enabled: true,
    token_required: false,
    token_present: true,
    records_count: 142500,
    last_sync: '2026-11-20T19:30:00Z',
    status: 'ready',
  },
  {
    name: 'nvd',
    display_name: 'NIST NVD API 2.0',
    provider: 'NIST',
    category: 'api',
    description: 'Official National Vulnerability Database CVE records, descriptions, and CVSS vector specifications.',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    enabled: true,
    token_required: true,
    token_present: true,
    token_file: '/etc/rampart/feed-secrets/nvd-api-key',
    records_count: 248000,
    last_sync: '2026-11-20T19:00:00Z',
    status: 'ready',
  },
  {
    name: 'sonatype',
    display_name: 'Sonatype OSS Index',
    provider: 'Sonatype',
    category: 'api',
    description: 'Component vulnerability reports and remediation guidance with batch purl querying.',
    url: 'https://ossindex.sonatype.org/api/v3/component-report',
    enabled: false,
    token_required: true,
    token_present: false,
    token_file: '/etc/rampart/feed-secrets/sonatype-token',
    status: 'disabled',
  },
  {
    name: 'snyk',
    display_name: 'Snyk Vulnerability Database',
    provider: 'Snyk',
    category: 'commercial',
    description: 'Deep narrative writeups, attack scenarios, and patch verifications for open source libraries.',
    url: 'https://api.snyk.io/rest',
    enabled: false,
    token_required: true,
    token_present: false,
    token_file: '/etc/rampart/feed-secrets/snyk-token',
    status: 'disabled',
  },
  {
    name: 'vulncheck',
    display_name: 'VulnCheck Advisory & KEV',
    provider: 'VulnCheck',
    category: 'commercial',
    description: 'Commercial exploit intelligence, ransomware tracking, and real-time weaponization feeds.',
    url: 'https://api.vulncheck.com/v3',
    enabled: false,
    token_required: true,
    token_present: false,
    token_file: '/etc/rampart/feed-secrets/vulncheck-token',
    status: 'disabled',
  },
  {
    name: 'depsdev',
    display_name: 'Google Open Source Insights (deps.dev)',
    provider: 'Google',
    category: 'open',
    description: 'Fast dependency graph resolution, transitive impact analysis, and open security advisories.',
    url: 'https://api.deps.dev/v3',
    enabled: true,
    token_required: false,
    token_present: true,
    records_count: 98000,
    last_sync: '2026-11-20T18:45:00Z',
    status: 'ready',
  },
];

export function AdvisorySourcesView() {
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [selectedName, setSelectedName] = useState<string | null>('osv');
  const [manifestOpen, setManifestOpen] = useState(false);
  const [copiedManifest, setCopiedManifest] = useState(false);
  const [testingSource, setTestingSource] = useState<string | null>(null);

  const items = DEFAULT_SOURCES;

  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((item) => {
      const matchCat = categoryFilter === 'all' || item.category === categoryFilter;
      const matchSearch =
        !q ||
        item.name.toLowerCase().includes(q) ||
        item.display_name.toLowerCase().includes(q) ||
        item.provider.toLowerCase().includes(q) ||
        item.description.toLowerCase().includes(q);
      return matchCat && matchSearch;
    });
  }, [items, search, categoryFilter]);

  const selectedSource = items.find((s) => s.name === selectedName) ?? null;

  const activeCount = items.filter((s) => s.enabled).length;
  const disabledCount = items.filter((s) => !s.enabled).length;
  const totalRecords = items.reduce((acc, s) => acc + (s.records_count ?? 0), 0);
  const manifest = buildAdvisoryManifest();

  const copyManifest = async () => {
    try {
      await navigator.clipboard.writeText(manifest);
      setCopiedManifest(true);
      setTimeout(() => setCopiedManifest(false), 1500);
    } catch {
      // ignore
    }
  };

  const handleTest = (name: string) => {
    setTestingSource(name);
    setTimeout(() => {
      setTestingSource(null);
    }, 1200);
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Top Banner & Metric Chips */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 text-12">
          <span className="text-13 text-ink-2">
            {activeCount} active, {disabledCount} disabled, {totalRecords.toLocaleString()} advisories indexed.
          </span>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="secondary" className="h-8 text-12" onClick={() => setManifestOpen(true)}>
            <IconCopy className="mr-1.5 h-3.5 w-3.5 text-ink-2" />
            CRD Manifest
          </Button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="w-72">
            <Input
              placeholder="Filter advisory sources..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-1 rounded border border-rule bg-surface p-0.5 text-12">
            {(['all', 'open', 'api', 'commercial'] as const).map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => setCategoryFilter(cat)}
                className={cn(
                  'rounded px-2.5 py-1 font-medium capitalize transition-colors',
                  categoryFilter === cat
                    ? 'bg-chrome text-ink shadow-2xs font-semibold'
                    : 'text-ink-2 hover:text-ink'
                )}
              >
                {cat === 'all' ? 'All Types' : cat}
              </button>
            ))}
          </div>
        </div>

        <span className="text-12 text-ink-2">
          {shown.length} of {items.length} sources
        </span>
      </div>

      {/* Main Split Table + Inspector Layout */}
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-hidden desktop:grid-cols-[1fr_360px]">
        {/* Table Area */}
        <div className="overflow-auto rounded-lg border border-rule bg-surface">
          {shown.length === 0 ? (
            <div className="p-8">
              <EmptyState title="No advisory sources match your filter">
                Try searching for another keyword or selecting All Types.
              </EmptyState>
            </div>
          ) : (
            <Table aria-label="Advisory Sources">
              <THead>
                <tr>
                  <Th>Source Name</Th>
                  <Th>Provider</Th>
                  <Th>Type</Th>
                  <Th>Token Status</Th>
                  <Th>Status</Th>
                  <Th align="end">Records</Th>
                </tr>
              </THead>
              <TBody>
                {shown.map((item) => {
                  const isSelected = item.name === selectedName;
                  return (
                    <Tr
                      key={item.name}
                      onClick={() => setSelectedName(item.name)}
                      className={cn(
                        'cursor-pointer transition-colors',
                        isSelected && 'bg-accent/10 dark:bg-accent/15'
                      )}
                    >
                      <Td className="font-medium text-ink">
                        <div className="flex flex-col">
                          <span className="font-semibold text-13">{item.display_name}</span>
                          <span className="font-mono text-12 text-ink-2">{item.name}</span>
                        </div>
                      </Td>
                      <Td className="text-12 text-ink-2">{item.provider}</Td>
                      <Td>
                        <span className="capitalize text-12 font-medium text-ink">
                          {item.category}
                        </span>
                      </Td>
                      <Td>
                        <span
                          className={cn(
                            'inline-flex items-center rounded px-2 py-0.5 text-12 font-medium',
                            item.token_required && item.token_present && 'bg-resolved/15 text-resolved',
                            item.token_required && !item.token_present && 'bg-medium/15 text-medium dark:text-medium',
                            !item.token_required && 'bg-chrome text-ink-2 border border-rule'
                          )}
                        >
                          {item.token_required
                            ? item.token_present
                              ? '✓ Present'
                              : '⚠ Missing'
                            : 'Open'}
                        </span>
                      </Td>
                      <Td>
                        <span
                          className={cn(
                            'text-12 font-medium capitalize',
                            item.status === 'error' ? 'text-critical' : item.status === 'disabled' ? 'text-ink-2' : 'text-ink'
                          )}
                        >
                          {item.status}
                        </span>
                      </Td>
                      <Td align="end" className="font-mono text-12 text-ink">
                        {item.records_count !== undefined
                          ? item.records_count.toLocaleString()
                          : '—'}
                      </Td>
                    </Tr>
                  );
                })}
              </TBody>
            </Table>
          )}
        </div>

        {/* Inspector Panel */}
        <div className="overflow-auto rounded-lg border border-rule bg-surface">
          <AdvisoryInspector
            source={selectedSource}
            onTest={handleTest}
            isTesting={testingSource !== null}
          />
        </div>
      </div>

      {/* CRD Manifest Dialog */}
      <Dialog open={manifestOpen} onOpenChange={setManifestOpen}>
        <DialogContent title="ClusterAdvisorySource Manifest" closeLabel="Close" className="max-w-2xl">
          <div className="flex items-center justify-between pb-2 border-b border-rule">
            <h3 className="text-14 font-semibold text-ink">ClusterAdvisorySource Manifest</h3>
            <Button variant="secondary" className="h-7 px-2 text-12" onClick={() => void copyManifest()}>
              {copiedManifest ? 'Copied' : 'Copy YAML'}
            </Button>
          </div>
          <p className="mt-2 text-12 text-ink-2">
            Declarative Kubernetes CRD resource to manage advisory report sources, ecosystems, and API tokens.
          </p>
          <pre className="mt-3 max-h-96 overflow-auto rounded bg-chrome p-3 font-mono text-12 text-ink border border-rule">
            <code>{manifest}</code>
          </pre>
        </DialogContent>
      </Dialog>
    </div>
  );
}
