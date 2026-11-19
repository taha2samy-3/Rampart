import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { get, post, qk, toProblem } from '@/api';
import type { InventoryAsset } from '@/api/types';
import {
  Button,
  EmptyState,
  IconRefresh,
  Input,
  ProblemMessage,
  Spinner,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from '@/components';

interface ComponentRow {
  asset_id?: string;
  asset_name?: string;
  application_name?: string;
  track?: string;
  purl: string;
  name: string;
  version: string;
  type: string;
  license?: string;
  vulnerabilities: number;
}

/** The package url without its version and qualifiers, which is what the purl: filter matches by prefix. */
const purlBase = (purl: string) => purl.split(/[@?#]/)[0] ?? purl;

export function InventoryRoute() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<'assets' | 'components'>('assets');
  const [search, setSearch] = useState('');
  const [scanningPurl, setScanningPurl] = useState<string | null>(null);
  const [scanFeedback, setScanFeedback] = useState<{ purl: string; message: string; ok: boolean } | null>(null);

  useEffect(() => {
    document.title = `${t('nav.inventory', { defaultValue: 'Inventory' })} · Rampart`;
  }, [t]);

  const assetsQuery = useQuery({
    queryKey: qk.inventory.all(),
    queryFn: async ({ signal }) => {
      // A failed load used to come back as an empty list, so a missing endpoint looked like "no assets yet".
      const res = await get<{ assets: InventoryAsset[] | null }>('/api/v1/inventory', { signal });
      return res.assets ?? [];
    },
  });

  const componentsQuery = useQuery({
    queryKey: ['inventory', 'components'],
    queryFn: async ({ signal }) => {
      const res = await get<{ components: ComponentRow[] | null; total?: number; truncated?: boolean }>('/api/v1/inventory/components', { signal });
      return { rows: res.components ?? [], total: res.total ?? (res.components ?? []).length, truncated: res.truncated ?? false };
    },
  });

  const handleScanComponent = async (c: ComponentRow) => {
    try {
      setScanningPurl(c.purl);
      const res = await post<{ status: string; message: string; purl: string }>('/api/v1/inventory/components/scan', {
        purl: c.purl,
        name: c.name,
        version: c.version,
        asset_id: c.asset_id,
        force: true,
      });
      setScanFeedback({
        purl: c.purl,
        message: res.message || t('inventory.scanInitiated', { name: c.name, defaultValue: `On-demand scan initiated for ${c.name}` }),
        ok: true,
      });
      void componentsQuery.refetch();
    } catch (err) {
      const prob = toProblem(err);
      setScanFeedback({
        purl: c.purl,
        message: prob.detail || t('inventory.scanFailed', { name: c.name, defaultValue: `Failed to initiate scan for ${c.name}` }),
        ok: false,
      });
    } finally {
      setScanningPurl(null);
    }
  };

  const components = componentsQuery.data?.rows ?? [];
  const lowerSearch = search.trim().toLowerCase();

  const assets = (assetsQuery.data ?? []).filter((a) =>
    !lowerSearch ||
    a.name.toLowerCase().includes(lowerSearch) ||
    (a.application_name && a.application_name.toLowerCase().includes(lowerSearch))
  );

  const filteredComponents = components.filter((c) =>
    !lowerSearch ||
    c.name.toLowerCase().includes(lowerSearch) ||
    c.purl.toLowerCase().includes(lowerSearch) ||
    c.type.toLowerCase().includes(lowerSearch) ||
    c.version.toLowerCase().includes(lowerSearch) ||
    (c.application_name ?? '').toLowerCase().includes(lowerSearch) ||
    (c.track ?? '').toLowerCase().includes(lowerSearch)
  );

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto p-6">
      <div className="mb-6 flex flex-col gap-1">
        <h1 className="display text-20 font-semibold text-ink">
          {t('nav.inventory', { defaultValue: 'Software & Asset Inventory' })}
        </h1>
        <p className="text-13 text-ink-2">
          {t('inventory.subtitle', { defaultValue: 'Explore scanned repositories, container images, hosts, and third-party software bill of materials (SBOM) packages.' })}
        </p>
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as 'assets' | 'components')} className="flex flex-col gap-4">
        <div className="flex items-center justify-between border-b border-rule">
          <TabsList label="Inventory Tabs">
            <TabsTrigger value="assets">
              {t('inventory.assetsTab', { defaultValue: 'Assets & Targets' })}
            </TabsTrigger>
            <TabsTrigger value="components">
              {t('inventory.componentsTab', { defaultValue: 'SBOM Packages & Dependencies' })}
            </TabsTrigger>
          </TabsList>
          <div className="w-64 pb-2">
            <Input
              placeholder="Filter inventory..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>

        <TabsContent value="assets" className="flex flex-col gap-4">
          {assetsQuery.isLoading ? (
            <div className="flex h-48 items-center justify-center">
              <Spinner />
            </div>
          ) : assetsQuery.isError ? (
            <ProblemMessage problem={toProblem(assetsQuery.error)} title={t('inventory.loadFailed')} onRetry={() => void assetsQuery.refetch()} />
          ) : assets.length === 0 ? (
            <EmptyState title="No matching assets found">
              Assets automatically populate when SARIF, CycloneDX, or container scanner reports are ingested.
            </EmptyState>
          ) : (
            <Table aria-label="Assets table">
              <THead>
                <tr>
                  <Th>Asset / Target</Th>
                  <Th>Kind</Th>
                  <Th>Application</Th>
                  <Th align="end">Critical</Th>
                  <Th align="end">High</Th>
                  <Th align="end">Total Findings</Th>
                </tr>
              </THead>
              <TBody>
                {assets.map((ast) => (
                  <Tr key={ast.id} className="h-12">
                    <Td className="font-medium text-ink">
                      <Link
                        to="/findings"
                        search={{ q: `asset:${ast.id}` }}
                        className="text-accent no-underline hover:underline font-mono text-12"
                      >
                        {ast.name}
                      </Link>
                    </Td>
                    <Td className="text-12 text-ink-2 capitalize">{ast.kind}</Td>
                    <Td className="text-12 text-ink">{ast.application_name || '—'}</Td>
                    <Td align="end" className="text-12 font-medium text-critical">
                      {ast.critical_findings}
                    </Td>
                    <Td align="end" className="text-12 font-medium text-high">
                      {ast.high_findings}
                    </Td>
                    <Td align="end" className="text-12 font-medium text-ink">
                      {ast.total_findings}
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </TabsContent>

        <TabsContent value="components" className="flex flex-col gap-4">
          {scanFeedback && (
            <div
              role="status"
              className={`flex items-center justify-between rounded border px-3 py-2 text-12 font-medium ${
                scanFeedback.ok
                  ? 'border-resolved/20 bg-resolved/10 text-resolved'
                  : 'border-critical/20 bg-critical/10 text-critical'
              }`}
            >
              <span>{scanFeedback.message}</span>
              <button
                type="button"
                onClick={() => setScanFeedback(null)}
                className="ml-2 text-12 opacity-70 hover:opacity-100"
                aria-label="Dismiss scan status"
              >
                ✕
              </button>
            </div>
          )}
          {componentsQuery.isLoading ? (
            <div className="flex h-48 items-center justify-center">
              <Spinner />
            </div>
          ) : componentsQuery.isError ? (
            <ProblemMessage problem={toProblem(componentsQuery.error)} title={t('inventory.loadFailed')} onRetry={() => void componentsQuery.refetch()} />
          ) : filteredComponents.length === 0 ? (
            <EmptyState title="No matching components found">
              {search.trim()
                ? "Try adjusting your search query."
                : "Packages and dependencies automatically populate when SBOM reports (CycloneDX or SPDX) are ingested."}
            </EmptyState>
          ) : (
            <>
            {componentsQuery.data?.truncated && (
              <p className="m-0 text-12 text-ink-2">{t('inventory.truncated', { shown: components.length, total: componentsQuery.data.total })}</p>
            )}
            <Table aria-label="Components table">
              <THead>
                <tr>
                  <Th>Package Name</Th>
                  <Th>Version</Th>
                  <Th>Ecosystem</Th>
                  <Th>Application</Th>
                  <Th>Asset</Th>
                  <Th>Track</Th>
                  <Th>License</Th>
                  <Th align="end">Vulnerabilities</Th>
                  <Th align="end">Actions</Th>
                </tr>
              </THead>
              <TBody>
                {filteredComponents.map((c) => (
                  <Tr key={`${c.asset_id ?? ''}|${c.track ?? ''}|${c.purl}`} className="h-12">
                    <Td className="font-medium text-ink">
                      <div className="flex flex-col">
                        <span className="font-mono text-12">{c.name}</span>
                        <span className="text-12 text-ink-2 truncate max-w-sm">{c.purl}</span>
                      </div>
                    </Td>
                    <Td className="font-mono text-12 text-ink-2">{c.version}</Td>
                    <Td className="text-12 text-ink-2 uppercase">{c.type}</Td>
                    <Td className="text-12 text-ink">{c.application_name || '—'}</Td>
                    <Td className="text-12 text-ink-2">
                      <span className="block max-w-[14rem] truncate" title={c.asset_name}>{c.asset_name || '—'}</span>
                    </Td>
                    <Td className="font-mono text-12 text-ink-2">{c.track || '—'}</Td>
                    <Td className="text-12 text-ink-2">{c.license || 'Unknown'}</Td>
                    <Td align="end">
                      <Link
                        to="/findings"
                        search={{ q: `purl:"${purlBase(c.purl)}"` }}
                        className="text-12 font-medium text-accent hover:underline"
                      >
                        {c.vulnerabilities > 0 ? `${c.vulnerabilities} open` : 'Clean'}
                      </Link>
                    </Td>
                    <Td align="end">
                      <Button
                        variant="ghost"
                        disabled={scanningPurl !== null}
                        loading={scanningPurl === c.purl}
                        onClick={() => void handleScanComponent(c)}
                        className="h-7 px-2.5 text-12 flex items-center gap-1 text-accent hover:text-accent hover:bg-accent/10"
                        title={t('inventory.scanNowTooltip', {
                          name: c.name,
                          defaultValue: `Force on-demand vulnerability scan for ${c.name}`,
                        })}
                        aria-label={`Scan ${c.name}`}
                      >
                        <IconRefresh className="size-3" />
                        <span>{t('inventory.scanNow', { defaultValue: 'Scan Now' })}</span>
                      </Button>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
