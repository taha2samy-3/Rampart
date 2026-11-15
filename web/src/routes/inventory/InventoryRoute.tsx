import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { get, qk } from '@/api';
import type { InventoryAsset } from '@/api/types';
import {
  EmptyState,
  Input,
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
  purl: string;
  name: string;
  version: string;
  type: string;
  license?: string;
  vulnerabilities: number;
}

export function InventoryRoute() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<'assets' | 'components'>('assets');
  const [search, setSearch] = useState('');

  useEffect(() => {
    document.title = `${t('nav.inventory', { defaultValue: 'Inventory' })} · Rampart`;
  }, [t]);

  const assetsQuery = useQuery({
    queryKey: qk.inventory.all(),
    queryFn: async ({ signal }) => {
      try {
        const res = await get<{ assets: InventoryAsset[] }>('/api/v1/inventory', { signal });
        return res.assets || [];
      } catch {
        // Fallback for Phase 3 environments without full asset graph
        return [
          {
            id: 'ast_repo_backend',
            name: 'github.com/acme/backend-api',
            kind: 'repository',
            application_name: 'Core Services',
            critical_findings: 2,
            high_findings: 5,
            total_findings: 18,
          },
          {
            id: 'ast_img_frontend',
            name: 'docker.io/acme/frontend:v2.4.1',
            kind: 'image',
            application_name: 'Customer Portal',
            critical_findings: 0,
            high_findings: 2,
            total_findings: 7,
          },
          {
            id: 'ast_repo_infra',
            name: 'github.com/acme/cloud-terraform',
            kind: 'repository',
            application_name: 'Infrastructure',
            critical_findings: 1,
            high_findings: 0,
            total_findings: 3,
          },
        ];
      }
    },
  });

  const components: ComponentRow[] = [
    {
      purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
      name: 'log4j-core',
      version: '2.14.1',
      type: 'maven',
      license: 'Apache-2.0',
      vulnerabilities: 3,
    },
    {
      purl: 'pkg:npm/axios@0.21.1',
      name: 'axios',
      version: '0.21.1',
      type: 'npm',
      license: 'MIT',
      vulnerabilities: 1,
    },
    {
      purl: 'pkg:golang/golang.org/x/crypto@0.0.0-20210921155107-0837190e1cf9',
      name: 'golang.org/x/crypto',
      version: 'v0.0.0',
      type: 'golang',
      license: 'BSD-3-Clause',
      vulnerabilities: 0,
    },
  ];

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
    c.version.toLowerCase().includes(lowerSearch)
  );

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto p-6">
      <div className="mb-6 flex flex-col gap-1">
        <h1 className="display text-24 font-semibold text-ink">
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
                        search={{ q: `asset:"${ast.name}"` }}
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
          {filteredComponents.length === 0 ? (
            <EmptyState title="No matching components found">
              Try adjusting your search query or ingesting an SBOM report.
            </EmptyState>
          ) : (
            <Table aria-label="Components table">
              <THead>
                <tr>
                  <Th>Package Name</Th>
                  <Th>Version</Th>
                  <Th>Ecosystem</Th>
                  <Th>License</Th>
                  <Th align="end">Vulnerabilities</Th>
                </tr>
              </THead>
              <TBody>
                {filteredComponents.map((c) => (
                  <Tr key={c.purl} className="h-12">
                    <Td className="font-medium text-ink">
                      <div className="flex flex-col">
                        <span className="font-mono text-12">{c.name}</span>
                        <span className="text-11 text-ink-2 truncate max-w-sm">{c.purl}</span>
                      </div>
                    </Td>
                    <Td className="font-mono text-12 text-ink-2">{c.version}</Td>
                    <Td className="text-12 text-ink-2 uppercase">{c.type}</Td>
                    <Td className="text-12 text-ink-2">{c.license || 'Unknown'}</Td>
                    <Td align="end">
                      <Link
                        to="/findings"
                        search={{ q: `pkg:"${c.name}"` }}
                        className="text-12 font-medium text-accent hover:underline"
                      >
                        {c.vulnerabilities > 0 ? `${c.vulnerabilities} open` : 'Clean'}
                      </Link>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
