import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { get, qk } from '@/api';
import type { ConnectorSummary, IntegrationPackageItem } from '@/api/types';
import {
  Button,
  EmptyState,
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
import { ConnectorCatalogueDialog } from './ConnectorCatalogueDialog';
import { FeedsView } from './FeedsView';

export function IntegrationsRoute() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<'connectors' | 'feeds' | 'tokens'>('connectors');
  const [catalogueOpen, setCatalogueOpen] = useState(false);
  useEffect(() => {
    document.title = `${t('nav.integrations', { defaultValue: 'Integrations' })} · Rampart`;
  }, [t]);

  // Connectors list
  const connectorsQuery = useQuery({
    queryKey: qk.connectors.list(),
    // No fallback list: a connector shown here exists on the server, with the status the operator wrote (D82).
    queryFn: async ({ signal }): Promise<ConnectorSummary[]> =>
      (await get<{ items?: ConnectorSummary[] }>('/api/v1/connectors', { signal })).items ?? [],
  });

  const connectors = connectorsQuery.data ?? [];
  const packagesQuery = useQuery({
    queryKey: qk.connectors.packages(),
    queryFn: async ({ signal }): Promise<IntegrationPackageItem[]> =>
      (await get<{ items?: IntegrationPackageItem[] }>('/api/v1/integration-packages', { signal })).items ?? [],
  });
  const packages = packagesQuery.data ?? [];

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto p-6">
      <div className="mb-6 flex flex-col gap-1">
        <h1 className="display text-24 font-semibold text-ink">
          {t('nav.integrations', { defaultValue: 'Integrations & External Systems' })}
        </h1>
        <p className="text-13 text-ink-2">
          {t('integrations.subtitle', { defaultValue: 'Manage bidirectional issue trackers, upstream telemetry sources, and programmatic API tokens.' })}
        </p>
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as 'connectors' | 'feeds' | 'tokens')} className="flex flex-col gap-4">
        <TabsList label="Integrations Tabs">
          <TabsTrigger value="connectors">
            {t('integrations.connectorsTab', { defaultValue: 'Connectors & Trackers' })}
          </TabsTrigger>
          <TabsTrigger value="feeds">
            {t('integrations.feedsTab', { defaultValue: 'Vulnerability Feeds' })}
          </TabsTrigger>
          <TabsTrigger value="tokens">
            {t('integrations.tokensTab', { defaultValue: 'API Tokens' })}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="connectors" className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <span className="text-13 text-ink-2">
              Configured connectors synchronise tickets, alerts, and SBOM data with external services.
            </span>
            <Button variant="primary" onClick={() => setCatalogueOpen(true)}>
              + New Connector
            </Button>
          </div>

          {connectorsQuery.isError ? (
            <p role="alert" className="text-13 text-ink-2">
              The connectors could not be loaded.
            </p>
          ) : connectorsQuery.isLoading ? (
            <div className="flex h-48 items-center justify-center">
              <Spinner />
            </div>
          ) : connectors.length === 0 ? (
            <EmptyState title="No connectors configured">
              Connectors are declared via `Connector` CRDs in Kubernetes.
            </EmptyState>
          ) : (
            <Table aria-label="Connectors table">
              <THead>
                <tr>
                  <Th>Name</Th>
                  <Th>Type</Th>
                  <Th>Direction</Th>
                  <Th>Status</Th>
                  <Th>Last check</Th>
                </tr>
              </THead>
              <TBody>
                {connectors.map((c) => {
                  const connected = c.status?.conditions?.find((cond) => cond.type === 'Connected');
                  // The operator's Check result (D69): True, False, or not run yet.
                  const state = connected?.status === 'True' ? 'ok' : connected?.status === 'False' ? 'failing' : 'unknown';
                  return (
                    <Tr key={c.name} className="h-12">
                      <Td className="font-medium text-ink">{c.name}</Td>
                      <Td className="text-12 text-ink-2">
                        {c.type === 'plugin' && c.spec?.plugin?.name ? `Package ${c.spec.plugin.name}` : c.type}
                      </Td>
                      <Td className="text-12 text-ink-2 capitalize">{c.direction}</Td>
                      <Td className={state === 'failing' ? 'font-medium text-ink' : 'text-ink-2'}>
                        {/* plain words, no pill: colour is for risk (docs/13 §6) */}
                        {state === 'ok' ? 'Connected' : state === 'failing' ? 'Failing' : 'Not checked yet'}
                      </Td>
                      <Td className="text-12 text-ink-2">
                        {connected?.message || '—'}
                      </Td>
                    </Tr>
                  );
                })}
              </TBody>
            </Table>
          )}
          <section aria-labelledby="pkg-heading" className="mt-6 flex flex-col gap-2">
            <h2 id="pkg-heading" className="text-16 font-semibold">
              Installed packages
            </h2>
            <p className="max-w-[72ch] text-13 text-ink-2">
              A package describes a tool as data. A notifier package gives the request it sends, the secrets it needs and
              the hosts it may reach; a Connector of type plugin names it. A parser package maps a report format to
              findings; uploads use it by name or when it recognises the file. Apply either in your namespace. No Rampart
              release is needed.
            </p>
            {packagesQuery.isError ? (
              <p role="alert" className="text-13 text-ink-2">The packages could not be loaded.</p>
            ) : packages.length === 0 ? (
              <p className="text-13 text-ink-2">
                None installed. The connector catalogue has an example under Installed package.
              </p>
            ) : (
              <Table aria-label="Installed packages">
                <THead>
                  <tr>
                    <Th>Package</Th>
                    <Th>What it is</Th>
                    <Th>May reach</Th>
                    <Th>Used by</Th>
                    <Th>State</Th>
                  </tr>
                </THead>
                <TBody>
                  {packages.map((p) => (
                    <Tr key={p.name}>
                      <Td>
                        <span className="text-13 font-medium text-ink">{p.name}</span>
                        {p.description && <span className="block text-12 text-ink-2">{p.description}</span>}
                      </Td>
                      <Td className="text-13 text-ink-2">
                        {p.runtime} {p.kind} {p.version}
                        {(p.secrets ?? []).length > 0 && <span className="block text-12">needs {(p.secrets ?? []).join(', ')}</span>}
                      </Td>
                      <Td className="font-mono text-12 text-ink-2">{(p.egress ?? []).join(', ') || 'nothing'}</Td>
                      <Td className="text-13 text-ink-2">
                        {p.kind === 'parser'
                          ? `uploads named ${p.name}, or detected`
                          : (p.used_by ?? []).length
                            ? (p.used_by ?? []).join(', ')
                            : 'no connector'}
                      </Td>
                      <Td className={p.error ? 'whitespace-normal text-13 font-medium text-ink' : 'text-13 text-ink-2'}>
                        {p.error ? `Not used: ${p.error}` : 'Installed'}
                      </Td>
                    </Tr>
                  ))}
                </TBody>
              </Table>
            )}
          </section>
          {/* Connector Catalogue Modal */}
          <ConnectorCatalogueDialog
            open={catalogueOpen}
            onOpenChange={setCatalogueOpen}
          />
        </TabsContent>

        <TabsContent value="feeds" className="flex flex-col gap-4">
          <FeedsView />
        </TabsContent>

        <TabsContent value="tokens" className="flex flex-col gap-3">
          {/* There is no token API yet (docs/23, D82): this page says how tokens are issued instead of pretending to. */}
          <p className="text-13 text-ink">API tokens are not listed or issued from this page yet.</p>
          <ul className="flex list-disc flex-col gap-1 ps-5 text-13 text-ink-2">
            <li>
              For a CI pipeline, use CI federation: a trust rule on the <code>ScanSource</code> lets GitHub or GitLab exchange its
              own token for a 15-minute ingest token, with no stored secret.
            </li>
            <li>
              For the CLI, sign in with <code>rampart login</code>, which uses the device flow and your single sign-on.
            </li>
          </ul>
        </TabsContent>
      </Tabs>
    </div>
  );
}
