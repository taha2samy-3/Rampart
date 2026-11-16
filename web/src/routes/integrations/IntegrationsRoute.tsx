import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { get, qk } from '@/api';
import type { ConnectorSummary } from '@/api/types';
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
import { cn } from '@/lib/cn';
import { ConnectorCatalogueDialog } from './ConnectorCatalogueDialog';

export function IntegrationsRoute() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<'connectors' | 'tokens'>('connectors');
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

      <Tabs value={tab} onValueChange={(v) => setTab(v as 'connectors' | 'tokens')} className="flex flex-col gap-4">
        <TabsList label="Integrations Tabs">
          <TabsTrigger value="connectors">
            {t('integrations.connectorsTab', { defaultValue: 'Connectors & Trackers' })}
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
                      <Td className="font-mono text-12 text-ink-2 capitalize">{c.type}</Td>
                      <Td className="text-12 text-ink-2 capitalize">{c.direction}</Td>
                      <Td>
                        <span
                          className={cn(
                            'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-11 font-medium',
                            state === 'ok' && 'bg-success/15 text-success',
                            state === 'failing' && 'bg-critical/15 text-critical',
                            state === 'unknown' && 'bg-surface-2 text-ink-2',
                          )}
                        >
                          <span
                            className={cn(
                              'size-1.5 rounded-full',
                              state === 'ok' ? 'bg-success' : state === 'failing' ? 'bg-critical' : 'bg-ink-3',
                            )}
                          />
                          {state === 'ok' ? 'Connected' : state === 'failing' ? 'Failing' : 'Not checked yet'}
                        </span>
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
          {/* Connector Catalogue Modal */}
          <ConnectorCatalogueDialog
            open={catalogueOpen}
            onOpenChange={setCatalogueOpen}
          />
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
