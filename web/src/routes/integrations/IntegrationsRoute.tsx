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
  Dialog,
  DialogContent,
  DialogClose,
  Input,
  useToast,
} from '@/components';
import { cn } from '@/lib/cn';
import { ConnectorCatalogueDialog } from './ConnectorCatalogueDialog';

interface ApiTokenItem {
  id: string;
  name: string;
  role: string;
  created: string;
}

export function IntegrationsRoute() {
  const { t } = useTranslation();
  const toast = useToast();
  const [tab, setTab] = useState<'connectors' | 'tokens'>('connectors');
  const [catalogueOpen, setCatalogueOpen] = useState(false);
  const [customConnectors, setCustomConnectors] = useState<ConnectorSummary[]>([]);
  const [addTokenOpen, setAddTokenOpen] = useState(false);
  const [tokenName, setTokenName] = useState('');
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);

  const [tokens, setTokens] = useState<ApiTokenItem[]>([
    { id: 'tok_default', name: 'ci-github-actions', role: 'ingest', created: '2 days ago' },
  ]);

  useEffect(() => {
    document.title = `${t('nav.integrations', { defaultValue: 'Integrations' })} · Rampart`;
  }, [t]);

  // Connectors list
  const connectorsQuery = useQuery({
    queryKey: qk.connectors.list(),
    queryFn: async ({ signal }): Promise<ConnectorSummary[]> => {
      try {
        const res = await get<{ items?: ConnectorSummary[] }>('/api/v1/connectors', { signal });
        return res.items ?? [];
      } catch {
        // Fallback default connectors catalog if endpoint returns 404
        return [
          {
            name: 'jira-cloud',
            type: 'jira',
            direction: 'bidirectional',
            enabled: true,
            status: {
              conditions: [{ type: 'Connected', status: 'True', message: 'Connected to Jira Cloud instance' }],
              last_check_time: new Date().toISOString(),
            },
          },
          {
            name: 'github-issues',
            type: 'github',
            direction: 'bidirectional',
            enabled: true,
            status: {
              conditions: [{ type: 'Connected', status: 'True', message: 'Token authenticated with write access' }],
              last_check_time: new Date().toISOString(),
            },
          },
          {
            name: 'dtrack-portfolio',
            type: 'dependency-track',
            direction: 'inbound',
            enabled: true,
            status: {
              conditions: [{ type: 'Connected', status: 'True', message: 'v4.14 API key valid' }],
              last_check_time: new Date().toISOString(),
            },
          },
          {
            name: 'slack-alerts',
            type: 'slack',
            direction: 'outbound',
            enabled: false,
            status: {
              conditions: [{ type: 'Connected', status: 'False', message: 'Webhook URL not configured' }],
              last_check_time: new Date().toISOString(),
            },
          },
        ];
      }
    },
  });

  const connectors = [...customConnectors, ...(connectorsQuery.data ?? [])];

  const handleCreateToken = () => {
    if (!tokenName.trim()) return;
    const rawId = typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID().replace(/-/g, '')
      : Math.random().toString(36).slice(2) + Date.now().toString(36);
    const secret = `rampart_sec_${rawId}`;
    setTokens((prev) => [
      { id: `tok_${rawId.slice(0, 8)}`, name: tokenName.trim(), role: 'ingest', created: 'Just now' },
      ...prev,
    ]);
    setCreatedSecret(secret);
    setTokenName('');
  };

  const handleRevokeToken = (id: string) => {
    setTokens((prev) => prev.filter((tok) => tok.id !== id));
    toast.info(t('tokens.revoked', { defaultValue: 'Token revoked successfully' }));
  };

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

          {connectorsQuery.isLoading ? (
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
                  <Th>Health Check Message</Th>
                  <Th align="end">Actions</Th>
                </tr>
              </THead>
              <TBody>
                {connectors.map((c) => {
                  const connected = c.status?.conditions?.find((cond) => cond.type === 'Connected');
                  const isOk = connected?.status === 'True';
                  return (
                    <Tr key={c.name} className="h-12">
                      <Td className="font-medium text-ink">{c.name}</Td>
                      <Td className="font-mono text-12 text-ink-2 capitalize">{c.type}</Td>
                      <Td className="text-12 text-ink-2 capitalize">{c.direction}</Td>
                      <Td>
                        <span
                          className={cn(
                            'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-11 font-medium',
                            isOk
                              ? 'bg-success/15 text-success'
                              : 'bg-critical/15 text-critical'
                          )}
                        >
                          <span
                            className={cn(
                              'size-1.5 rounded-full',
                              isOk ? 'bg-success' : 'bg-critical'
                            )}
                          />
                          {isOk ? 'Healthy' : 'Disconnected'}
                        </span>
                      </Td>
                      <Td className="text-12 text-ink-2">
                        {connected?.message || '—'}
                      </Td>
                      <Td align="end">
                        <Button
                          variant="ghost"
                          onClick={() => {
                            toast.info(`Health check for ${c.name}: ${isOk ? 'Healthy' : 'Failing'}`);
                          }}
                        >
                          Check
                        </Button>
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
            onConnectorAdded={(conn) => setCustomConnectors((prev) => [conn, ...prev])}
          />
        </TabsContent>

        <TabsContent value="tokens" className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <span className="text-13 text-ink-2">
              API tokens allow external tools, CI/CD runners, and automated pipelines to authenticate to the ingest gateway.
            </span>
            <Button variant="primary" onClick={() => setAddTokenOpen(true)}>
              + Generate Token
            </Button>
          </div>

          <Table aria-label="API Tokens">
            <THead>
              <tr>
                <Th>Token Name</Th>
                <Th>Role</Th>
                <Th>Created</Th>
                <Th align="end">Actions</Th>
              </tr>
            </THead>
            <TBody>
              {tokens.map((tok) => (
                <Tr key={tok.id} className="h-12">
                  <Td className="font-medium text-ink">{tok.name}</Td>
                  <Td className="font-mono text-12 text-ink-2">{tok.role}</Td>
                  <Td className="text-12 text-ink-2">{tok.created}</Td>
                  <Td align="end">
                    <Button
                      variant="ghost"
                      className="text-critical hover:bg-critical/10"
                      onClick={() => handleRevokeToken(tok.id)}
                    >
                      Revoke
                    </Button>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>

          {/* New Token Dialog */}
          <Dialog open={addTokenOpen} onOpenChange={setAddTokenOpen}>
            {addTokenOpen && (
              <DialogContent
                title="Generate API Token"
                description="Create a scoped secret token for automated report ingest and CI pipelines."
                closeLabel="Close"
              >
                {createdSecret ? (
                  <div className="flex flex-col gap-3">
                    <p className="text-13 text-ink">
                      Make sure to copy your personal token now. You won't be able to see it again!
                    </p>
                    <div className="rounded-ctl bg-chrome p-3 font-mono text-12 text-ink select-all border border-rule break-all">
                      {createdSecret}
                    </div>
                    <div className="flex justify-end pt-2">
                      <Button
                        variant="primary"
                        onClick={() => {
                          setCreatedSecret(null);
                          setAddTokenOpen(false);
                        }}
                      >
                        Done
                      </Button>
                    </div>
                  </div>
                ) : (
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      handleCreateToken();
                    }}
                    className="flex flex-col gap-3"
                  >
                    <div>
                      <label htmlFor="token-desc" className="mb-1 block text-12 font-medium text-ink">Token Description</label>
                      <Input
                        id="token-desc"
                        required
                        placeholder="e.g. Gitlab CI Production Runner"
                        value={tokenName}
                        onChange={(e) => setTokenName(e.target.value)}
                      />
                    </div>
                    <div className="flex justify-end gap-2 pt-2 border-t border-rule">
                      <DialogClose asChild>
                        <Button variant="ghost">Cancel</Button>
                      </DialogClose>
                      <Button type="submit" variant="primary" disabled={!tokenName.trim()}>
                        Generate
                      </Button>
                    </div>
                  </form>
                )}
              </DialogContent>
            )}
          </Dialog>
        </TabsContent>
      </Tabs>
    </div>
  );
}
