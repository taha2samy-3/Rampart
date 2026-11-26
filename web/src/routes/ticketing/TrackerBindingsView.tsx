import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { get, qk, toProblem } from '@/api';
import type { ConnectorSummary } from '@/api/types';
import { Button, EmptyState, ProblemMessage, Spinner, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { ConnectorCatalogueDialog } from '@/routes/integrations/ConnectorCatalogueDialog';

function isTrackerConnector(c: Pick<ConnectorSummary, 'type'>): boolean {
  return c.type === 'externalTracker' || c.type === 'jira' || c.type === 'github';
}

function bindingTarget(c: ConnectorSummary): string {
  const ext = c.spec?.externalTracker as { trackerRef?: { scope?: string; namespace?: string; name?: string }; defaultProject?: string } | undefined;
  if (c.type === 'externalTracker' && ext?.trackerRef?.name) {
    const scope = ext.trackerRef.scope || 'cluster';
    const proj = ext.defaultProject ? ` · ${ext.defaultProject}` : '';
    return `${scope}/${ext.trackerRef.name}${proj}`;
  }
  return c.type;
}

export function TrackerBindingsView() {
  const { t } = useTranslation();
  const [showCatalogue, setShowCatalogue] = useState(false);

  const q = useQuery({
    queryKey: qk.connectors.list(),
    queryFn: async ({ signal }) => (await get<{ items?: ConnectorSummary[] }>('/api/v1/connectors', { signal })).items ?? [],
  });

  if (q.isPending) {
    return (
      <div className="flex items-center gap-2 py-8 text-13 text-ink-2">
        <Spinner size={16} /> Loading tracker bindings…
      </div>
    );
  }
  if (q.isError) {
    return <ProblemMessage problem={toProblem(q.error)} title="Failed to load tracker bindings" onRetry={() => void q.refetch()} className="mt-4" />;
  }

  const trackers = (q.data ?? []).filter(isTrackerConnector);

  return (
    <div className="mt-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-13 text-ink-2">{t('ticketing.bindingsNote')}</p>
        <Button variant="primary" onClick={() => setShowCatalogue(true)}>
          {t('ticketing.newBinding')}
        </Button>
      </div>

      {trackers.length === 0 ? (
        <EmptyState title="No tracker bindings configured">
          Create a tenant Connector referencing a registered external tracker container with ticketing rules (`onCritical`, project mapping).
        </EmptyState>
      ) : (
        <Table aria-label="Tracker bindings table">
          <THead>
            <Tr>
              <Th>Connector</Th>
              <Th>Container / Kind</Th>
              <Th>Direction</Th>
              <Th>Status</Th>
              <Th>Message</Th>
            </Tr>
          </THead>
          <TBody>
            {trackers.map((c) => {
              const cond = c.status?.conditions?.find((x) => x.type === 'Connected');
              const connStatus = cond?.status ?? 'Unknown';
              const connMsg = cond?.message || (connStatus === 'Unknown' ? 'Not checked yet' : '');
              return (
                <Tr key={c.name}>
                  <Td className="font-medium text-ink">{c.name}</Td>
                  <Td className="font-mono text-12 text-ink-2">{bindingTarget(c)}</Td>
                  <Td className="text-12 text-ink-2">{c.direction}</Td>
                  <Td className="text-12">
                    {connStatus === 'True' ? (
                      <span className="font-medium text-accent">Connected</span>
                    ) : connStatus === 'False' ? (
                      <span className="font-medium text-critical">Failed ({cond?.reason || 'Error'})</span>
                    ) : (
                      <span className="text-ink-2">Not checked yet</span>
                    )}
                  </Td>
                  <Td className="max-w-xs truncate text-12 text-ink-2" title={connMsg}>{connMsg}</Td>
                </Tr>
              );
            })}
          </TBody>
        </Table>
      )}

      <ConnectorCatalogueDialog kindFilter="tracker" open={showCatalogue} onOpenChange={setShowCatalogue} />
    </div>
  );
}
