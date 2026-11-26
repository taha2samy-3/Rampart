import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { listTickets, qk, toProblem } from '@/api';
import { EmptyState, ProblemMessage, Spinner, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { absoluteDateTime } from '@/lib/format';

export function TicketsQueueView() {
  const { t } = useTranslation();
  const q = useQuery({
    queryKey: qk.tickets.list(),
    queryFn: ({ signal }) => listTickets(signal),
  });

  if (q.isPending) {
    return (
      <div className="flex items-center gap-2 py-8 text-13 text-ink-2">
        <Spinner size={16} /> Loading tickets & outbox…
      </div>
    );
  }
  if (q.isError) {
    return <ProblemMessage problem={toProblem(q.error)} title="Could not load tickets queue" onRetry={() => void q.refetch()} className="mt-4" />;
  }

  const data = q.data;
  if (!data?.configured) {
    return (
      <EmptyState title={t('ticketing.queueNotConfigured')} className="mt-6">
        {t('ticketing.queueNotConfiguredHint')}
      </EmptyState>
    );
  }

  return (
    <div className="mt-4 space-y-8">
      <section aria-labelledby="tq-outbox-heading">
        <div className="mb-2 flex items-baseline justify-between">
          <h2 id="tq-outbox-heading" className="text-14 font-semibold text-ink">Outbox Queue</h2>
          <span className="text-12 text-ink-2">Live updates via SSE</span>
        </div>
        {data.outbox.length === 0 ? (
          <EmptyState title="Outbox is clear">No pending or failed ticket creations in the queue.</EmptyState>
        ) : (
          <Table aria-label="Ticket outbox table">
            <THead>
              <Tr>
                <Th>Finding</Th>
                <Th>Severity</Th>
                <Th>Status</Th>
                <Th className="text-right">Attempts</Th>
                <Th>Last error</Th>
                <Th>Updated</Th>
              </Tr>
            </THead>
            <TBody>
              {data.outbox.map((row) => (
                <Tr key={row.finding_id}>
                  <Td className="font-medium text-ink">{row.finding_title || row.finding_id}</Td>
                  <Td className="text-12 text-ink-2">{row.severity || '—'}</Td>
                  <Td className="text-12">
                    <span className={row.status === 'failed' ? 'font-medium text-critical' : 'text-ink-2'}>{row.status}</span>
                  </Td>
                  <Td className="text-right font-mono tabular-nums">{row.attempts}</Td>
                  <Td className="max-w-xs truncate font-mono text-12 text-critical" title={row.last_error || ''}>
                    {row.last_error || '—'}
                  </Td>
                  <Td className="font-mono text-12 text-ink-2">{absoluteDateTime(row.updated_at)}</Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </section>

      <section aria-labelledby="tq-opened-heading">
        <h2 id="tq-opened-heading" className="mb-2 text-14 font-semibold text-ink">Opened Tickets</h2>
        {data.tickets.length === 0 ? (
          <EmptyState title="No tickets opened yet">Tickets created for critical findings, groups, or attestation renewals will appear here.</EmptyState>
        ) : (
          <Table aria-label="Opened tickets table">
            <THead>
              <Tr>
                <Th>Reference</Th>
                <Th>Binding</Th>
                <Th>State</Th>
                <Th className="text-right">Findings</Th>
                <Th>Updated</Th>
              </Tr>
            </THead>
            <TBody>
              {data.tickets.map((row) => (
                <Tr key={row.id}>
                  <Td className="font-mono text-12">
                    {row.url ? (
                      <a href={row.url} target="_blank" rel="noreferrer" className="text-accent hover:underline">
                        {row.external_ref}
                      </a>
                    ) : (
                      row.external_ref
                    )}
                  </Td>
                  <Td className="font-medium text-ink">{row.connector}</Td>
                  <Td className="text-12 text-ink-2">{row.state}</Td>
                  <Td className="text-right font-mono tabular-nums">{row.finding_count}</Td>
                  <Td className="font-mono text-12 text-ink-2">{absoluteDateTime(row.updated_at)}</Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </section>
    </div>
  );
}
