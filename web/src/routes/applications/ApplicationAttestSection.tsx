import { useState } from 'react';
import { useMutation, useQuery, useQueries, useQueryClient } from '@tanstack/react-query';
import { getApplicationCompliance, getTaxonomyStatus, qk, retryAttestationTicket, toProblem } from '@/api';
import type { ApplicationPage, ControlStatus } from '@/api/types';
import { Button, EmptyState, ProblemMessage, Skeleton, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { useAccess } from '@/app/useAccess';
import { AttestDialog } from '../compliance/ComplianceRoute';
import { absoluteDate } from '@/lib/format';

const READING: Record<string, string> = {
  clear: 'Met',
  open: 'Not met',
  at_risk: 'At risk',
  not_assessed: 'Not attested',
};

/**
 * A person's reading of the manual controls of this application's frameworks (docs/16 D102, item 8). Only a control
 * the framework marks `manual` can be attested, and the attestation is of that control, for this application. The
 * automatic controls are read from findings and scans and are shown in the Compliance section above.
 */
export function ApplicationAttestSection({ app }: { app: ApplicationPage }) {
  const { can } = useAccess();
  const mayAttest = can(app.id, 'maintainer');
  const mayRetry = can(undefined, 'admin'); // the ticket is opened on the tenant's tracker, with its credentials
  const qc = useQueryClient();
  const retry = useMutation({
    mutationFn: (attestationId: string) => retryAttestationTicket(attestationId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['taxonomies', 'status'] }),
  });
  const [attesting, setAttesting] = useState<{ framework: string; control: ControlStatus } | null>(null);

  const compliance = useQuery({
    queryKey: qk.applications.compliance(app.id),
    queryFn: ({ signal }) => getApplicationCompliance(app.id, signal),
  });
  const frameworks = compliance.data?.frameworks ?? [];
  const statuses = useQueries({
    queries: frameworks.map((fw) => ({
      queryKey: qk.taxonomyStatus(fw.id, app.id, ''),
      queryFn: ({ signal }: { signal: AbortSignal }) => getTaxonomyStatus(fw.id, app.id, signal, ''),
      retry: false,
    })),
  });
  const loading = compliance.isLoading || statuses.some((s) => s.isLoading);
  const failed = statuses.flatMap((s, i) => (s.isError ? [{ fw: frameworks[i]!, s }] : []));

  const rows = frameworks.flatMap((fw, i) =>
    (statuses[i]?.data?.status ?? []).filter((c) => c.manual).map((c) => ({ fw, control: c })),
  );

  return (
    <section className="mt-8 border-t border-rule pt-6" aria-labelledby="app-attest-section">
      <h2 id="app-attest-section" className="text-16 font-semibold text-ink">Manual controls</h2>
      <p className="m-0 text-12 text-ink-2">
        Controls that no scan can read, such as a threat-model sign-off. A maintainer records whether each is met for this
        application, with what was checked and when the reading ends.
      </p>
      <div className="mt-4">
        {loading ? (
          <Skeleton className="h-24 w-full" />
        ) : compliance.isError ? (
          <ProblemMessage problem={toProblem(compliance.error)} title="Failed to load compliance status" onRetry={() => void compliance.refetch()} />
        ) : rows.length === 0 && failed.length === 0 ? (
          <EmptyState title="No manual controls">
            {frameworks.length === 0
              ? 'This application is in no compliance framework yet.'
              : <>None of the frameworks this application is in has a control marked <code>manual: true</code>. Add one to a ComplianceFramework to record a sign-off here.</>}
          </EmptyState>
        ) : (
          <>
          {failed.map(({ fw, s }) => (
            <ProblemMessage key={fw.id} problem={toProblem(s.error)} title={`The controls of ${fw.name} could not be loaded`} onRetry={() => void s.refetch()} />
          ))}
          {rows.length > 0 && <Table aria-label="Manual controls table">
            <THead>
              <tr>
                <Th>Framework</Th>
                <Th>Control</Th>
                <Th>Reading</Th>
                <Th>Owner</Th>
                <Th>In force until</Th>
                <Th>Renewal ticket</Th>
                <Th align="end">Actions</Th>
              </tr>
            </THead>
            <TBody>
              {rows.map(({ fw, control }) => (
                <Tr key={`${fw.id}/${control.id}`} className="h-11">
                  <Td className="text-12 text-ink-2">{fw.name}</Td>
                  <Td>
                    <div className="flex flex-col">
                      <span className="font-medium text-ink">{control.name}</span>
                      <span className="font-mono text-12 text-ink-2">{control.id}</span>
                    </div>
                  </Td>
                  <Td>
                    <span className="text-12 text-ink" title={control.reason}>{READING[control.status] ?? control.status}</span>
                  </Td>
                  <Td className="text-12 text-ink-2">
                    {control.attestation ? (control.attestation.owner || control.attestation.attested_by).replace(/^(user|team):/, '') : '—'}
                  </Td>
                  <Td className="text-12 text-ink-2">
                    {control.attestation && control.status !== 'not_assessed' ? absoluteDate(control.attestation.expires_at) : '—'}
                  </Td>
                  <Td className="text-12 text-ink-2">
                    <TicketCell control={control} mayRetry={mayRetry} busy={retry.isPending} onRetry={(id) => retry.mutate(id)} />
                  </Td>
                  <Td align="end">
                    {mayAttest ? (
                      <Button variant="ghost" onClick={() => setAttesting({ framework: fw.id, control })} className="h-7 px-2.5 text-12 text-accent hover:bg-accent/10 hover:text-accent">
                        {control.attestation ? 'Attest again' : 'Attest'}
                      </Button>
                    ) : (
                      <span className="text-12 text-ink-2" title="Recording an attestation needs the maintainer role on this application">Needs maintainer</span>
                    )}
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>}
          </>
        )}
      </div>
      {attesting && (
        <AttestDialog framework={attesting.framework} control={attesting.control} application={app.id} onClose={() => setAttesting(null)} />
      )}
    </section>
  );
}

/** The renewal ticket of the attestation in force, or why there is none. It is opened when the attestation ends within 14 days. */
function TicketCell({ control, mayRetry, busy, onRetry }: { control: ControlStatus; mayRetry: boolean; busy: boolean; onRetry: (attestationId: string) => void }) {
  const a = control.attestation;
  const t = a?.ticket;
  if (!a || a.status !== 'passed') return <span>—</span>;
  if (!t) return <span title="A ticket is opened 14 days before it ends, when the tenant has a tracker">Not yet</span>;
  if (t.status === 'opened')
    return t.url ? <a href={t.url} className="text-accent underline" target="_blank" rel="noreferrer">{t.ref || 'Open ticket'}</a> : <span>{t.ref}</span>;
  if (t.status === 'closed') return <span>Closed (renewed)</span>;
  if (t.status === 'reserved') return <span>Opening…</span>;
  return (
    <span className="flex flex-col items-start gap-1">
      <span className="text-critical dark:text-critical">Could not be opened</span>
      {t.error && <span className="max-w-[16rem] break-words text-12" title={t.error}>{t.error}</span>}
      {mayRetry && <Button variant="ghost" disabled={busy} onClick={() => onRetry(a.id)} className="h-6 px-2 text-12 text-accent">Try again</Button>}
    </span>
  );
}
