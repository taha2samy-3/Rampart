import { useEffect, useId, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { confirmHeldClose, decideAcceptance, discardHeldClose, listAcceptances, listHeldCloses, listProofs, proofHref, qk, toProblem, uploadProof } from '@/api';
import type { AcceptanceStatus, HeldClose, RiskAcceptance } from '@/api/types';
import { Button, EmptyState, ProblemMessage, Select, Skeleton, Table, TBody, Td, Th, THead, Tr, useToast } from '@/components';
import { useSession } from '@/app/session';
import { useAccess } from '@/app/useAccess';
import { cn } from '@/lib/cn';
import { absoluteDate } from '@/lib/format';

export interface WorkflowSearch {
  tab?: 'acceptances' | 'held_closes';
  sel?: string;
  status?: AcceptanceStatus;
  run_id?: string;
}
const STATUSES: (AcceptanceStatus | '')[] = ['', 'pending', 'approved', 'rejected', 'expired', 'revoked'];

/** Risk acceptances and held mass-closes: what is waiting for approval or confirmation (docs/13, docs/21 Section 3.2). */
export function WorkflowRoute({ search }: { search: WorkflowSearch }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const tab = search.tab ?? 'acceptances';

  useEffect(() => {
    document.title = `${tab === 'held_closes' ? 'Held Closes' : t('acceptance.workflow')} - Rampart`;
  }, [t, tab]);

  const set = (patch: Partial<WorkflowSearch>) => void navigate({ to: '/workflow', search: (p: WorkflowSearch) => ({ ...p, ...patch }), replace: true });

  if (tab === 'held_closes') {
    return <HeldClosesView search={search} set={set} />;
  }

  return <AcceptancesView search={search} set={set} />;
}

function AcceptancesView({ search, set }: { search: WorkflowSearch; set: (patch: Partial<WorkflowSearch>) => void }) {
  const { t } = useTranslation();
  const status = search.status ?? '';
  const q = useQuery({ queryKey: qk.acceptances.list(status), queryFn: ({ signal }) => listAcceptances(status, signal) });
  const rows = q.data ?? [];
  const selected = rows.find((r) => r.id === search.sel);

  let list: React.ReactNode;
  if (q.isPending) {
    list = (
      <div className="flex-1" aria-busy="true" aria-label={t('common.loading')}>
        {Array.from({ length: 5 }, (_, i) => (
          <div key={i} className="flex h-[46px] items-center gap-3 border-b border-rule px-3"><Skeleton className="h-3 flex-1" /></div>
        ))}
      </div>
    );
  } else if (q.isError) {
    list = <div className="p-4"><ProblemMessage problem={toProblem(q.error)} title={t('acceptance.loadFailed')} onRetry={() => void q.refetch()} /></div>;
  } else if (rows.length === 0) {
    list = <EmptyState title={t('acceptance.emptyTitle')}>{t('acceptance.emptyBody')}</EmptyState>;
  } else {
    const tabbable = selected?.id ?? rows[0]?.id;
    list = (
      <div className="min-h-0 flex-1 overflow-auto">
        <Table role="grid" aria-label={t('acceptance.tableLabel')} aria-rowcount={rows.length}>
          <colgroup><col /><col className="w-[160px]" /><col className="w-[110px]" /><col className="w-[72px]" /></colgroup>
          <THead className="sticky top-0 z-10">
            <tr role="row">
              <Th>{t('acceptance.colWhy')}</Th>
              <Th>{t('acceptance.colStatus')}</Th>
              <Th>{t('acceptance.colFindings')}</Th>
              <Th align="end">{t('acceptance.colUntil')}</Th>
            </tr>
          </THead>
          <TBody>
            {rows.map((r, i) => (
              <Tr
                key={r.id}
                data-row-id={r.id}
                aria-rowindex={i + 2}
                selected={r.id === selected?.id}
                tabIndex={r.id === tabbable ? 0 : -1}
                onClick={() => set({ sel: r.id })}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    set({ sel: r.id });
                  }
                }}
                className="h-[46px] cursor-default align-middle focus-visible:outline-offset-[-2px]"
              >
                <Td className={cn('py-0', r.id === selected?.id && 'shadow-[inset_3px_0_0_var(--accent)]')}>
                  <span className="block truncate font-medium">{r.justification}</span>
                  <span className="block truncate text-[11.5px] leading-4 text-ink-2">{r.owner}</span>
                </Td>
                <Td>{t(`acceptance.status.${r.status}`)}</Td>
                <Td className="text-ink-2">{t('acceptance.covers', { count: r.finding_ids.length })}</Td>
                <Td align="end" className="text-ink-2" title={absoluteDate(r.expires_at)}>{absoluteDate(r.expires_at)}</Td>
              </Tr>
            ))}
          </TBody>
        </Table>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col tablet:flex-row">
      <section aria-label={t('acceptance.list')} className="flex min-h-0 min-w-0 flex-1 basis-3/5 flex-col tablet:basis-auto">
        <div className="flex items-center gap-3 border-b border-rule px-3 py-2">
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => set({ tab: 'acceptances', sel: undefined })}
              className="rounded-ctl bg-surface px-2.5 py-1 text-13 font-semibold text-ink shadow-sm"
            >
              {t('acceptance.tabAcceptances', { defaultValue: 'Risk Acceptances' })}
            </button>
            <button
              type="button"
              onClick={() => set({ tab: 'held_closes', sel: undefined })}
              className="rounded-ctl px-2.5 py-1 text-13 font-medium text-ink-2 transition-colors hover:text-ink"
            >
              {t('acceptance.tabHeldCloses', { defaultValue: 'Held Closes' })}
            </button>
          </div>
          <Select
            className="ms-auto w-[200px]"
            label={t('acceptance.filter')}
            value={status}
            onValueChange={(v) => set({ status: (v || undefined) as AcceptanceStatus | undefined, sel: undefined })}
            options={STATUSES.map((s) => ({ value: s, label: t(`acceptance.filters.${s}`) }))}
          />
        </div>
        {list}
      </section>
      <div className="min-h-[200px] shrink-0 basis-2/5 border-t border-rule bg-chrome tablet:min-h-0 tablet:w-[360px] tablet:basis-auto tablet:border-s tablet:border-t-0">
        <aside aria-label={t('acceptance.detail')} className="h-full overflow-y-auto">
          {selected ? <Detail key={selected.id} ra={selected} /> : <EmptyState title={t('acceptance.selectTitle')}>{t('acceptance.selectBody')}</EmptyState>}
        </aside>
      </div>
    </div>
  );
}

function HeldClosesView({ search, set }: { search: WorkflowSearch; set: (patch: Partial<WorkflowSearch>) => void }) {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: qk.heldCloses.list(), queryFn: ({ signal }) => listHeldCloses('', signal) });
  const rows = q.data ?? [];
  const selected = rows.find((r) => r.id === search.sel || (search.run_id && r.ingest_run_id === search.run_id));

  let list: React.ReactNode;
  if (q.isPending) {
    list = (
      <div className="flex-1" aria-busy="true" aria-label={t('common.loading')}>
        {Array.from({ length: 5 }, (_, i) => (
          <div key={i} className="flex h-[46px] items-center gap-3 border-b border-rule px-3"><Skeleton className="h-3 flex-1" /></div>
        ))}
      </div>
    );
  } else if (q.isError) {
    list = <div className="p-4"><ProblemMessage problem={toProblem(q.error)} title="Failed to load held closes" onRetry={() => void q.refetch()} /></div>;
  } else if (rows.length === 0) {
    list = <EmptyState title="No mass-closes held">{t('heldClose.emptyBody', { defaultValue: 'No scans have had their close step held by the safety guard.' })}</EmptyState>;
  } else {
    const tabbable = selected?.id ?? rows[0]?.id;
    list = (
      <div className="min-h-0 flex-1 overflow-auto">
        <Table role="grid" aria-label="Held closes table" aria-rowcount={rows.length}>
          <colgroup><col /><col className="w-[120px]" /><col className="w-[120px]" /><col className="w-[120px]" /></colgroup>
          <THead className="sticky top-0 z-10">
            <tr role="row">
              <Th>Scope</Th>
              <Th>Status</Th>
              <Th>Findings</Th>
              <Th align="end">Date</Th>
            </tr>
          </THead>
          <TBody>
            {rows.map((r, i) => {
              const status = r.decision || 'pending';
              return (
                <Tr
                  key={r.id}
                  data-row-id={r.id}
                  aria-rowindex={i + 2}
                  selected={r.id === selected?.id}
                  tabIndex={r.id === tabbable ? 0 : -1}
                  onClick={() => set({ sel: r.id, run_id: undefined })}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      set({ sel: r.id, run_id: undefined });
                    }
                  }}
                  className="h-[46px] cursor-default align-middle focus-visible:outline-offset-[-2px]"
                >
                  <Td className={cn('py-0', r.id === selected?.id && 'shadow-[inset_3px_0_0_var(--accent)]')}>
                    <span className="block truncate font-medium">{r.scope.scanner_family || 'scan'} ({r.scope.track || 'main'})</span>
                    <span className="block truncate font-mono text-[11px] text-ink-2">{r.ingest_run_id.slice(0, 8)}</span>
                  </Td>
                  <Td>
                    <span className={cn('inline-block rounded px-1.5 py-0.5 text-12 font-medium capitalize', status === 'pending' ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400' : status === 'confirmed' ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-ink-3/10 text-ink-2')}>
                      {status}
                    </span>
                  </Td>
                  <Td className="text-ink-2">{r.finding_ids.length} to close</Td>
                  <Td align="end" className="text-ink-2" title={absoluteDate(r.created_at)}>{absoluteDate(r.created_at)}</Td>
                </Tr>
              );
            })}
          </TBody>
        </Table>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col tablet:flex-row">
      <section aria-label="Held mass-closes" className="flex min-h-0 min-w-0 flex-1 basis-3/5 flex-col tablet:basis-auto">
        <div className="flex items-center gap-3 border-b border-rule px-3 py-2">
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => set({ tab: 'acceptances', sel: undefined })}
              className="rounded-ctl px-2.5 py-1 text-13 font-medium text-ink-2 transition-colors hover:text-ink"
            >
              {t('acceptance.tabAcceptances', { defaultValue: 'Risk Acceptances' })}
            </button>
            <button
              type="button"
              onClick={() => set({ tab: 'held_closes', sel: undefined })}
              className="rounded-ctl bg-surface px-2.5 py-1 text-13 font-semibold text-ink shadow-sm"
            >
              {t('acceptance.tabHeldCloses', { defaultValue: 'Held Closes' })}
            </button>
          </div>
        </div>
        {list}
      </section>
      <div className="min-h-[200px] shrink-0 basis-2/5 border-t border-rule bg-chrome tablet:min-h-0 tablet:w-[360px] tablet:basis-auto tablet:border-s tablet:border-t-0">
        <aside aria-label="Held close details" className="h-full overflow-y-auto">
          {selected ? <HeldCloseDetail key={selected.id} hc={selected} /> : <EmptyState title="Select a held close">Choose a held close from the list to review the affected findings and confirm or discard.</EmptyState>}
        </aside>
      </div>
    </div>
  );
}

function HeldCloseDetail({ hc }: { hc: HeldClose }) {
  const toast = useToast();
  const qc = useQueryClient();
  const { canAnywhere } = useAccess();
  const isMaintainer = canAnywhere('maintainer');
  const isPending = !hc.decision;

  const mutation = useMutation({
    mutationFn: (action: 'confirm' | 'discard') =>
      action === 'confirm' ? confirmHeldClose(hc.id) : discardHeldClose(hc.id),
    onSuccess: (data) => {
      void qc.invalidateQueries({ queryKey: qk.heldCloses.all() });
      void qc.invalidateQueries({ queryKey: qk.findings.all() });
      toast.info(data.decision === 'confirmed' ? `Held close confirmed (${'closed' in data ? data.closed : 0} findings closed)` : 'Held close discarded');
    },
  });

  const problem = mutation.isError ? toProblem(mutation.error) : null;
  const sample = hc.finding_ids.slice(0, 5);

  return (
    <article aria-label="Held close detail" className="px-4 py-3">
      <h2 className="display text-16 leading-snug [overflow-wrap:anywhere]">
        {hc.scope.scanner_family || 'Scan'} — {hc.finding_ids.length} findings held
      </h2>
      <p className="mt-1 text-13 text-ink-2">
        Status: <span className="font-semibold capitalize">{hc.decision || 'pending review'}</span>
      </p>

      <dl className="m-0 mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-13">
        <dt className="text-ink-2">Scan Run</dt>
        <dd className="m-0">
          <a href={`/ingestion?run=${encodeURIComponent(hc.ingest_run_id)}`} className="font-mono text-12 text-accent hover:underline">
            {hc.ingest_run_id}
          </a>
        </dd>
        <dt className="text-ink-2">Scanner</dt><dd className="m-0">{hc.scope.scanner_family || '—'}</dd>
        <dt className="text-ink-2">Track</dt><dd className="m-0 font-mono text-12">{hc.scope.track || '—'}</dd>
        <dt className="text-ink-2">Date</dt><dd className="m-0">{absoluteDate(hc.created_at)}</dd>
        {hc.decided_by && (<><dt className="text-ink-2">Decided by</dt><dd className="m-0">{hc.decided_by.replace(/^user:/, '')}</dd></>)}
        {hc.decided_at && (<><dt className="text-ink-2">Decided at</dt><dd className="m-0">{absoluteDate(hc.decided_at)}</dd></>)}
      </dl>

      <section className="mt-4">
        <h3 className="m-0 mb-1 text-13 font-semibold">Sample Findings ({sample.length} of {hc.finding_ids.length})</h3>
        <ul className="m-0 list-none p-0 text-12 font-mono text-ink-2">
          {sample.map((id) => (
            <li key={id} className="border-b border-rule py-1">{id}</li>
          ))}
        </ul>
        {hc.finding_ids.length > 5 && (
          <p className="m-0 mt-1 text-11 text-ink-2">...and {hc.finding_ids.length - 5} more</p>
        )}
      </section>

      {problem && <ProblemMessage className="mt-3" problem={problem} title="Action failed" />}

      {isPending && (
        <div className="mt-5 flex flex-wrap gap-2">
          {isMaintainer ? (
            <>
              <Button variant="primary" loading={mutation.isPending} onClick={() => mutation.mutate('confirm')}>
                Confirm Close
              </Button>
              <Button loading={mutation.isPending} onClick={() => mutation.mutate('discard')}>
                Discard
              </Button>
            </>
          ) : (
            <p className="m-0 text-13 text-ink-2">Confirming or discarding mass-closes requires the maintainer role on the application.</p>
          )}
        </div>
      )}
    </article>
  );
}

function Detail({ ra }: { ra: RiskAcceptance }) {
  const { t } = useTranslation();
  const { session } = useSession();
  const toast = useToast();
  const qc = useQueryClient();
  const [asking, setAsking] = useState<'reject' | 'revoke' | null>(null);
  const [note, setNote] = useState('');
  const noteId = useId();
  const me = session.user.email;
  const { canAnywhere } = useAccess();
  // The server checks the application of every finding; the screen offers it to someone who can decide somewhere.
  const isAdmin = canAnywhere('maintainer');
  const mine = ra.requester === `user:${me}` || ra.owner === `user:${me}` || ra.requester === me || ra.owner === me;
  const own = ra.requester === `user:${me}` || ra.requester === me;

  const mutation = useMutation({
    mutationFn: (action: 'approve' | 'reject' | 'revoke') => decideAcceptance(ra.id, action, note.trim() || undefined).then(() => action),
    onSuccess: (action) => {
      void qc.invalidateQueries({ queryKey: qk.acceptances.all() });
      void qc.invalidateQueries({ queryKey: qk.findings.all() });
      toast.info(t(`acceptance.done.${action}`));
      setAsking(null);
      setNote('');
    },
  });
  const problem = mutation.isError ? toProblem(mutation.error) : null;
  const pending = ra.status === 'pending';
  const live = ra.status === 'approved' || pending;
  const canApprove = pending && isAdmin && !own;
  const canRevoke = live && (isAdmin || mine);

  return (
    <article aria-label={t('acceptance.detail')} className="px-4 py-3">
      <h2 className="display text-16 leading-snug [overflow-wrap:anywhere]">{ra.justification}</h2>
      <p className="mt-1 text-13 text-ink-2">{t(`acceptance.status.${ra.status}`)}. {t('acceptance.covers', { count: ra.finding_ids.length })}.</p>

      <dl className="m-0 mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-13">
        <dt className="text-ink-2">{t('acceptance.owner')}</dt><dd className="m-0">{ra.owner.replace(/^user:/, '')}</dd>
        <dt className="text-ink-2">{t('acceptance.requestedBy')}</dt><dd className="m-0">{ra.requester.replace(/^user:/, '')}</dd>
        {ra.approver && (<><dt className="text-ink-2">{t('acceptance.approvedBy')}</dt><dd className="m-0">{ra.approver.replace(/^user:/, '')}</dd></>)}
        <dt className="text-ink-2">{t('acceptance.expires')}</dt><dd className="m-0">{absoluteDate(ra.expires_at)}</dd>
        {ra.impact_statement && (<><dt className="text-ink-2">{t('acceptance.impact')}</dt><dd className="m-0">{ra.impact_statement}</dd></>)}
        {ra.decision_note && (<><dt className="text-ink-2">{t('acceptance.note')}</dt><dd className="m-0">{ra.decision_note}</dd></>)}
      </dl>
      <p className="mt-3 text-13 text-ink-2">{t(`acceptance.endsAction.${ra.on_expiry}`)}</p>
      {pending && own && <p className="mt-2 text-13">{t('acceptance.ownRequest')}</p>}

      {asking && (
        <div className="mt-4 flex flex-col gap-1">
          <label htmlFor={noteId} className="text-13 font-medium">{asking === 'reject' ? t('acceptance.reasonLabel') : t('acceptance.revokeReason')}</label>
          <textarea id={noteId} rows={3} value={note} onChange={(e) => setNote(e.target.value)} className="w-full resize-y rounded-ctl border border-rule bg-surface px-2.5 py-1.5 text-13 text-ink" />
          {asking === 'reject' && <p className="m-0 text-12 text-ink-2">{t('acceptance.reasonHelp')}</p>}
        </div>
      )}
      {problem && <ProblemMessage className="mt-3" problem={{ ...problem, detail: problem.detail ?? (problem.status === 400 ? problem.title : undefined) }} title={t('acceptance.decisionFailed')} />}

      <Proofs id={ra.id} canAdd={live && (isAdmin || mine)} />

      <div className="mt-4 flex flex-wrap gap-2">
        {!asking && canApprove && <Button variant="primary" loading={mutation.isPending} onClick={() => mutation.mutate('approve')}>{t('acceptance.approve')}</Button>}
        {!asking && canApprove && <Button onClick={() => setAsking('reject')}>{t('acceptance.reject')}</Button>}
        {!asking && canRevoke && <Button onClick={() => setAsking('revoke')}>{pending ? t('acceptance.withdraw') : t('acceptance.revoke')}</Button>}
        {asking && (
          <>
            <Button variant="primary" loading={mutation.isPending} disabled={asking === 'reject' && note.trim() === ''} onClick={() => mutation.mutate(asking)}>
              {asking === 'reject' ? t('acceptance.confirmReject') : t('acceptance.confirmRevoke')}
            </Button>
            <Button onClick={() => { setAsking(null); setNote(''); }}>{t('acceptance.cancel')}</Button>
          </>
        )}
      </div>
    </article>
  );
}

/** Files that support the decision (docs/16 D60): listed for everyone who can read it, added by its people. */
function Proofs({ id, canAdd }: { id: string; canAdd: boolean }) {
  const { t } = useTranslation();
  const toast = useToast();
  const qc = useQueryClient();
  const inputId = useId();
  const list = useQuery({ queryKey: qk.acceptances.proofs(id), queryFn: ({ signal }) => listProofs(id, signal) });
  const upload = useMutation({
    mutationFn: (file: File) => uploadProof(id, file),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.acceptances.proofs(id) });
      toast.info(t('proofs.done'));
    },
  });
  const problem = upload.isError ? toProblem(upload.error) : null;
  const items = list.data ?? [];
  return (
    <section className="mt-4" aria-labelledby={`${inputId}-h`}>
      <h3 id={`${inputId}-h`} className="m-0 mb-1 text-13 font-semibold">{t('proofs.title')}</h3>
      {items.length === 0 && !list.isPending && <p className="m-0 text-13 text-ink-2">{t('proofs.empty')}</p>}
      {items.length > 0 && (
        <ul className="m-0 list-none p-0 text-13">
          {items.map((p) => (
            <li key={p.id} className="border-b border-rule py-1.5">
              <a href={proofHref(id, p.id)} download={p.name} className="[overflow-wrap:anywhere]">{p.name}</a>
              <span className="block text-12 text-ink-2">
                {t('proofs.by', { size: formatBytes(p.size_bytes), who: p.uploaded_by.replace(/^user:/, ''), when: absoluteDate(p.uploaded_at) })}
              </span>
            </li>
          ))}
        </ul>
      )}
      {canAdd && (
        <div className="mt-2 flex flex-col gap-1">
          <label htmlFor={inputId} className="text-13 font-medium">{t('proofs.add')}</label>
          <input
            id={inputId}
            type="file"
            accept=".pdf,.png,.jpg,.jpeg,.txt,.md,.eml"
            disabled={upload.isPending}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) upload.mutate(f);
              e.target.value = '';
            }}
            className="text-13 file:me-2 file:rounded-ctl file:border file:border-rule file:bg-surface file:px-2.5 file:py-1 file:text-13 file:text-ink"
          />
          <p className="m-0 text-12 text-ink-2">{upload.isPending ? t('proofs.uploading') : t('proofs.help')}</p>
        </div>
      )}
      {problem && <ProblemMessage className="mt-2" problem={{ ...problem, detail: problem.detail ?? problem.title }} title={t('proofs.failed')} />}
    </section>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1 << 20) return `${Math.round(n / 1024)} KB`;
  return `${(n / (1 << 20)).toFixed(1)} MB`;
}
