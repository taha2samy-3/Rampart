import { useEffect, useId, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { decideAcceptance, listAcceptances, qk, toProblem } from '@/api';
import type { AcceptanceStatus, RiskAcceptance } from '@/api/types';
import { Button, EmptyState, ProblemMessage, Select, Skeleton, Table, TBody, Td, Th, THead, Tr, useToast } from '@/components';
import { useSession } from '@/app/session';
import { cn } from '@/lib/cn';
import { absoluteDate } from '@/lib/format';

export interface WorkflowSearch {
  sel?: string;
  status?: AcceptanceStatus;
}
const STATUSES: (AcceptanceStatus | '')[] = ['', 'pending', 'approved', 'rejected', 'expired', 'revoked'];

/** Risk acceptances: what is waiting for approval, what is accepted, and what ended (docs/13, Workflow). */
export function WorkflowRoute({ search }: { search: WorkflowSearch }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { permissions } = useSession();
  useEffect(() => {
    document.title = `${t('acceptance.workflow')} - Rampart`;
  }, [t]);
  const status = search.status ?? '';
  const q = useQuery({ queryKey: qk.acceptances.list(status), queryFn: ({ signal }) => listAcceptances(status, signal) });
  const rows = q.data ?? [];
  const selected = rows.find((r) => r.id === search.sel);
  const set = (patch: Partial<WorkflowSearch>) => void navigate({ to: '/workflow', search: (p: WorkflowSearch) => ({ ...p, ...patch }), replace: true });

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
          <h1 className="display text-16">{t('acceptance.list')}</h1>
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
          {selected ? <Detail key={selected.id} ra={selected} role={permissions.role} /> : <EmptyState title={t('acceptance.selectTitle')}>{t('acceptance.selectBody')}</EmptyState>}
        </aside>
      </div>
    </div>
  );
}

function Detail({ ra, role }: { ra: RiskAcceptance; role: string }) {
  const { t } = useTranslation();
  const { session } = useSession();
  const toast = useToast();
  const qc = useQueryClient();
  const [asking, setAsking] = useState<'reject' | 'revoke' | null>(null);
  const [note, setNote] = useState('');
  const noteId = useId();
  const me = session.user.email;
  const isAdmin = role === 'admin';
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
