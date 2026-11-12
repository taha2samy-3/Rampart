import { useEffect, useMemo, useState } from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { auditExportUrl, listAudit, qk, toProblem } from '@/api';
import type { AuditEntry } from '@/api/types';
import { Button, EmptyState, Input, ProblemMessage, Skeleton, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { useSession } from '@/app/session';
import { useAccess } from '@/app/useAccess';
import { AccessSection } from './AccessSection';
import { cn } from '@/lib/cn';

/** "PATCH /api/v1/findings/{id}" -> "PATCH findings/{id}": the route without the prefix every row repeats. */
const shortAction = (a: string) => a.replace('/api/v1/', ' ').replace('/ingest/v1/', ' ingest/').replace(/\s+/g, ' ').trim();

/** Administration: the audit log today; users, teams and access bindings follow (docs/13). */
export function AdministrationRoute() {
  const { t } = useTranslation();
  const { permissions } = useSession();
  useEffect(() => {
    document.title = `${t('admin.title')} - Rampart`;
  }, [t]);
  const isAdmin = permissions.role === 'admin';
  const { canAnywhere } = useAccess();
  const [draft, setDraft] = useState({ actor: '', action: '' });
  const [applied, setApplied] = useState({ actor: '', action: '' });
  const q = useInfiniteQuery({
    queryKey: qk.audit(applied),
    queryFn: ({ pageParam, signal }) => listAudit({ ...applied, cursor: pageParam || undefined, signal }),
    initialPageParam: '',
    getNextPageParam: (last) => last.nextCursor || undefined,
    enabled: isAdmin,
    retry: false,
  });
  const rows = useMemo<AuditEntry[]>(() => q.data?.pages.flatMap((p) => p.items) ?? [], [q.data]);

  return (
    <div className="mx-auto max-w-[1000px] px-6 py-5">
      <h1 className="display text-28">{t('admin.title')}</h1>
      <section className="mt-5" aria-labelledby="audit-h">
        <h2 id="audit-h" className="text-13 font-semibold">{t('admin.auditTitle')}</h2>
        {!isAdmin ? (
          <p className="m-0 mt-1 text-13 text-ink-2">{t('admin.adminsOnly')}</p>
        ) : (
          <>
            <p className="m-0 mt-1 text-13 text-ink-2">{t('admin.auditIntro')}</p>
            <form
              className="mt-3 flex flex-wrap items-center gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                setApplied({ actor: draft.actor.trim(), action: draft.action.trim() });
              }}
            >
              <Input aria-label={t('admin.actorFilter')} placeholder={t('admin.actorFilter')} value={draft.actor} onChange={(e) => setDraft({ ...draft, actor: e.target.value })} className="w-[220px]" />
              <Input aria-label={t('admin.actionFilter')} placeholder={t('admin.actionFilter')} value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.target.value })} className="w-[220px]" />
              <Button type="submit">{t('admin.apply')}</Button>
              <span className="ms-auto flex gap-3 text-13">
                <a href={auditExportUrl('csv', applied)} download>{t('admin.exportCsv')}</a>
                <a href={auditExportUrl('ndjson', applied)} download>{t('admin.exportNdjson')}</a>
              </span>
            </form>
            <div className="mt-3">
              {q.isPending && (
                <div aria-busy="true" aria-label={t('common.loading')}>
                  {Array.from({ length: 6 }, (_, i) => <div key={i} className="flex h-8 items-center border-b border-rule"><Skeleton className="h-3 flex-1" /></div>)}
                </div>
              )}
              {q.isError && <ProblemMessage problem={toProblem(q.error)} title={t('admin.failed')} onRetry={() => void q.refetch()} />}
              {q.data && rows.length === 0 && <EmptyState className="p-0 text-left" title={t('admin.empty')} />}
              {rows.length > 0 && (
                <Table aria-label={t('admin.tableLabel')}>
                  <colgroup><col className="w-[170px]" /><col className="w-[210px]" /><col /><col className="w-[64px]" /></colgroup>
                  <THead>
                    <tr>
                      <Th>{t('admin.when')}</Th>
                      <Th>{t('admin.actor')}</Th>
                      <Th>{t('admin.action')}</Th>
                      <Th align="end">{t('admin.result')}</Th>
                    </tr>
                  </THead>
                  <TBody>
                    {rows.map((e) => {
                      const status = e.detail?.status;
                      return (
                        <Tr key={e.id}>
                          <Td><time dateTime={e.at} title={e.at}>{new Date(e.at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</time></Td>
                          <Td className="truncate">{e.actor.replace(/^user:/, '')}</Td>
                          <Td>
                            <span className="block truncate font-mono text-12" title={e.action}>{shortAction(e.action)}</span>
                            {e.resource_id && <span className="block truncate text-12 text-ink-2">{e.resource_type} {e.resource_id}</span>}
                          </Td>
                          <Td align="end" className={cn(status !== undefined && status >= 400 && 'font-semibold')}>{status ?? ''}</Td>
                        </Tr>
                      );
                    })}
                  </TBody>
                </Table>
              )}
              {q.hasNextPage && (
                <div className="py-3">
                  <Button onClick={() => void q.fetchNextPage()} loading={q.isFetchingNextPage}>{t('admin.more')}</Button>
                </div>
              )}
            </div>
          </>
        )}
      </section>
      {canAnywhere('owner') && <AccessSection />}
    </div>
  );
}
