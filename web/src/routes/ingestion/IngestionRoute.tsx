import { useEffect, useMemo, useState } from 'react';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { getRun, listRuns, qk, toProblem } from '@/api';
import type { RunRow } from '@/api/types';
import { Button, CommandLine, EmptyState, ProblemMessage, Skeleton, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { RunInspector } from '@/features/run-inspector/RunInspector';
import { UploadDialog } from './UploadDialog';
import { cn } from '@/lib/cn';
import { absoluteDate, shortAge, shortId } from '@/lib/format';

export interface IngestionSearch {
  sel?: string;
}

const ACTIVE = new Set(['queued', 'parsing', 'merging', 'enriching', 'scoring']);

/** Where a run came from, as one short line: repository and branch, else the image, else the scanner. */
function sourceText(r: RunRow): string {
  const c = r.context;
  if (c.repository) return [c.repository, c.branch ?? r.track].filter(Boolean).join(' @ ');
  return c.image_ref || c.image_digest || r.scanners.join(', ') || r.scanner_family;
}

function foundText(r: RunRow): string {
  if (r.ephemeral) return `${r.stats.created} new`;
  return `${r.stats.created} new, ${r.stats.closed} closed`;
}

/** Ingest runs, newest first, with the selected run docked on the right (docs/13, the ingest run page). */
export function IngestionRoute({ search }: { search: IngestionSearch }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [uploadOpen, setUploadOpen] = useState(false);
  useEffect(() => {
    document.title = `${t('ingestion.title')} - Rampart`;
  }, [t]);
  const selectedId = search.sel;

  const query = useInfiniteQuery({
    queryKey: qk.runs.list(),
    queryFn: ({ pageParam, signal }) => listRuns({ cursor: pageParam || undefined, signal }),
    initialPageParam: '',
    getNextPageParam: (last) => last.nextCursor || undefined,
    retry: (n, err) => toProblem(err).status >= 500 && n < 1,
    // A run in progress changes under the reader; poll while any visible run is still going.
    refetchInterval: (q) => (q.state.data?.pages.some((p) => p.items.some((r) => ACTIVE.has(r.status))) ? 3000 : false),
  });
  const rows = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data]);
  const inList = rows.find((r) => r.id === selectedId);
  // A deep link to a run older than the loaded pages: ask for it directly.
  const direct = useQuery({
    queryKey: qk.runs.one(selectedId ?? ''),
    queryFn: ({ signal }) => getRun(selectedId ?? '', signal),
    enabled: !!selectedId && !inList && query.isSuccess,
    retry: false,
  });
  const selected = inList ?? direct.data;
  const select = (id: string) => void navigate({ to: '/ingestion', search: { sel: id }, replace: true });

  let list: React.ReactNode;
  if (query.isPending) {
    list = (
      <div className="flex-1 overflow-hidden" aria-busy="true" aria-label={t('common.loading')}>
        {Array.from({ length: 8 }, (_, i) => (
          <div key={i} className="flex h-[46px] items-center gap-3 border-b border-rule px-3">
            <Skeleton className="h-2.5 w-24" />
            <Skeleton className="h-3 flex-1" />
          </div>
        ))}
      </div>
    );
  } else if (query.isError) {
    list = (
      <div className="p-4">
        <ProblemMessage problem={toProblem(query.error)} title={t('ingestion.loadFailed')} onRetry={() => void query.refetch()} />
      </div>
    );
  } else if (rows.length === 0) {
    list = (
      <EmptyState
        title={t('ingestion.emptyTitle')}
        action={
          <div className="flex flex-col items-center gap-2">
            <Button variant="secondary" onClick={() => setUploadOpen(true)}>
              {t('ingestion.uploadButton')}
            </Button>
            <CommandLine command={t('ingestion.emptyCommand')} />
          </div>
        }
      >
        {t('ingestion.emptyBody')}
      </EmptyState>
    );
  } else {
    const tabbable = selectedId && rows.some((r) => r.id === selectedId) ? selectedId : rows[0]?.id;
    list = (
      <div className="min-h-0 flex-1 overflow-auto">
        <Table role="grid" aria-label={t('ingestion.tableLabel')} aria-rowcount={rows.length}>
          <colgroup>
            <col className="w-[96px]" />
            <col />
            <col className="w-[150px]" />
            <col className="w-[132px] @max-[520px]/list:hidden" />
            <col className="w-[72px]" />
          </colgroup>
          <THead className="sticky top-0 z-10">
            <tr role="row">
              <Th>{t('ingestion.colRun')}</Th>
              <Th>{t('ingestion.colSource')}</Th>
              <Th>{t('ingestion.colStatus')}</Th>
              <Th>{t('ingestion.colFound')}</Th>
              <Th align="end">{t('ingestion.colWhen')}</Th>
            </tr>
          </THead>
          <TBody>
            {rows.map((r, i) => {
              const selectedRow = r.id === selectedId;
              return (
                <Tr
                  key={r.id}
                  data-row-id={r.id}
                  aria-rowindex={i + 2}
                  selected={selectedRow}
                  tabIndex={r.id === tabbable ? 0 : -1}
                  onClick={() => select(r.id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      select(r.id);
                    }
                  }}
                  className="h-[46px] cursor-default align-middle focus-visible:outline-offset-[-2px]"
                >
                  <Td className={cn('py-0 font-mono text-12', selectedRow && 'shadow-[inset_3px_0_0_var(--accent)]')} title={r.id}>
                    {shortId(r.id)}
                  </Td>
                  <Td className="py-0">
                    <span className="block truncate font-medium">{sourceText(r)}</span>
                    <span className="block truncate text-[11.5px] leading-4 text-ink-2">
                      {[r.scanners.join(', '), r.context.commit?.slice(0, 7), r.ephemeral ? t('ingestion.pullRequest') : '']
                        .filter(Boolean)
                        .join(', ')}
                    </span>
                  </Td>
                  <Td className={cn(r.status === 'failed' && 'font-semibold')}>{t(`ingestion.status.${r.status}`)}</Td>
                  <Td className="text-ink-2">{foundText(r)}</Td>
                  <Td align="end" className="text-ink-2" title={absoluteDate(r.created_at)}>
                    {shortAge(r.created_at)}
                  </Td>
                </Tr>
              );
            })}
          </TBody>
        </Table>
        <div className="px-3 py-3 text-12 text-ink-2" aria-live="polite">
          {query.hasNextPage ? (
            <Button onClick={() => void query.fetchNextPage()} disabled={query.isFetchingNextPage}>
              {query.isFetchingNextPage ? t('ingestion.loadingMore') : t('ingestion.loadMore')}
            </Button>
          ) : (
            t('ingestion.reachedEnd')
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col tablet:flex-row">
      <section aria-label={t('ingestion.title')} className="@container/list flex min-h-0 min-w-0 flex-1 basis-3/5 flex-col tablet:basis-auto">
        <div className="flex items-center justify-between border-b border-rule px-3 py-2">
          <h1 className="display text-16">{t('ingestion.title')}</h1>
          <Button variant="secondary" onClick={() => setUploadOpen(true)}>
            {t('ingestion.uploadButton')}
          </Button>
        </div>
        {list}
      </section>
      <div className="relative min-h-[200px] shrink-0 basis-2/5 border-t border-rule bg-chrome tablet:min-h-0 tablet:w-[360px] tablet:basis-auto tablet:border-s tablet:border-t-0">
        <aside aria-label={t('ingestion.inspector')} className="h-full overflow-y-auto">
          <RunInspector run={selected} selectedId={selectedId} />
        </aside>
      </div>
      <UploadDialog open={uploadOpen} onOpenChange={setUploadOpen} />
    </div>
  );
}
