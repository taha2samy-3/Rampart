import { useCallback, useEffect, useMemo, useState } from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { listFindings, qk, toProblem } from '@/api';
import { Button, CommandLine, Dialog, DialogContent, EmptyState, ProblemMessage, Skeleton } from '@/components';
import { Facets } from '@/features/facets/Facets';
import { FilterBar } from '@/features/filter-bar/FilterBar';
import { Inspector } from '@/features/finding-inspector/Inspector';
import { FindingsTable } from '@/features/findings-table/FindingsTable';
import { AcceptanceDialog } from '@/features/acceptance/AcceptanceDialog';
import { TriageDialog } from '@/features/triage/TriageDialog';
import { EditDialog } from '@/features/triage/EditDialog';
import { BulkBar } from '@/features/bulk/BulkBar';
import { useAccess } from '@/app/useAccess';
import { cn } from '@/lib/cn';
import { parseQuery, removeTerm } from '@/lib/grammar';
import { useMedia } from '@/lib/useMedia';

export interface FindingsSearch {
  q?: string;
  sel?: string;
  sort?: string;
  density?: 'compact';
}
export const DEFAULT_SORT = '-score';
const MIN_W = 280;
const MAX_W = 560;

/** Drag or arrow-key resize for the inspector; the width lives in memory only. */
function useInspectorWidth() {
  const [w, setW] = useState(330);
  const clamp = (n: number) => Math.min(MAX_W, Math.max(MIN_W, n));
  const onKeyDown = (e: React.KeyboardEvent, rtl: boolean) => {
    const dir = rtl ? -1 : 1;
    if (e.key === 'ArrowLeft') setW((x) => clamp(x + 16 * dir));
    else if (e.key === 'ArrowRight') setW((x) => clamp(x - 16 * dir));
    else return;
    e.preventDefault();
  };
  const onPointerDown = (e: React.PointerEvent<HTMLElement>) => {
    const el = e.currentTarget;
    const parent = el.parentElement?.parentElement;
    if (!parent) return;
    el.setPointerCapture(e.pointerId);
    const rtl = getComputedStyle(parent).direction === 'rtl';
    const move = (ev: PointerEvent) => {
      const r = parent.getBoundingClientRect();
      setW(clamp(rtl ? ev.clientX - r.left : r.right - ev.clientX));
    };
    const up = () => {
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerup', up);
    };
    el.addEventListener('pointermove', move);
    el.addEventListener('pointerup', up);
  };
  return { w, onKeyDown, onPointerDown };
}

export function FindingsRoute({ search, deepLinkId }: { search: FindingsSearch; deepLinkId?: string }) {
  const { t } = useTranslation();
  useEffect(() => {
    document.title = `${t('findings.title')} - Rampart`;
  }, [t]);
  const navigate = useNavigate();
  const q = search.q ?? '';
  const sort = search.sort ?? DEFAULT_SORT;
  const density = search.density === 'compact' ? 'compact' : 'comfortable';
  const selectedId = search.sel ?? deepLinkId;
  const tablet = useMedia('(max-width: 899px)');
  const [sheetOpen, setSheetOpen] = useState(false);
  const insp = useInspectorWidth();
  const { can, canAnywhere } = useAccess();
  const [triageOpen, setTriageOpen] = useState(false);
  const [acceptOpen, setAcceptOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  // Findings picked for a bulk change, and whether "all matching" replaced them with the filter (docs/13).
  const [checked, setChecked] = useState<ReadonlySet<string>>(new Set());
  const [allMatching, setAllMatching] = useState(false);
  const clearChecked = useCallback(() => {
    setChecked(new Set());
    setAllMatching(false);
  }, []);
  const toggleChecked = useCallback((id: string) => {
    setAllMatching(false);
    setChecked((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const setSearch = useCallback(
    (patch: Partial<FindingsSearch>) =>
      void navigate({ to: '/findings', search: (prev: FindingsSearch) => ({ ...prev, ...patch }), replace: true }),
    [navigate],
  );
  const setQ = useCallback(
    (next: string) => {
      clearChecked(); // a selection belongs to the list it was made in
      setSearch({ q: next || undefined, sel: undefined });
    },
    [setSearch, clearChecked],
  );

  const query = useInfiniteQuery({
    queryKey: qk.findings.list(q, sort),
    queryFn: ({ pageParam, signal }) => listFindings({ q, sort, cursor: pageParam || undefined, signal }),
    initialPageParam: '',
    getNextPageParam: (last) => last.nextCursor || undefined,
    // A bad filter is the user's to fix; only server faults are retried.
    retry: (n, err) => toProblem(err).status >= 500 && n < 1,
  });
  const rows = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data]);
  const total = query.data?.pages[0]?.total;
  const selectedRow = rows.find((r) => r.finding.id === selectedId);
  // A decision is offered where the caller's role on the finding's application reaches it (D48).
  const canTriage = can(selectedRow?.finding.application_id, 'triager');
  // Selecting for a bulk change is offered to anyone who may decide somewhere; the server decides each finding
  // by its application and reports the ones it refused (D48).
  const canTriageAny = canAnywhere('triager');
  // "s" sets the state of the selected finding (docs/13), unless the keystroke is for a field.
  useEffect(() => {
    if (!canTriage || !selectedRow) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.key !== 's' && e.key !== 'e' && e.key !== 'a') || e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return;
      const el = e.target as HTMLElement | null;
      if (el && (el.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName))) return;
      e.preventDefault();
      if (e.key === 's') setTriageOpen(true);
      else if (e.key === 'a') setEditOpen(true);
      else if (['open', 'under_investigation', 'affected'].includes(selectedRow.finding.state)) setAcceptOpen(true);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [canTriage, selectedRow]);

  const { fetchNextPage, hasNextPage, isFetchingNextPage } = query;
  const loadMore = useCallback(() => void fetchNextPage(), [fetchNextPage]);
  const onSelect = useCallback((id: string) => setSearch({ sel: id }), [setSearch]);
  const toggleSort = () => setSearch({ sort: sort === '-score' ? 'score' : '-score' });
  const firstTerm = parseQuery(q).terms[0];

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
        <ProblemMessage problem={toProblem(query.error)} title={t('findings.loadFailed')} onRetry={() => void query.refetch()} />
      </div>
    );
  } else if (rows.length === 0 && !q) {
    list = (
      <EmptyState title={t('findings.emptyTitle')} action={<CommandLine command={t('findings.emptyCommand')} />}>
        {t('findings.emptyBody')}
      </EmptyState>
    );
  } else if (rows.length === 0) {
    list = (
      <EmptyState
        title={t('findings.emptyNoMatch')}
        action={
          <Button onClick={() => setQ(firstTerm ? removeTerm(q, 0) : '')}>
            {firstTerm ? t('findings.emptyNoMatchNext', { term: firstTerm.source }) : t('findings.emptyNoMatchClear')}
          </Button>
        }
      >
        {t('findings.emptyNoMatchClear')}
      </EmptyState>
    );
  } else {
    list = (
      <FindingsTable
        rows={rows}
        selectedId={selectedId}
        onSelect={onSelect}
        density={density}
        sort={sort}
        onToggleSort={toggleSort}
        hasMore={!!hasNextPage}
        loadingMore={isFetchingNextPage}
        onLoadMore={loadMore}
        checked={checked}
        onToggleChecked={canTriageAny ? toggleChecked : undefined}
      />
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col tablet:flex-row" style={{ '--insp-w': `${insp.w}px` } as React.CSSProperties}>
      {!tablet && (
        <aside aria-label={t('findings.facetsTitle')} className="w-[156px] shrink-0 overflow-y-auto border-e border-rule">
          <Facets q={q} onQueryChange={setQ} />
        </aside>
      )}
      <section aria-label={t('findings.title')} className="flex min-h-0 min-w-0 flex-1 basis-3/5 flex-col tablet:basis-auto">
        <FilterBar q={q} onQueryChange={setQ} total={total} onOpenFilters={tablet ? () => setSheetOpen(true) : undefined} />
        {list}
        {(checked.size > 0 || allMatching) && (
          <BulkBar
            ids={[...checked]}
            all={allMatching}
            total={total}
            q={q}
            onSelectAll={() => setAllMatching(true)}
            onClear={clearChecked}
          />
        )}
      </section>
      <div
        className={cn(
          'pane-anim relative min-h-[200px] shrink-0 basis-2/5 border-t border-rule bg-chrome',
          'tablet:min-h-0 tablet:w-[var(--insp-w)] tablet:basis-auto tablet:border-s tablet:border-t-0',
        )}
      >
        {!tablet && (
          <div
            role="separator"
            aria-orientation="vertical"
            aria-label={t('findings.inspectorResize')}
            aria-valuemin={MIN_W}
            aria-valuemax={MAX_W}
            aria-valuenow={insp.w}
            tabIndex={0}
            onKeyDown={(e) => insp.onKeyDown(e, getComputedStyle(e.currentTarget).direction === 'rtl')}
            onPointerDown={insp.onPointerDown}
            className="absolute inset-y-0 start-0 z-10 w-1.5 cursor-col-resize hover:bg-accent/30 focus-visible:bg-accent/40 focus-visible:outline-offset-[-2px]"
          />
        )}
        <aside aria-label={t('findings.inspector')} className="h-full overflow-y-auto">
          <Inspector
            row={selectedRow}
            selectedId={selectedId}
            onTriage={canTriage && selectedRow ? () => setTriageOpen(true) : undefined}
            onAccept={canTriage && selectedRow ? () => setAcceptOpen(true) : undefined}
            onEdit={canTriage && selectedRow ? () => setEditOpen(true) : undefined}
          />
        </aside>
      </div>
      {selectedRow && <TriageDialog row={selectedRow} open={triageOpen && canTriage} onOpenChange={setTriageOpen} />}
      {selectedRow && <EditDialog row={selectedRow} open={editOpen && canTriage} onOpenChange={setEditOpen} />}
      {selectedRow && <AcceptanceDialog row={selectedRow} open={acceptOpen && canTriage} onOpenChange={setAcceptOpen} />}
      <Dialog open={sheetOpen && tablet} onOpenChange={setSheetOpen}>
        <DialogContent sheet title={t('findings.facetsTitle')}>
          <Facets q={q} onQueryChange={setQ} />
        </DialogContent>
      </Dialog>
    </div>
  );
}
