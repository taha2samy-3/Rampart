import { useEffect, useMemo, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { createColumnHelper, getCoreRowModel, useReactTable } from '@tanstack/react-table';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { FindingRow } from '@/api/types';
import { BandShape, ScoreBar, Table, Td, TBody, Th, THead, Tr } from '@/components';
import { toBand } from '@/lib/band';
import { cn } from '@/lib/cn';
import { absoluteDate, dueShort, shortAge, shortId } from '@/lib/format';

const col = createColumnHelper<FindingRow>();

/** Column visibility by list-pane width (container query on the pane). */
const HIDE_NARROW = '@max-[640px]/list:hidden';
const HIDE_NARROWER = '@max-[520px]/list:hidden';

function locationText(r: FindingRow): string {
  const l = r.finding.location;
  if (l?.purl) return l.purl;
  if (l?.file_path) return l.start_line ? `${l.file_path}:${l.start_line}` : l.file_path;
  return r.finding.vulnerability_id ?? r.finding.rule_id ?? '';
}

export const ROW_HEIGHT = { comfortable: 46, compact: 32 } as const;

export function FindingsTable({
  rows,
  selectedId,
  onSelect,
  density,
  sort,
  onToggleSort,
  hasMore,
  loadingMore,
  onLoadMore,
}: {
  rows: FindingRow[];
  selectedId: string | undefined;
  onSelect: (id: string) => void;
  density: 'comfortable' | 'compact';
  sort: string;
  onToggleSort: () => void;
  hasMore: boolean;
  loadingMore: boolean;
  onLoadMore: () => void;
}) {
  const { t } = useTranslation();
  const scrollRef = useRef<HTMLDivElement>(null);
  const rowH = ROW_HEIGHT[density];

  const columns = useMemo(
    () => [
      col.display({ id: 'score', header: t('findings.colScore') }),
      col.display({ id: 'finding', header: t('findings.colFinding') }),
      col.display({ id: 'application', header: t('findings.colApplication') }),
      col.display({ id: 'state', header: t('findings.colState') }),
      col.display({ id: 'due', header: t('findings.colDue') }),
      col.display({ id: 'first', header: t('findings.colFirstSeen') }),
    ],
    [t],
  );
  // TanStack Table returns unmemoizable functions; this component is not compiler-optimised.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({ data: rows, columns, getCoreRowModel: getCoreRowModel(), getRowId: (r) => r.finding.id });
  const modelRows = table.getRowModel().rows;

  const virt = useVirtualizer({
    count: modelRows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowH,
    overscan: 12,
    initialRect: { width: 800, height: 640 },
  });
  const items = virt.getVirtualItems();
  const padTop = items.length ? (items[0]?.start ?? 0) : 0;
  const padBottom = items.length ? virt.getTotalSize() - (items[items.length - 1]?.end ?? 0) : 0;

  // Infinite scroll: ask for the next page when the last rows come into view.
  const lastIndex = items.length ? (items[items.length - 1]?.index ?? 0) : -1;
  useEffect(() => {
    if (hasMore && !loadingMore && lastIndex >= modelRows.length - 8) onLoadMore();
  }, [hasMore, loadingMore, lastIndex, modelRows.length, onLoadMore]);

  // Keyboard: j/k and arrows move, selection follows focus.
  const focusAfter = useRef<string | null>(null);
  const move = (delta: number) => {
    if (!modelRows.length) return;
    const cur = modelRows.findIndex((r) => r.id === selectedId);
    const next = Math.min(modelRows.length - 1, Math.max(0, cur < 0 ? 0 : cur + delta));
    const id = modelRows[next]?.id;
    if (!id) return;
    focusAfter.current = id;
    virt.scrollToIndex(next);
    onSelect(id);
  };
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === 'j' || e.key === 'ArrowDown') {
      e.preventDefault();
      move(1);
    } else if (e.key === 'k' || e.key === 'ArrowUp') {
      e.preventDefault();
      move(-1);
    } else if (e.key === 'Home') {
      e.preventDefault();
      move(-Infinity);
    } else if (e.key === 'End') {
      e.preventDefault();
      move(Infinity);
    }
  };
  useEffect(() => {
    const id = focusAfter.current;
    if (!id) return;
    const el = scrollRef.current?.querySelector<HTMLElement>(`[data-row-id="${CSS.escape(id)}"]`);
    if (el) {
      el.focus({ preventScroll: true });
      focusAfter.current = null;
    }
  });

  const tabbableId = selectedId && modelRows.some((r) => r.id === selectedId) ? selectedId : modelRows[0]?.id;
  const sortState = sort === 'score' ? 'ascending' : sort === '-score' ? 'descending' : 'none';
  const now = Date.now();

  return (
    <div ref={scrollRef} className="@container/list min-h-0 flex-1 overflow-auto">
      <Table role="grid" aria-label={t('findings.tableLabel')} aria-rowcount={modelRows.length} onKeyDown={onKeyDown}>
        <colgroup>
          <col className="w-[150px]" />
          <col />
          <col className={cn('w-[88px]', HIDE_NARROW)} />
          <col className="w-[116px] @max-[520px]/list:hidden" />
          <col className="w-[72px]" />
          <col className={cn('w-[88px]', HIDE_NARROWER)} />
        </colgroup>
        <THead className="sticky top-0 z-10">
          <tr role="row">
            <Th sort={sortState} onSort={onToggleSort}>{t('findings.colScore')}</Th>
            <Th>{t('findings.colFinding')}</Th>
            <Th className={HIDE_NARROW}>{t('findings.colApplication')}</Th>
            <Th className={HIDE_NARROWER}>{t('findings.colState')}</Th>
            <Th align="end">{t('findings.colDue')}</Th>
            <Th align="end" className={HIDE_NARROWER}>{t('findings.colFirstSeen')}</Th>
          </tr>
        </THead>
        <TBody>
          {padTop > 0 && (
            <tr aria-hidden="true">
              <td colSpan={6} className="p-0" style={{ blockSize: padTop }} />
            </tr>
          )}
          {items.map((vi) => {
            const row = modelRows[vi.index];
            if (!row) return null;
            const r = row.original;
            const f = r.finding;
            const band = toBand(r.risk?.band ?? f.severity);
            const selected = f.id === selectedId;
            const due = dueShort(r.sla_due_date, now);
            return (
              <Tr
                key={row.id}
                data-row-id={f.id}
                data-index={vi.index}
                aria-rowindex={vi.index + 2}
                selected={selected}
                tabIndex={f.id === tabbableId ? 0 : -1}
                onClick={() => onSelect(f.id)}
                className="cursor-default align-middle focus-visible:outline-offset-[-2px]"
                style={{ blockSize: rowH }}
              >
                <Td className={cn('py-0', selected && 'shadow-[inset_3px_0_0_var(--accent)]')}>
                  <span className="flex items-center gap-2">
                    <BandShape band={band} size={12} />
                    <span className="w-9 text-end text-14 font-semibold tnum">{r.risk?.total_score ?? f.risk_score}</span>
                    <ScoreBar breakdown={r.risk} score={r.risk?.total_score ?? f.risk_score} />
                  </span>
                </Td>
                <Td className="py-0">
                  <span className="block truncate font-medium">{f.title}</span>
                  {density === 'comfortable' && (
                    <span className="block truncate font-mono text-[11.5px] leading-4 text-ink-2">{locationText(r)}</span>
                  )}
                </Td>
                <Td className={cn('font-mono text-12 text-ink-2', HIDE_NARROW)} title={f.application_id}>
                  {shortId(f.application_id)}
                </Td>
                <Td className={HIDE_NARROWER}>{t(`state.${f.state}`, { defaultValue: f.state })}</Td>
                <Td align="end" className={cn(due.late && 'font-semibold text-critical')} title={r.sla_due_date ? absoluteDate(r.sla_due_date) : undefined}>
                  {due.text}
                </Td>
                <Td align="end" className={cn('text-ink-2', HIDE_NARROWER)} title={absoluteDate(f.first_seen)}>
                  {shortAge(f.first_seen, now)}
                </Td>
              </Tr>
            );
          })}
          {padBottom > 0 && (
            <tr aria-hidden="true">
              <td colSpan={6} className="p-0" style={{ blockSize: padBottom }} />
            </tr>
          )}
        </TBody>
      </Table>
      <p className="px-3 py-3 text-12 text-ink-2" aria-live="polite">
        {loadingMore ? t('findings.loadingMore') : hasMore ? '' : t('findings.reachedEnd')}
      </p>
    </div>
  );
}
