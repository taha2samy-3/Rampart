import { useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { BandShape } from '@/components';
import { cn } from '@/lib/cn';
import { riskTotal, worstBand, type GraphNodeData, type VisibleTree } from './model';
import { useTreeKeys } from './useTreeKeys';

/**
 * The same tree as an outline: one row for each component that is open, indented by level. It is the keyboard and
 * screen reader way into the drawing, and easier to scan when a name is long.
 */
export function GraphList({
  tree, nodes, selectedId, pathIds, matchIds, onSelect, onToggle,
}: {
  tree: VisibleTree;
  nodes: Map<string, GraphNodeData>;
  selectedId: string | null;
  pathIds: Set<string>;
  matchIds: Set<string>;
  onSelect: (id: string) => void;
  onToggle: (id: string) => void;
}) {
  const { t } = useTranslation();
  const box = useRef<HTMLUListElement>(null);
  const { tabKey, onKey, setFocusKey } = useTreeKeys(tree.items, selectedId, tree.root?.key ?? null, box, onSelect, onToggle);
  return (
    <ul ref={box} role="tree" aria-label={t('apps.graph.treeLabel')} className="h-full min-h-[22rem] overflow-auto py-1">
      {tree.items.map((item) => {
        const n = nodes.get(item.id)!;
        const band = worstBand(n.vulnerabilities);
        const total = riskTotal(n.vulnerabilities);
        const selected = item.id === selectedId;
        const onPath = selectedId !== null && pathIds.has(item.id);
        return (
          <li
            key={item.key}
            data-key={item.key}
            role="treeitem"
            aria-level={item.depth + 1}
            aria-selected={selected}
            aria-expanded={item.expandable ? item.expanded : undefined}
            tabIndex={item.key === tabKey ? 0 : -1}
            onClick={() => onSelect(item.id)}
            onDoubleClick={() => item.expandable && onToggle(item.id)}
            onKeyDown={(e) => onKey(e, item)}
            onFocus={() => setFocusKey(item.key)}
            style={{ paddingInlineStart: item.depth * 20 + 10 }}
            className={cn(
              'flex h-8 cursor-pointer items-center gap-2 border-s-[3px] pe-3 text-13 outline-none',
              'hover:bg-chrome focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent',
              selected ? 'border-accent bg-chrome' : 'border-transparent',
              matchIds.has(item.id) && !selected && 'bg-chrome/60',
            )}
          >
            <span
              aria-hidden="true"
              onClick={(e) => { if (item.expandable) { e.stopPropagation(); onToggle(item.id); } }}
              className={cn('inline-flex size-4 shrink-0 items-center justify-center text-ink-2', item.expandable && 'rounded-ctl hover:bg-rule')}
            >
              {item.expandable ? (item.expanded ? '−' : '+') : ''}
            </span>
            {band ? <BandShape band={band} /> : <span aria-hidden="true" className="size-1.5 shrink-0 rounded-full bg-ink-2 opacity-70" />}
            <span className={cn('truncate', n.root && 'font-semibold', onPath && 'font-semibold text-accent', item.again && 'italic')} title={n.purl ?? n.name}>
              {n.name}
            </span>
            {n.version && <span className="shrink-0 text-ink-2">{n.version}</span>}
            {item.again && <span className="shrink-0 text-12 text-ink-2">{t('apps.graph.shownAbove')}</span>}
            {total > 0 && <span className="ms-auto shrink-0 font-semibold tabular-nums">{total}</span>}
          </li>
        );
      })}
    </ul>
  );
}
