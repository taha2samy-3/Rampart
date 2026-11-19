import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent, type WheelEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { BandGlyph, BAND_TEXT_CLASS } from '@/components';
import { riskTotal, worstBand, type GraphNodeData, type VisibleTree } from './model';
import { useTreeKeys } from './useTreeKeys';

const PAD = 16;
const MIN_K = 0.3;
const MAX_K = 2.5;
const READABLE_K = 0.85; // the first view is never drawn smaller than this: small text is no help
// Inside a column (see COL_WIDTH): marker, name and version, the finding count right-aligned, the open/close box, the link out.
const TEXT_X = 18;
const COUNT_X = 216;
const BOX_X = 224;
const LINK_X = 244;

export interface CanvasProps {
  tree: VisibleTree;
  size: { width: number; height: number };
  nodes: Map<string, GraphNodeData>;
  selectedId: string | null;
  /** The components on the path from the root to the selected one, and the edges between them. */
  pathIds: Set<string>;
  matchIds: Set<string>;
  onSelect: (id: string) => void;
  onToggle: (id: string) => void;
  /** Bump to centre the view on the selected component (after a search). */
  centerToken: number;
}

function label(n: GraphNodeData) {
  const name = n.name.length > 22 ? `${n.name.slice(0, 21)}…` : n.name;
  const version = n.version ? (n.version.length > 9 ? `${n.version.slice(0, 8)}…` : n.version) : '';
  return { name, version };
}

/**
 * The dependency tree drawn left to right: a level to a column, the root on the left. A component is marked by the shape
 * of its worst open finding; the path from the root to the selected component is drawn in the accent colour and the rest
 * recedes. Drag to move, Ctrl or Cmd with the wheel (or the buttons) to zoom; arrow keys walk the tree.
 */
export function GraphCanvas({ tree, size, nodes, selectedId, pathIds, matchIds, onSelect, onToggle, centerToken }: CanvasProps) {
  const { t } = useTranslation();
  const boxRef = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const drag = useRef<{ px: number; py: number; x: number; y: number } | null>(null);

  // Show the tree from the left with the root in the middle of the height. A tree too big for the box is not shrunk below a
  // readable size: the reader drags to see the rest, or searches. "Fit to view" is the one button that shrinks it fully.
  const rootY = tree.root?.y ?? 0;
  const place = useCallback((floor: number) => {
    const box = boxRef.current;
    const w = box?.clientWidth || 900;
    const h = box?.clientHeight || 520;
    const whole = Math.min(1, (w - 2 * PAD) / Math.max(size.width + 24, 1), (h - 2 * PAD) / Math.max(size.height, 1));
    const k = Math.max(whole, floor);
    const tall = (size.height + 2 * PAD) * k > h;
    setView({ k, x: 0, y: tall ? h / 2 - (rootY + PAD) * k : (h - size.height * k) / 2 - PAD * k });
  }, [size.width, size.height, rootY]);
  const fit = useCallback(() => place(MIN_K), [place]);

  // Show the whole tree again when its shape changes a lot (a new graph, a filter); a small change keeps the reader's place.
  const shapeKey = `${tree.root?.id ?? ''}/${tree.items.length > 40 ? 'big' : 'small'}`;
  // eslint-disable-next-line react-hooks/exhaustive-deps -- only when the shape changes, not on every open or close
  useEffect(() => place(READABLE_K), [shapeKey]);

  const items = tree.items;
  const selectedItem = useMemo(() => items.find((i) => i.id === selectedId) ?? null, [items, selectedId]);
  useEffect(() => {
    if (!centerToken || !selectedItem) return;
    const box = boxRef.current;
    const w = box?.clientWidth || 900;
    const h = box?.clientHeight || 520;
    setView((v) => {
      const k = Math.max(v.k, READABLE_K);
      return { k, x: w / 2 - (selectedItem.x + PAD + 110) * k, y: h / 2 - (selectedItem.y + PAD) * k };
    });
  }, [centerToken, selectedItem]);

  const zoom = (factor: number, cx?: number, cy?: number) =>
    setView((v) => {
      const k = Math.min(MAX_K, Math.max(MIN_K, v.k * factor));
      const ax = cx ?? (boxRef.current?.clientWidth ?? 900) / 2;
      const ay = cy ?? (boxRef.current?.clientHeight ?? 520) / 2;
      return { k, x: ax - ((ax - v.x) / v.k) * k, y: ay - ((ay - v.y) / v.k) * k };
    });

  const onWheel = (e: WheelEvent) => {
    if (!(e.ctrlKey || e.metaKey)) return;
    const r = boxRef.current?.getBoundingClientRect();
    zoom(e.deltaY < 0 ? 1.1 : 1 / 1.1, r ? e.clientX - r.left : undefined, r ? e.clientY - r.top : undefined);
  };
  const onDown = (e: PointerEvent) => {
    if ((e.target as Element).closest('[data-node]')) return;
    drag.current = { px: e.clientX, py: e.clientY, x: view.x, y: view.y };
    e.currentTarget.setPointerCapture?.(e.pointerId);
  };
  const onMove = (e: PointerEvent) => {
    const d = drag.current;
    if (d) setView((v) => ({ ...v, x: d.x + e.clientX - d.px, y: d.y + e.clientY - d.py }));
  };

  const { tabKey, onKey, setFocusKey } = useTreeKeys(items, selectedId, tree.root?.key ?? null, boxRef, onSelect, onToggle);

  const dim = selectedId !== null;
  const W = size.width + 2 * PAD + 120;
  const H = size.height + 2 * PAD;

  return (
    <div ref={boxRef} className="relative h-full min-h-[22rem] overflow-hidden bg-surface" onWheel={onWheel}>
      <svg
        className="size-full cursor-grab touch-none select-none active:cursor-grabbing"
        role="application"
        aria-label={t('apps.graph.canvasLabel')}
        onPointerDown={onDown}
        onPointerMove={onMove}
        onPointerUp={() => (drag.current = null)}
        onPointerCancel={() => (drag.current = null)}
      >
        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
          <rect x={0} y={0} width={W} height={H} fill="transparent" />
          <g transform={`translate(${PAD} ${PAD})`} fontSize={13}>
            {items.map((item) => item.children.map((ch) => {
              const startX = item.x + LINK_X;
              const midX = ch.x - 12;
              const onPath = pathIds.has(item.id) && pathIds.has(ch.id) && dim;
              return (
                <path
                  key={`${item.key}>${ch.key}`}
                  d={`M${startX} ${item.y}H${midX}V${ch.y}H${ch.x - 2}`}
                  fill="none"
                  stroke={onPath ? 'var(--accent)' : 'var(--rule)'}
                  strokeWidth={onPath ? 2 : 1}
                  strokeDasharray={ch.again ? '3 3' : undefined}
                />
              );
            }))}
            <g role="tree" aria-label={t('apps.graph.treeLabel')}>
              {items.map((item) => {
                const n = nodes.get(item.id)!;
                const { name, version } = label(n);
                const band = worstBand(n.vulnerabilities);
                const total = riskTotal(n.vulnerabilities);
                const selected = item.id === selectedId;
                const onPath = pathIds.has(item.id);
                const matched = matchIds.has(item.id);
                const tx = item.x + TEXT_X;
                const opacity = dim && !onPath && !matched ? 0.55 : 1;
                const text = [
                  n.name + (n.version ? ` ${n.version}` : ''),
                  band ? t('apps.graph.nodeFindings', { count: total, band: t(`apps.graph.band.${band}`) }) : '',
                  item.again ? t('apps.graph.shownAbove') : '',
                ].filter(Boolean).join(', ');
                return (
                  <g
                    key={item.key}
                    data-node
                    data-key={item.key}
                    role="treeitem"
                    aria-level={item.depth + 1}
                    aria-selected={selected}
                    aria-expanded={item.expandable ? item.expanded : undefined}
                    aria-label={text}
                    tabIndex={item.key === tabKey ? 0 : -1}
                    opacity={opacity}
                    className="cursor-pointer outline-none [&:focus-visible>rect]:stroke-[var(--accent)] [&:focus-visible>rect]:stroke-2"
                    onClick={() => onSelect(item.id)}
                    onDoubleClick={() => item.expandable && onToggle(item.id)}
                    onKeyDown={(e) => onKey(e, item)}
                    onFocus={() => setFocusKey(item.key)}
                  >
                    <title>{n.purl ?? n.name}</title>
                    <rect x={item.x - 5} y={item.y - 12} width={LINK_X - 4} height={24} rx={2}
                      fill={selected ? 'var(--chrome)' : 'transparent'} stroke={selected ? 'var(--accent)' : 'none'} strokeWidth={1} />
                    <g transform={`translate(${item.x} ${item.y - 6})`} className={band ? BAND_TEXT_CLASS[band] : 'text-ink-2'}>
                      {band ? <BandGlyph band={band} /> : n.root ? <rect x="1.5" y="1.5" width="9" height="9" fill="var(--accent)" /> : <circle cx="6" cy="6" r="2.5" fill="currentColor" opacity="0.7" />}
                    </g>
                    <text x={tx} y={item.y + 4.5} fill={onPath && dim ? 'var(--accent)' : 'var(--ink)'} fontWeight={n.root || (onPath && dim) ? 600 : 400} fontStyle={item.again ? 'italic' : undefined}>
                      {name}
                      {version && <tspan fill="var(--ink-2)" fontWeight={400} dx={5}>{version}</tspan>}
                    </text>
                    {total > 0 && (
                      <text x={item.x + COUNT_X} y={item.y + 4.5} fontSize={12} textAnchor="end" className={band ? BAND_TEXT_CLASS[band] : ''} fill="currentColor" fontWeight={600}>{total}</text>
                    )}
                    {item.expandable && (
                      <g
                        role="button"
                        aria-label={t(item.expanded ? 'apps.graph.collapse' : 'apps.graph.expand', { name: n.name })}
                        transform={`translate(${item.x + BOX_X} ${item.y - 7})`}
                        onClick={(e) => { e.stopPropagation(); onToggle(item.id); }}
                      >
                        <rect width={14} height={14} rx={2} fill="var(--surface)" stroke="var(--ink-2)" />
                        <path d={item.expanded ? 'M3.5 7h7' : 'M3.5 7h7M7 3.5v7'} stroke="var(--ink)" strokeWidth={1.4} fill="none" />
                      </g>
                    )}
                  </g>
                );
              })}
            </g>
          </g>
        </g>
      </svg>
      <div className="absolute bottom-3 end-3 flex overflow-hidden rounded-ctl border border-rule bg-surface">
        <button type="button" className="size-8 text-16 hover:bg-chrome" aria-label={t('apps.graph.zoomIn')} onClick={() => zoom(1.25)}>+</button>
        <button type="button" className="size-8 border-s border-rule text-16 hover:bg-chrome" aria-label={t('apps.graph.zoomOut')} onClick={() => zoom(0.8)}>−</button>
        <button type="button" className="h-8 border-s border-rule px-3 text-13 hover:bg-chrome" onClick={fit}>{t('apps.graph.fit')}</button>
      </div>
    </div>
  );
}
