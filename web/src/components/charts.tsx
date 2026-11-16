import { useId, useMemo, useState } from 'react';
import { BandShape, BAND_LABEL } from './BandShape';
import type { Band } from '@/lib/band';
import type { AgeBuckets } from '@/api/types';

/*
 * Charts of the application pages (docs/13 §6, docs/16 D93). Colour is risk: a mark is coloured only by its risk
 * band, and the band is always named next to it with its shape, because the band colours are too close to tell
 * apart by colour alone (critical/high in dark mode). Everything else is ink. Each chart has its numbers as text
 * or in a table, so nothing depends on seeing the marks.
 */

export const OPEN_BANDS = ['critical', 'high', 'medium', 'low'] as const;
export type ChartBand = (typeof OPEN_BANDS)[number];

const BAND_VAR: Record<ChartBand, string> = {
  critical: 'var(--band-critical)',
  high: 'var(--band-high)',
  medium: 'var(--band-medium)',
  low: 'var(--band-low)',
};

/**
 * The open findings of one application as one bar, worst band first, on a scale shared by every row so the rows
 * compare. Segments are separated by a 2 px gap; each names itself on hover. The row's text gives the counts.
 */
export function BandMixBar({ open, max, label }: { open: Record<ChartBand, number>; max: number; label: string }) {
  const W = 200;
  const H = 8;
  const GAP = 2;
  const total = OPEN_BANDS.reduce((n, b) => n + (open[b] ?? 0), 0);
  if (total === 0 || max <= 0) return <svg width="100%" height={H} aria-hidden="true" />;
  const present = OPEN_BANDS.filter((b) => (open[b] ?? 0) > 0);
  const widths = present.map((b) => Math.max(2, ((open[b] ?? 0) / max) * W));
  const segs = present.map((b, i) => ({ band: b, w: widths[i]!, x: widths.slice(0, i).reduce((n, w) => n + w + GAP, 0) }));
  return (
    <svg viewBox={`0 0 ${W + GAP * 4} ${H}`} preserveAspectRatio="none" className="block h-2 w-full" role="img" aria-label={label}>
      {segs.map((s, i) => {
        const last = i === segs.length - 1;
        const w = Math.max(1, s.w);
        // the data end of the bar is rounded; the start stays square on the baseline
        const r = last ? Math.min(3, w / 2) : 0;
        const d = `M${s.x} 0H${s.x + w - r}${r ? `Q${s.x + w} 0 ${s.x + w} ${r}V${H - r}Q${s.x + w} ${H} ${s.x + w - r} ${H}` : `V${H}`}H${s.x}Z`;
        return (
          <path key={s.band} d={d} fill={BAND_VAR[s.band]}>
            <title>{`${open[s.band]} ${s.band}`}</title>
          </path>
        );
      })}
    </svg>
  );
}

export interface BandTrendPoint {
  day: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

function dayLabel(day: string): string {
  const d = new Date(`${day}T00:00:00Z`);
  return Number.isNaN(d.getTime()) ? day : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' });
}

function changeText(from: number, to: number): string {
  const d = to - from;
  if (d === 0) return 'no change';
  return d > 0 ? `up ${d}` : `down ${-d}`;
}

/**
 * Open findings per day, one small panel per band (small multiples instead of four coloured lines on one plot,
 * which the band colours cannot keep apart). The panels share the day axis and the hover: pointing at a day in
 * any panel shows that day in all four, read out in one line above them. Each panel has its own scale, written
 * as its peak, so a band with few findings still shows its shape. Arrow keys move the day when the chart has focus.
 */
export function BandTrendPanels({ points, days }: { points: BandTrendPoint[]; days: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const captionId = useId();
  const n = points.length;
  const last = n > 0 ? points[n - 1]! : undefined;
  const first = n > 0 ? points[0]! : undefined;
  const at = hover !== null && hover < n ? points[hover]! : undefined;

  if (!last || !first) return null;
  const caption = at
    ? `${dayLabel(at.day)}: ${at.critical} critical, ${at.high} high, ${at.medium} medium, ${at.low} low open.`
    : `Today: ${last.critical} critical, ${last.high} high, ${last.medium} medium, ${last.low} low open. Point at a day to read it.`;

  const move = (e: React.PointerEvent<SVGSVGElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const f = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
    setHover(Math.round(f * (n - 1)));
  };

  return (
    <figure
      className="m-0"
      tabIndex={0}
      aria-describedby={captionId}
      aria-label={`Open findings by band over the last ${days} days`}
      onKeyDown={(e) => {
        if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
          e.preventDefault();
          const cur = hover ?? n - 1;
          setHover(Math.min(n - 1, Math.max(0, cur + (e.key === 'ArrowRight' ? 1 : -1))));
        } else if (e.key === 'Escape') setHover(null);
      }}
      onBlur={() => setHover(null)}
    >
      <figcaption id={captionId} aria-live="polite" className="mb-2 min-h-5 text-13 text-ink tnum">
        {caption}
      </figcaption>
      <div className="grid grid-cols-1 gap-x-6 gap-y-4 tablet:grid-cols-2">
        {OPEN_BANDS.map((b) => (
          <TrendPanel key={b} band={b} points={points} hover={hover} onMove={move} onLeave={() => setHover(null)} from={first[b]} to={last[b]} />
        ))}
      </div>
      <div className="mt-1 flex justify-between text-11 text-ink-2 tnum" aria-hidden="true">
        <span>{dayLabel(first.day)}</span>
        <span>{dayLabel(last.day)}</span>
      </div>
      <details className="mt-2 text-12">
        <summary className="cursor-pointer text-ink-2">Show the numbers</summary>
        <div className="max-h-64 overflow-auto">
          <table className="mt-1 text-12 tnum">
            <thead>
              <tr>
                <th className="pe-4 text-start font-medium">Day</th>
                {OPEN_BANDS.map((b) => (
                  <th key={b} className="ps-3 text-end font-medium">{BAND_LABEL[b]}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {points.map((p) => (
                <tr key={p.day}>
                  <td className="pe-4">{p.day}</td>
                  {OPEN_BANDS.map((b) => (
                    <td key={b} className="ps-3 text-end">{p[b]}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}

function TrendPanel({
  band,
  points,
  hover,
  onMove,
  onLeave,
  from,
  to,
}: {
  band: ChartBand;
  points: BandTrendPoint[];
  hover: number | null;
  onMove: (e: React.PointerEvent<SVGSVGElement>) => void;
  onLeave: () => void;
  from: number;
  to: number;
}) {
  const W = 320;
  const H = 64;
  const PAD = 4;
  const n = points.length;
  const peak = Math.max(...points.map((p) => p[band]));
  const max = Math.max(1, peak);
  const x = (i: number) => (n === 1 ? W : (i / (n - 1)) * W);
  const y = (v: number) => H - PAD - (v / max) * (H - PAD * 2);
  const path = useMemo(
    () => points.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)} ${y(p[band]).toFixed(1)}`).join(' '),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [points, band, max],
  );
  const hp = hover !== null && hover < n ? points[hover] : undefined;
  return (
    <div>
      <div className="flex items-baseline gap-2 text-13">
        <BandShape band={band as Band} size={10} />
        <span className="font-medium">{BAND_LABEL[band as Band]}</span>
        <span className="text-14 font-semibold tnum">{to}</span>
        <span className="text-12 text-ink-2">{changeText(from, to)}</span>
        <span className="ms-auto text-11 text-ink-2 tnum">peak {peak}</span>
      </div>
      <div className="relative mt-1">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="none"
          className="block h-16 w-full touch-none"
          aria-hidden="true"
          onPointerMove={onMove}
          onPointerLeave={onLeave}
        >
          <line x1="0" y1={H - 0.5} x2={W} y2={H - 0.5} stroke="var(--rule)" strokeWidth="1" vectorEffect="non-scaling-stroke" />
          <path d={path} fill="none" stroke={BAND_VAR[band]} strokeWidth="2" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
          {hp && hover !== null && (
            <line x1={x(hover)} y1="0" x2={x(hover)} y2={H} stroke="var(--ink-2)" strokeWidth="1" vectorEffect="non-scaling-stroke" />
          )}
        </svg>
        {hp && hover !== null && (
          // the marker is HTML so the stretched plot does not squash it into an ellipse
          <span
            aria-hidden="true"
            className="pointer-events-none absolute size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-surface"
            style={{ left: `${(x(hover) / W) * 100}%`, top: `${(y(hp[band]) / H) * 100}%`, background: BAND_VAR[band] }}
          />
        )}
      </div>
    </div>
  );
}

/**
 * One bar per band on a shared scale (the time to fix of each band). The band is named with its shape at the
 * start of the row, and the value is written at the end, so the colour only repeats what the words say.
 */
export function BandBars({
  rows,
  unit,
  describe,
}: {
  rows: { band: ChartBand; value: number }[];
  unit: string;
  describe: (row: { band: ChartBand; value: number }) => string;
}) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-13">
      {rows.map((r) => (
        <li key={r.band} className="grid grid-cols-[88px_1fr] items-center gap-3 tablet:grid-cols-[88px_1fr_minmax(0,22rem)]">
          <span className="flex items-center gap-2">
            <BandShape band={r.band as Band} size={10} />
            {BAND_LABEL[r.band as Band]}
          </span>
          <span className="block h-2" aria-hidden="true">
            <span
              className="block h-2 rounded-e-[3px]"
              style={{ width: `${Math.max(1, (r.value / max) * 100)}%`, background: BAND_VAR[r.band] }}
              title={`${r.value.toFixed(1)} ${unit}`}
            />
          </span>
          <span className="col-span-2 text-ink-2 tablet:col-span-1">{describe(r)}</span>
        </li>
      ))}
    </ul>
  );
}

/**
 * How the deadlines went, as parts of one bar: resolved in time, resolved late, still open past the deadline.
 * These are not risk bands, so they are ink, from light to dark, and each part is named below the bar.
 */
export function DeadlineBar({ within, late, breached }: { within: number; late: number; breached: number }) {
  const total = within + late + breached;
  if (total === 0) return null;
  const parts = [
    { key: 'within', n: within, cls: 'bg-ink-2/35', text: 'resolved in time' },
    { key: 'late', n: late, cls: 'bg-ink-2', text: 'resolved late' },
    { key: 'breached', n: breached, cls: 'bg-ink', text: 'still open past the deadline' },
  ].filter((p) => p.n > 0);
  return (
    <div>
      <div className="flex h-2 w-full max-w-[560px] gap-[2px]" aria-hidden="true">
        {parts.map((p, i) => (
          <span
            key={p.key}
            className={`${p.cls} block h-2 ${i === parts.length - 1 ? 'rounded-e-[3px]' : ''}`}
            style={{ width: `${(p.n / total) * 100}%` }}
            title={`${p.n} ${p.text}`}
          />
        ))}
      </div>
      <ul className="m-0 mt-1.5 flex list-none flex-wrap gap-x-5 gap-y-1 p-0 text-12 text-ink-2">
        {parts.map((p) => (
          <li key={p.key} className="flex items-center gap-1.5">
            <span className={`${p.cls} inline-block size-2`} aria-hidden="true" />
            <span className="tnum text-ink">{p.n}</span> {p.text}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Sums daily new and fixed counts into weeks ending on the last day, oldest first. */
export function toWeeks(points: { day: string; new: number; fixed: number }[]): { end: string; new: number; fixed: number }[] {
  const out: { end: string; new: number; fixed: number }[] = [];
  for (let i = points.length; i > 0; i -= 7) {
    const slice = points.slice(Math.max(0, i - 7), i);
    out.unshift({ end: slice[slice.length - 1]!.day, new: slice.reduce((n, p) => n + p.new, 0), fixed: slice.reduce((n, p) => n + p.fixed, 0) });
  }
  return out;
}

/**
 * Velocity: each week, findings that arrived (above the line, ink) against findings fixed (below the line, the
 * resolved teal). Position carries the meaning, so the two never depend on telling colours apart. Hover or focus
 * a week to read it.
 */
export function VelocityBars({ weeks }: { weeks: { end: string; new: number; fixed: number }[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const captionId = useId();
  if (weeks.length === 0) return null;
  const W = 640;
  const H = 120;
  const mid = H / 2;
  const max = Math.max(1, ...weeks.map((w) => Math.max(w.new, w.fixed)));
  const slot = W / weeks.length;
  const bw = Math.max(4, slot * 0.55);
  const h = (v: number) => (v / max) * (mid - 4);
  const totalNew = weeks.reduce((n, w) => n + w.new, 0);
  const totalFixed = weeks.reduce((n, w) => n + w.fixed, 0);
  const at = hover !== null ? weeks[hover] : undefined;
  const caption = at
    ? `Week ending ${dayLabel(at.end)}: ${at.new} new, ${at.fixed} fixed.`
    : `${totalNew} new and ${totalFixed} fixed in ${weeks.length} weeks: ${totalFixed >= totalNew ? 'fixing keeps up' : `${totalNew - totalFixed} more arrived than were fixed`}.`;
  return (
    <figure
      className="m-0"
      tabIndex={0}
      aria-describedby={captionId}
      aria-label="New and fixed findings per week"
      onKeyDown={(e) => {
        if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
          e.preventDefault();
          const cur = hover ?? weeks.length - 1;
          setHover(Math.min(weeks.length - 1, Math.max(0, cur + (e.key === 'ArrowRight' ? 1 : -1))));
        }
      }}
      onBlur={() => setHover(null)}
    >
      <figcaption id={captionId} aria-live="polite" className="mb-2 text-13 tnum">
        {caption}
      </figcaption>
      <div className="flex gap-3 text-12 text-ink-2" aria-hidden="true">
        <span className="flex items-center gap-1.5"><span className="inline-block size-2 bg-ink" />New, above the line</span>
        <span className="flex items-center gap-1.5"><span className="inline-block size-2" style={{ background: 'var(--resolved)' }} />Fixed, below</span>
        <span className="ms-auto tnum">peak {max} a week</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="mt-1 block h-[120px] w-full" aria-hidden="true" onPointerLeave={() => setHover(null)}>
        {weeks.map((w, i) => {
          const cx = i * slot + slot / 2;
          return (
            <g key={w.end} onPointerEnter={() => setHover(i)}>
              <rect x={i * slot} y="0" width={slot} height={H} fill={hover === i ? 'var(--chrome)' : 'transparent'} />
              {w.new > 0 && <rect x={cx - bw / 2} y={mid - 1 - h(w.new)} width={bw} height={h(w.new)} fill="var(--ink)" />}
              {w.fixed > 0 && <rect x={cx - bw / 2} y={mid + 1} width={bw} height={h(w.fixed)} fill="var(--resolved)" />}
            </g>
          );
        })}
        <line x1="0" y1={mid} x2={W} y2={mid} stroke="var(--rule)" strokeWidth="1" />
      </svg>
      <div className="mt-1 flex justify-between text-11 text-ink-2 tnum" aria-hidden="true">
        <span>{dayLabel(weeks[0]!.end)}</span>
        <span>{dayLabel(weeks[weeks.length - 1]!.end)}</span>
      </div>
    </figure>
  );
}

/** How long the open findings have been open. Past 90 days is set darker: those are the backlog, not the flow. */
export function AgeBars({ aging }: { aging: AgeBuckets }) {
  const rows = [
    { key: 'under_30', label: 'Under 30 days', n: aging.under_30, old: false },
    { key: 'd30_90', label: '30 to 90 days', n: aging.d30_90, old: false },
    { key: 'd90_180', label: '90 to 180 days', n: aging.d90_180, old: true },
    { key: 'over_180', label: 'Over 180 days', n: aging.over_180, old: true },
  ];
  const max = Math.max(1, ...rows.map((r) => r.n));
  return (
    <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-13">
      {rows.map((r) => (
        <li key={r.key} className="grid grid-cols-[120px_1fr_48px] items-center gap-3">
          <span className={r.old ? 'font-medium' : 'text-ink-2'}>{r.label}</span>
          <span className="block h-2" aria-hidden="true">
            {r.n > 0 && (
              <span className={`block h-2 rounded-e-[3px] ${r.old ? 'bg-ink' : 'bg-ink-2/45'}`} style={{ width: `${(r.n / max) * 100}%` }} />
            )}
          </span>
          <span className="text-end tnum">{r.n}</span>
        </li>
      ))}
    </ul>
  );
}
