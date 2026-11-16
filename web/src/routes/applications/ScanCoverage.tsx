import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { CategoryCoverage, OpenBand } from '@/api/types';
import { BandMixBar, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { openText } from '@/lib/apps';
import { absoluteDate, shortAge } from '@/lib/format';

/** A scan older than this is called stale: the code it read has likely moved on. */
export const STALE_DAYS = 30;

const BANDS: OpenBand[] = ['critical', 'high', 'medium', 'low'];

function openOf(c: CategoryCoverage): Record<OpenBand, number> {
  return Object.fromEntries(BANDS.map((b) => [b, c.open[b] ?? 0])) as Record<OpenBand, number>;
}

function daysSince(iso: string, now: number): number {
  return Math.floor((now - new Date(iso).getTime()) / 86_400_000);
}

const SHORT: Record<string, string> = {
  sast: 'SAST', sca: 'SCA', secret: 'Secrets', iac: 'IaC', container: 'Images', dast: 'DAST', cspm: 'Cloud',
  license: 'Licences', supply_chain: 'Supply chain',
};

function niceMax(v: number): number {
  if (v <= 4) return 4;
  const step = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * step >= v) return m * step;
  return 10 * step;
}

/**
 * The radar other ASPMs draw, held to this product's rules (D101): the axes are always in the table's order, so
 * the shape compares across applications; the distance from the centre is the count, on a linear scale, never the
 * area; the line is neutral ink, because colour is for risk; a kind never scanned is a dashed spoke named "not
 * scanned", not a zero; every spoke carries its number. The table below it is the exact reading.
 */
export function CoverageRadar({ rows, totals, label }: { rows: CategoryCoverage[]; totals: number[]; label: string }) {
  const { t } = useTranslation();
  const [hover, setHover] = useState<number | null>(null);
  const S = 300;
  const c = S / 2;
  const R = 92;
  const top = niceMax(Math.max(0, ...totals));
  const n = rows.length;
  const angle = (i: number) => -Math.PI / 2 + (i * 2 * Math.PI) / n;
  const at = (i: number, r: number) => [c + r * Math.cos(angle(i)), c + r * Math.sin(angle(i))] as const;
  const radius = (v: number) => (v / top) * R;
  const scanned = rows.map((r) => !!r.last_scan);
  const pts = rows.map((_, i) => at(i, radius(totals[i] ?? 0)));
  const poly = pts.filter((_, i) => scanned[i]).map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  return (
    // The labels sit outside the spokes: a 70 px margin on each side keeps "Supply chain" or "not scanned" whole.
    <svg viewBox={`-70 -6 ${S + 140} ${S + 12}`} className="block h-auto w-full max-w-[420px]" role="img" aria-label={label}>
      {[1 / 3, 2 / 3, 1].map((f) => (
        <polygon
          key={f}
          points={rows.map((_, i) => at(i, R * f).map((v) => v.toFixed(1)).join(',')).join(' ')}
          fill="none"
          stroke="var(--rule)"
          strokeWidth="1"
        />
      ))}
      {[1 / 3, 2 / 3, 1].map((f) => (
        <text key={`t${f}`} x={c + 5} y={c - R * f + 11} fontSize="9" fill="var(--ink-2)">
          {Math.round(top * f)}
        </text>
      ))}
      {rows.map((r, i) => {
        const [x, y] = at(i, R);
        return (
          <line
            key={`s${r.category}`}
            x1={c}
            y1={c}
            x2={x}
            y2={y}
            stroke={scanned[i] ? 'var(--rule)' : 'var(--ink-2)'}
            strokeWidth="1"
            strokeDasharray={scanned[i] ? undefined : '3 3'}
          />
        );
      })}
      {poly && <polygon points={poly} fill="var(--ink)" fillOpacity="0.08" stroke="var(--ink-2)" strokeWidth="2" strokeLinejoin="round" />}
      {rows.map((r, i) => {
        const [lx, ly] = at(i, R + 26);
        const anchor = Math.abs(lx - c) < 8 ? 'middle' : lx > c ? 'start' : 'end';
        const total = totals[i] ?? 0;
        return (
          <g key={`l${r.category}`}>
            <text x={lx} y={ly - 2} fontSize="11" textAnchor={anchor} fill="var(--ink)" fontWeight={scanned[i] ? 400 : 600}>
              {SHORT[r.category] ?? r.category}
            </text>
            <text x={lx} y={ly + 11} fontSize="10" textAnchor={anchor} fill={scanned[i] ? 'var(--ink-2)' : 'var(--ink)'} fontWeight={scanned[i] ? 400 : 600}>
              {scanned[i] ? t('apps.radarOpen', { count: total }) : t('apps.notScannedShort')}
            </text>
          </g>
        );
      })}
      {rows.map((r, i) => {
        if (!scanned[i]) return null;
        const [x, y] = pts[i]!;
        return (
          <g key={`p${r.category}`} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
            <circle cx={x} cy={y} r="12" fill="transparent" />
            <circle cx={x} cy={y} r={hover === i ? 5 : 4} fill="var(--ink-2)" stroke="var(--surface)" strokeWidth="2" />
            <title>{`${SHORT[r.category] ?? r.category}: ${t('apps.radarOpen', { count: totals[i] ?? 0 })}`}</title>
          </g>
        );
      })}
    </svg>
  );
}

/**
 * Which kinds of testing an application has, and what each left open (D101). Other ASPMs draw this as a radar;
 * a radar's shape depends on the order of its axes and its area exaggerates, so here it is one row per kind, in
 * a fixed order, with the gap named in words. Colour is only the risk of the open findings (docs/13 §6), on one
 * scale shared by every row so the rows compare.
 */
export function ScanCoverage({ rows, now: fixedNow }: { rows: CategoryCoverage[]; now?: number }) {
  const { t } = useTranslation();
  const [clock] = useState(() => Date.now()); // read once: the page is about today
  const now = fixedNow ?? clock;
  const name = (c: string) => t(`apps.cat_${c}`, { defaultValue: c });
  const missing = rows.filter((r) => !r.last_scan);
  const stale = rows.filter((r) => r.last_scan && daysSince(r.last_scan, now) > STALE_DAYS);
  const totals = rows.map((r) => BANDS.reduce((n, b) => n + (r.open[b] ?? 0), 0));
  const max = Math.max(1, ...totals);
  const summary =
    missing.length === 0
      ? t('apps.scanCoverageAll', { count: rows.length })
      : t('apps.scanCoverageSome', { scanned: rows.length - missing.length, total: rows.length, missing: missing.map((r) => name(r.category)).join(', ') });

  return (
    <section className="mt-6" aria-labelledby="app-scan-coverage">
      <h2 id="app-scan-coverage" className="mb-1 text-14 font-semibold">{t('apps.scanCoverage')}</h2>
      <p className="m-0 mb-1 text-13">
        {summary}
        {stale.length > 0 && ` ${t('apps.scanCoverageStale', { days: STALE_DAYS, which: stale.map((r) => name(r.category)).join(', ') })}`}
      </p>
      <p className="m-0 mb-2 text-12 text-ink-2">{t('apps.scanCoverageHelp')}</p>
      <div className="mb-3 flex flex-wrap items-center gap-6">
        <CoverageRadar rows={rows} totals={totals} label={summary} />
        <p className="m-0 max-w-[36ch] text-12 text-ink-2">{t('apps.radarHelp')}</p>
      </div>
      <Table aria-label={t('apps.scanCoverage')}>
        <THead>
          <tr>
            <Th>{t('apps.colKind')}</Th>
            <Th>{t('apps.colScannedBy')}</Th>
            <Th>{t('apps.colWhen')}</Th>
            <Th className="w-[30%]">{t('apps.colOpen')}</Th>
          </tr>
        </THead>
        <TBody>
          {rows.map((r) => {
            const open = openOf(r);
            const text = openText(open, t);
            const old = r.last_scan ? daysSince(r.last_scan, now) > STALE_DAYS : false;
            return (
              <Tr key={r.category} className="h-10">
                <Td className="text-13">{name(r.category)}</Td>
                <Td className={r.last_scan ? 'text-13 text-ink-2' : 'text-13 font-medium text-ink'}>
                  {r.last_scan ? r.scanners.join(', ') : t('apps.notScanned')}
                </Td>
                <Td className={old ? 'text-13 font-medium text-ink' : 'text-13 text-ink-2'} title={r.last_scan ? absoluteDate(r.last_scan) : undefined}>
                  {r.last_scan ? (old ? t('apps.staleScan', { age: shortAge(r.last_scan) }) : shortAge(r.last_scan)) : '—'}
                </Td>
                <Td>
                  <div className="flex items-center gap-3">
                    <div className="min-w-0 flex-1">
                      <BandMixBar open={open} max={max} label={text || t('apps.noOpen')} />
                    </div>
                    <span className="shrink-0 text-12 text-ink-2">{text || (r.last_scan ? t('apps.noneOpen') : '')}</span>
                  </div>
                </Td>
              </Tr>
            );
          })}
        </TBody>
      </Table>
    </section>
  );
}
