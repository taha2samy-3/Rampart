import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { ScoringFactor, ScoringResponse } from '@/api/types';
import { Table, TBody, Td, Th, THead, Tr } from '@/components';
import { cn } from '@/lib/cn';

const BANDS = ['critical', 'high', 'medium', 'low'] as const;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const GROUPS = ['threat', 'context', 'reduction'] as const;

export const signed = (n: number) => (n > 0 ? `+${n}` : `−${Math.abs(n)}`);

/** The points of each severity, and the bands the score is cut into. */
export function BaseAndBands({ scoring }: { scoring: ScoringResponse }) {
  const { t } = useTranslation();
  const { base, bands } = scoring.risk;
  return (
    <div className="grid gap-x-10 gap-y-4 sm:grid-cols-2">
      <section aria-labelledby="sc-base">
        <h3 id="sc-base" className="text-13 font-semibold">{t('about.baseTitle')}</h3>
        <dl className="mt-1 grid max-w-xs grid-cols-[1fr_auto] gap-y-0.5 text-13">
          {SEVERITIES.map((s) => (
            <div key={s} className="contents">
              <dt className="capitalize text-ink-2">{s}</dt>
              <dd className="m-0 text-end tnum">{base[s] ?? 0}</dd>
            </div>
          ))}
        </dl>
      </section>
      <section aria-labelledby="sc-bands">
        <h3 id="sc-bands" className="text-13 font-semibold">{t('about.bandsTitle')}</h3>
        <ul className="m-0 mt-1 list-none p-0 text-13 text-ink-2">
          {(['critical', 'high', 'medium'] as const).map((b) => (
            <li key={b} className="capitalize">{t('about.bandFrom', { band: b, from: bands[b] })}</li>
          ))}
          <li>{t('about.bandLow', { to: bands.medium })}</li>
        </ul>
      </section>
    </div>
  );
}

/** Every factor of the policy in force, in the three groups of the score bar, each with its points and the rule behind it. */
export function FactorsTable({ factors }: { factors: ScoringFactor[] }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Table aria-label={t('about.factorsTitle')}>
      <THead>
        <tr>
          <Th className="w-[70%]">{t('about.colFactor')}</Th>
          <Th align="end" className="w-[30%]">{t('about.colPoints')}</Th>
        </tr>
      </THead>
      <TBody>
        {GROUPS.flatMap((g) => {
          const rows = factors.filter((f) => f.group === g);
          if (rows.length === 0) return [];
          return [
            <Tr key={`g-${g}`} className="bg-chrome/60">
              <Td colSpan={2} className="h-8 text-12 font-semibold text-ink-2">{t(`about.group_${g}`)}</Td>
            </Tr>,
            ...rows.map((f) => (
              <Tr key={f.name} className="align-top">
                <Td className="whitespace-normal py-2">
                  <span className="block">{f.reason || f.name}</span>
                  <button type="button" aria-expanded={open === f.name} onClick={() => setOpen(open === f.name ? null : f.name)} className="mt-0.5 text-12 text-ink-2 underline-offset-2 hover:underline">
                    {t('about.showRule')}
                  </button>
                  {open === f.name && <code className="mt-1 block break-words font-mono text-12 text-ink-2">{f.name}: {f.when}</code>}
                </Td>
                <Td align="end" className={cn('py-2 font-semibold', f.points < 0 && 'text-resolved')}>{signed(f.points)}</Td>
              </Tr>
            )),
          ];
        })}
      </TBody>
    </Table>
  );
}

/** How long a finding may stay open: the band of the finding by the criticality of its application. */
export function SlaMatrix({ scoring }: { scoring: ScoringResponse }) {
  const { t } = useTranslation();
  const { matrix } = scoring.sla;
  return (
    <>
      <Table aria-label={t('about.slaTitle')} className="max-w-xl">
        <THead>
          <tr>
            <Th>{t('about.slaCorner')}</Th>
            {BANDS.map((c) => <Th key={c} align="end" className="capitalize">{c}</Th>)}
          </tr>
        </THead>
        <TBody>
          {BANDS.map((band) => (
            <Tr key={band} className="h-9">
              <Th scope="row" className="capitalize">{band}</Th>
              {BANDS.map((crit) => <Td key={crit} align="end">{t('about.slaDays', { count: matrix[band]?.[crit] ?? 0 })}</Td>)}
            </Tr>
          ))}
        </TBody>
      </Table>
      <ul className="m-0 mt-2 list-none p-0 text-13 text-ink-2">
        {scoring.sla.kevDueDate && <li>{t('about.slaKev')}</li>}
        {scoring.sla.maxDays > 0 && <li>{t('about.slaMax', { count: scoring.sla.maxDays })}</li>}
        {scoring.sla.pauseDuringRiskAcceptance && <li>{t('about.slaPause')}</li>}
        {scoring.sla.restartOnReactivation && <li>{t('about.slaRestart')}</li>}
      </ul>
    </>
  );
}
