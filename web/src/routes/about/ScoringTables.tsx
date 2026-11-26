import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { ScoringFactor, ScoringResponse } from '@/api/types';
import { Button, IconCheck, IconCopy, IconSearch, Input, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { cn } from '@/lib/cn';

const BANDS = ['critical', 'high', 'medium', 'low'] as const;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const PREFERRED_GROUPS = ['threat', 'context', 'reduction'] as const;

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
            <li key={b} className="first-letter:uppercase">{t('about.bandFrom', { band: b, from: bands[b] })}</li>
          ))}
          <li>{t('about.bandLow', { to: bands.medium })}</li>
        </ul>
      </section>
    </div>
  );
}

/** Every factor of the policy in force, displayed dynamically with CEL rule inspector and enterprise attribute badges. */
export function FactorsTable({ factors }: { factors: ScoringFactor[] }) {
  const { t } = useTranslation();
  const [selectedGroup, setSelectedGroup] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Dynamically extract all unique groups preserving canonical order first
  const availableGroups = useMemo(() => {
    const rawGroups = Array.from(new Set(factors.map((f) => f.group || 'context')));
    return rawGroups.sort((a, b) => {
      const ia = PREFERRED_GROUPS.indexOf(a as (typeof PREFERRED_GROUPS)[number]);
      const ib = PREFERRED_GROUPS.indexOf(b as (typeof PREFERRED_GROUPS)[number]);
      if (ia !== -1 && ib !== -1) return ia - ib;
      if (ia !== -1) return -1;
      if (ib !== -1) return 1;
      return a.localeCompare(b);
    });
  }, [factors]);

  const filteredFactors = useMemo(() => {
    const q = search.trim().toLowerCase();
    return factors.filter((f) => {
      if (selectedGroup !== 'all' && (f.group || 'context') !== selectedGroup) return false;
      if (!q) return true;
      return (
        f.name.toLowerCase().includes(q) ||
        (f.reason && f.reason.toLowerCase().includes(q)) ||
        f.when.toLowerCase().includes(q)
      );
    });
  }, [factors, selectedGroup, search]);

  const allAreExpanded = useMemo(() => {
    if (filteredFactors.length === 0) return false;
    return filteredFactors.every((f) => expanded[f.name]);
  }, [filteredFactors, expanded]);

  const toggleAll = () => {
    if (allAreExpanded) {
      setExpanded({});
    } else {
      const next: Record<string, boolean> = {};
      for (const f of filteredFactors) {
        next[f.name] = true;
      }
      setExpanded(next);
    }
  };

  const copyRule = (name: string, rule: string) => {
    void navigator.clipboard?.writeText(rule);
    setCopiedKey(name);
    setTimeout(() => {
      setCopiedKey((curr) => (curr === name ? null : curr));
    }, 2000);
  };

  return (
    <div className="space-y-3">
      {/* Controls & Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2.5">
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            aria-pressed={selectedGroup === 'all'}
            onClick={() => setSelectedGroup('all')}
            className={cn(
              'rounded-ctl border px-2.5 py-1 text-12 font-medium',
              selectedGroup === 'all'
                ? 'border-accent bg-accent text-accent-contrast'
                : 'border-rule bg-surface text-ink-2 hover:bg-chrome hover:text-ink',
            )}
          >
            {t('about.allGroups')} ({factors.length})
          </button>
          {availableGroups.map((g) => {
            const count = factors.filter((f) => (f.group || 'context') === g).length;
            const label = t(`about.group_${g}`, { defaultValue: g.charAt(0).toUpperCase() + g.slice(1) });
            return (
              <button
                key={g}
                type="button"
                aria-pressed={selectedGroup === g}
                onClick={() => setSelectedGroup(g)}
                className={cn(
                  'rounded-ctl border px-2.5 py-1 text-12 font-medium',
                  selectedGroup === g
                    ? 'border-accent bg-accent text-accent-contrast'
                    : 'border-rule bg-surface text-ink-2 hover:bg-chrome hover:text-ink',
                )}
              >
                {label} ({count})
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-2">
          <div className="relative min-w-[200px] max-w-xs">
            <IconSearch className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-2" />
            <Input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t('about.searchPlaceholder')}
              className="h-7 pl-8 text-12"
              aria-label={t('about.searchPlaceholder')}
            />
          </div>
          {filteredFactors.length > 0 && (
            <Button variant="ghost" onClick={toggleAll} className="h-7 px-2 text-12">
              {allAreExpanded ? t('about.collapseAll') : t('about.expandAll')}
            </Button>
          )}
        </div>
      </div>

      {filteredFactors.length === 0 ? (
        <div className="border border-dashed border-rule p-6 text-13 text-ink-2">
          {t('about.noMatchingFactors')}
        </div>
      ) : (
        <Table aria-label={t('about.factorsTitle')}>
          <THead>
            <tr>
              <Th className="w-[72%]">{t('about.colFactor')}</Th>
              <Th align="end" className="w-[28%]">{t('about.colPoints')}</Th>
            </tr>
          </THead>
          <TBody>
            {availableGroups.flatMap((g) => {
              const rows = filteredFactors.filter((f) => (f.group || 'context') === g);
              if (rows.length === 0) return [];
              const groupTitle = t(`about.group_${g}`, { defaultValue: g.charAt(0).toUpperCase() + g.slice(1) });
              return [
                <Tr key={`g-${g}`} className="bg-chrome/70">
                  <Td colSpan={2} className="h-8 text-12 font-semibold text-ink-2">
                    <span className="flex items-center gap-2">
                      <span>{groupTitle}</span>
                      <span className="text-12 font-normal tnum text-ink-2">{rows.length}</span>
                    </span>
                  </Td>
                </Tr>,
                ...rows.map((f) => {
                  const isOpen = !!expanded[f.name];
                  const hasAttr = f.when.includes('attributes') || f.when.includes('attr(');
                  const hasEnv = f.when.includes('environment') || f.when.includes('branch');
                  const isThreat = f.group === 'threat' || f.when.includes('kev') || f.when.includes('epss');
                  const isCopied = copiedKey === f.name;

                  return (
                    <Tr key={f.name} className="align-top">
                      <Td className="whitespace-normal py-2.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <code className="bg-chrome px-1.5 py-0.5 font-mono text-12 font-semibold text-ink">
                            {f.name}
                          </code>
                        </div>
                        {(() => {
                          // What the rule reads, said in words (docs/13: plain text for tags, colour is for risk).
                          const traits = [
                            hasAttr && t('about.badgeAttributeAware'),
                            hasEnv && t('about.badgeEnvAware'),
                            isThreat && t('about.badgeThreatIntel'),
                            f.points < 0 && t('about.badgeMitigation'),
                          ].filter(Boolean);
                          return traits.length > 0 ? <p className="m-0 mt-0.5 text-12 text-ink-2 first-letter:uppercase">{traits.join(', ')}</p> : null;
                        })()}

                        <p className="mt-1 text-13 font-medium text-ink">{f.reason || f.name}</p>

                        <div className="mt-1 flex items-center gap-3">
                          <button
                            type="button"
                            aria-expanded={isOpen}
                            onClick={() =>
                              setExpanded((prev) => ({
                                ...prev,
                                [f.name]: !prev[f.name],
                              }))
                            }
                            className="text-12 font-medium text-ink-2 underline-offset-2 hover:text-ink hover:underline"
                          >
                            {isOpen ? t('about.collapseAll') : t('about.showRule')}
                          </button>
                        </div>

                        {isOpen && (
                          <div className="mt-2 border border-rule bg-surface p-2.5 font-mono text-12 text-ink">
                            <div className="mb-1.5 flex items-center justify-between text-12 text-ink-2">
                              <span className="font-sans font-medium text-ink-2">
                                {t('about.celRuleTitle')}
                              </span>
                              <button
                                type="button"
                                onClick={() => copyRule(f.name, f.when)}
                                className="flex items-center gap-1 font-sans text-ink-2 hover:text-ink"
                                title={t('about.copyRule')}
                              >
                                {isCopied ? (
                                  <>
                                    <IconCheck className="h-3 w-3 text-resolved" />
                                    <span className="text-resolved">{t('about.copied')}</span>
                                  </>
                                ) : (
                                  <>
                                    <IconCopy className="h-3 w-3" />
                                    <span>{t('about.copyRule')}</span>
                                  </>
                                )}
                              </button>
                            </div>
                            <pre className="overflow-x-auto whitespace-pre-wrap break-all bg-chrome p-2 text-12 leading-relaxed text-ink">
                              <code>{f.when}</code>
                            </pre>
                          </div>
                        )}
                      </Td>
                      <Td align="end" className="py-2.5">
                        <span className={cn('text-13 font-semibold tnum', f.points < 0 ? 'text-resolved' : 'text-ink')}>
                          {signed(f.points)}
                        </span>
                      </Td>
                    </Tr>
                  );
                }),
              ];
            })}
          </TBody>
        </Table>
      )}
    </div>
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
            {BANDS.map((c) => (
              <Th key={c} align="end" className="capitalize">
                {c}
              </Th>
            ))}
          </tr>
        </THead>
        <TBody>
          {BANDS.map((band) => (
            <Tr key={band} className="h-9">
              <Th scope="row" className="capitalize">
                {band}
              </Th>
              {BANDS.map((crit) => (
                <Td key={crit} align="end" className={matrix[band]?.[crit] === undefined ? 'text-ink-2' : undefined}>
                  {matrix[band]?.[crit] === undefined ? t('about.slaNotConfigured') : t('about.slaDays', { count: matrix[band][crit] })}
                </Td>
              ))}
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
