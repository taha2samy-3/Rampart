import { useTranslation } from 'react-i18next';
import { BAND_LABEL, BandShape } from '@/components';
import { BANDS } from '@/lib/band';
import { fieldValues, toggleFieldValue } from '@/lib/grammar';

const STATES = ['open', 'under_investigation', 'fixed', 'risk_accepted'] as const;

/**
 * Facet rail. Risk and state write into `q` through the grammar. The other
 * facets need the groupBy endpoint for counts and arrive with it.
 */
export function Facets({ q, onQueryChange }: { q: string; onQueryChange: (q: string) => void }) {
  const { t } = useTranslation();
  const risk = fieldValues(q, 'risk');
  const state = fieldValues(q, 'state');
  return (
    <div className="flex flex-col gap-4 px-3 py-3 text-13">
      <fieldset className="m-0 border-0 p-0">
        <legend className="mb-1 p-0 font-semibold">{t('findings.facetRisk')}</legend>
        {BANDS.map((b) => (
          <label key={b} className="flex h-7 cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              className="size-3.5 accent-[var(--accent)]"
              checked={risk.includes(b)}
              onChange={() => onQueryChange(toggleFieldValue(q, 'risk', b))}
            />
            <BandShape band={b} size={11} />
            <span>{BAND_LABEL[b]}</span>
          </label>
        ))}
      </fieldset>
      <fieldset className="m-0 border-0 p-0">
        <legend className="mb-1 p-0 font-semibold">{t('findings.facetState')}</legend>
        {STATES.map((s) => (
          <label key={s} className="flex h-7 cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              className="size-3.5 accent-[var(--accent)]"
              checked={state.includes(s)}
              onChange={() => onQueryChange(toggleFieldValue(q, 'state', s))}
            />
            <span>{s === 'under_investigation' ? t('findings.stateShort') : t(`state.${s}`)}</span>
          </label>
        ))}
      </fieldset>
      <p className="text-12 text-ink-2">{t('findings.facetsLater')}</p>
    </div>
  );
}
