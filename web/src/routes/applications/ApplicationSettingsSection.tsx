import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { getScoring, qk, toProblem, updateApplicationContext } from '@/api';
import type { ApplicationContext, ApplicationContextUpdate, ApplicationPage, ScoringResponse } from '@/api/types';
import { Button, ProblemMessage, Select, useToast } from '@/components';
import { useAccess } from '@/app/useAccess';

const CRITICALITY = ['critical', 'high', 'medium', 'low'] as const;
const DATA = ['pci', 'pii', 'phi', 'secret', 'public'] as const;
const CONTROLS = ['waf', 'api_gateway', 'mtls', 'private_network'] as const;
const LIFECYCLE = ['planning', 'development', 'production', 'deprecated'] as const;
/** Radix selects refuse an empty value, so "not described" is this word on the screen and the empty string on the wire. */
const NO_ENVIRONMENT = 'none';

const same = (a: string[], b: string[]) => a.length === b.length && [...a].sort().join() === [...b].sort().join();

/** The points a factor of the policy in force gives, so the form says what a choice is worth. */
function pointsOf(scoring: ScoringResponse | undefined, names: string[]): number | null {
  const hits = (scoring?.risk.factors ?? []).filter((f) => names.includes(f.name));
  return hits.length ? hits[0]!.points : null;
}

/**
 * What the score knows about the application: how critical it is, whether the internet reaches it, what data it holds, what
 * stands in front of it and where it is in its life. Each choice says what it is worth in the policy in force. An
 * application that an Application resource manages is shown and not editable: the resource is the truth for it.
 */
export function ApplicationSettingsSection({ app }: { app: ApplicationPage }) {
  const { t } = useTranslation();
  const toast = useToast();
  const qc = useQueryClient();
  const { can } = useAccess();
  const initial = app.context;
  const scoring = useQuery({ queryKey: qk.scoring(), queryFn: ({ signal }) => getScoring(signal), staleTime: 60_000 });
  // The page remounts this section when the application changes (its key is the version), so the draft starts from what was saved.
  const [draft, setDraft] = useState<ApplicationContext | undefined>(initial);

  const managed = initial?.managed_by === 'crd';
  const mayEdit = !managed && can(app.id, 'maintainer');
  const changes = useMemo<ApplicationContextUpdate>(() => {
    if (!initial || !draft) return {};
    const c: ApplicationContextUpdate = {};
    if (draft.business_criticality !== initial.business_criticality) c.business_criticality = draft.business_criticality;
    if (draft.internet_facing !== initial.internet_facing) c.internet_facing = draft.internet_facing;
    if (!same(draft.data_classification, initial.data_classification)) c.data_classification = draft.data_classification;
    if (!same(draft.compensating_controls, initial.compensating_controls)) c.compensating_controls = draft.compensating_controls;
    if (draft.lifecycle !== initial.lifecycle) c.lifecycle = draft.lifecycle;
    if (draft.environment !== initial.environment) c.environment = draft.environment;
    return c;
  }, [initial, draft]);
  const dirty = Object.keys(changes).length > 0;

  const save = useMutation({
    mutationFn: () => updateApplicationContext(app.id, changes),
    onSuccess: async () => {
      toast.info(t('appSettings.saved'));
      await qc.invalidateQueries({ queryKey: ['applications'] });
    },
  });

  if (!initial || !draft) return null;
  const toggle = (key: 'data_classification' | 'compensating_controls', v: string) =>
    setDraft((d) => d && ({ ...d, [key]: d[key].includes(v) ? d[key].filter((x) => x !== v) : [...d[key], v] }));
  const worth = (names: string[]) => {
    const p = pointsOf(scoring.data, names);
    return p === null ? '' : t('appSettings.points', { points: p > 0 ? `+${p}` : `−${Math.abs(p)}` });
  };

  return (
    <section aria-labelledby="app-settings" className="max-w-[64ch]">
      <h2 id="app-settings" className="text-14 font-semibold">{t('appSettings.title')}</h2>
      <p className="mt-1 text-13 text-ink-2">{t('appSettings.intro')}</p>
      {managed && <p role="note" className="mt-3 border-s-[3px] border-accent ps-3 text-13">{t('appSettings.managedBy')}</p>}
      {!managed && !mayEdit && <p className="mt-3 text-13 text-ink-2">{t('appSettings.noRole')}</p>}

      {initial.type === 'repo' && (
        <p className="mt-3 text-13"><span className="font-semibold">{t('appSettings.identity')}</span> {t('appSettings.identityRepo', { branch: initial.branch, repository: initial.repository })}</p>
      )}

      <form className="mt-5 space-y-6" onSubmit={(e) => { e.preventDefault(); if (dirty) save.mutate(); }}>
        <fieldset disabled={!mayEdit} className="m-0 space-y-6 border-0 p-0">
          <div>
            <label id="crit-label" className="text-13 font-semibold">{t('appSettings.criticality')}</label>
            <p className="mb-1 text-12 text-ink-2">{t('appSettings.criticalityHelp')} <span className="whitespace-nowrap">{worth(['APP_CRITICAL'])} {t('appSettings.crit_critical').toLowerCase()}, {worth(['APP_HIGH'])} {t('appSettings.crit_high').toLowerCase()}.</span></p>
            <Select
              label={t('appSettings.criticality')}
              value={draft.business_criticality}
              onValueChange={(v) => setDraft({ ...draft, business_criticality: v as ApplicationContext['business_criticality'] })}
              options={CRITICALITY.map((c) => ({ value: c, label: t(`appSettings.crit_${c}`) }))}
            />
          </div>

          <div>
            <p className="m-0 text-13 font-semibold">{t('appSettings.exposure')}</p>
            <label className="mt-1 flex items-start gap-2 text-13">
              <input type="checkbox" className="mt-0.5 size-4 accent-[var(--accent)]" checked={draft.internet_facing} onChange={(e) => setDraft({ ...draft, internet_facing: e.target.checked })} />
              <span>{t('appSettings.internet')} <span className="text-ink-2">{worth(['INTERNET_FACING'])}</span><span className="block text-12 text-ink-2">{t('appSettings.internetHelp')}</span></span>
            </label>
          </div>

          <div>
            <p className="m-0 text-13 font-semibold">{t('appSettings.data')}</p>
            <p className="mb-1 text-12 text-ink-2">{t('appSettings.dataHelp')} {worth(['SENSITIVE_DATA'])}</p>
            {DATA.map((d) => (
              <label key={d} className="flex items-center gap-2 py-0.5 text-13">
                <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={draft.data_classification.includes(d)} onChange={() => toggle('data_classification', d)} />
                {t(`appSettings.data_${d}`)}
              </label>
            ))}
          </div>

          <div>
            <p className="m-0 text-13 font-semibold">{t('appSettings.controls')}</p>
            <p className="mb-1 text-12 text-ink-2">{t('appSettings.controlsHelp')} {worth(['COMPENSATING_CONTROL'])}</p>
            {CONTROLS.map((c) => (
              <label key={c} className="flex items-center gap-2 py-0.5 text-13">
                <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={draft.compensating_controls.includes(c)} onChange={() => toggle('compensating_controls', c)} />
                {t(`appSettings.control_${c}`)}
              </label>
            ))}
          </div>

          <div>
            <label className="text-13 font-semibold">{t('appSettings.environment')}</label>
            <p className="mb-1 text-12 text-ink-2">{t('appSettings.environmentHelp')} {worth(['PRODUCTION_ENV'])}</p>
            <Select
              label={t('appSettings.environment')}
              value={draft.environment || NO_ENVIRONMENT}
              onValueChange={(v) => setDraft({ ...draft, environment: (v === NO_ENVIRONMENT ? '' : v) as ApplicationContext['environment'] })}
              options={[NO_ENVIRONMENT, ...(scoring.data?.environments ?? ['production', 'staging', 'test', 'development'])].map((e) => ({ value: e, label: t(`appSettings.env_${e}`) }))}
            />
          </div>

          <div>
            <label className="text-13 font-semibold">{t('appSettings.lifecycle')}</label>
            <p className="mb-1 text-12 text-ink-2">{t('appSettings.lifecycleHelp')}</p>
            <Select
              label={t('appSettings.lifecycle')}
              value={draft.lifecycle}
              onValueChange={(v) => setDraft({ ...draft, lifecycle: v as ApplicationContext['lifecycle'] })}
              options={LIFECYCLE.map((l) => ({ value: l, label: t(`appSettings.life_${l}`) }))}
            />
          </div>
        </fieldset>

        {save.isError && <ProblemMessage problem={toProblem(save.error)} title={t('appSettings.saveFailed')} />}
        <div className="flex items-center gap-4">
          {mayEdit && <Button type="submit" variant="primary" disabled={!dirty} loading={save.isPending}>{save.isPending ? t('appSettings.saving') : t('appSettings.save')}</Button>}
          {mayEdit && !dirty && <span className="text-13 text-ink-2">{t('appSettings.nothingChanged')}</span>}
          <Link to="/about" className="ms-auto text-13">{t('appSettings.seeRules')}</Link>
        </div>
      </form>
    </section>
  );
}
