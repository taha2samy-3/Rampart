import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { getScoring, qk } from '@/api';
import type { ApplicationPage, ScoringResponse } from '@/api/types';

/** The points a factor of the policy in force gives, so the display says what a choice is worth. */
function factorPoints(scoring: ScoringResponse | undefined, names: string[]): number | null {
  const hits = (scoring?.risk.factors ?? []).filter((f) => names.includes(f.name));
  return hits.length ? hits[0]!.points : null;
}

/**
 * What the score knows about the application: how critical it is, whether the internet reaches it, what data it holds,
 * what stands in front of it and where it runs. Each dimension shows its live contribution to the finding scores
 * based on the active risk scoring policy.
 *
 * Editing from the UI is disabled to maintain declarative GitOps / CRD single-source-of-truth integrity.
 */
export function ApplicationSettingsSection({ app }: { app: ApplicationPage }) {
  const { t } = useTranslation();
  const initial = app.context;
  const scoring = useQuery({ queryKey: qk.scoring(), queryFn: ({ signal }) => getScoring(signal), staleTime: 60_000 });

  if (!initial) return null;

  const pointsText = (names: string[], active = true) => {
    if (!active) return null;
    const p = factorPoints(scoring.data, names);
    if (p === null) return null;
    return (
      <span className="ms-2 text-12 tnum text-ink-2">
        {p > 0 ? `+${p}` : `−${Math.abs(p)}`} {t('appSettings.points', { points: '' }).trim()}
      </span>
    );
  };

  const isSensitiveData = initial.data_classification?.some((d) => ['pci', 'pii', 'phi'].includes(d));
  const hasControls = initial.compensating_controls?.some((c) => ['waf', 'api_gateway', 'mtls', 'private_network'].includes(c));
  const isProduction = initial.environment === 'production';
  const isCritical = initial.business_criticality === 'critical';
  const isHigh = initial.business_criticality === 'high';
  const attributes = initial.attributes ?? {};
  const attributeEntries = Object.entries(attributes);

  return (
    <section id="app-settings-section" data-testid="app-settings-section" aria-labelledby="app-settings" className="max-w-[72ch] space-y-6">
      <div>
        <h2 id="app-settings" className="text-14 font-semibold">{t('appSettings.title')}</h2>
        <p className="mt-1 text-13 text-ink-2">{t('appSettings.intro')}</p>
        <div role="note" className="mt-3 rounded-ctl border border-rule/80 bg-surface/70 p-3 text-13">
          <p className="m-0 font-medium text-ink flex items-center gap-2">
            {t('appSettings.readOnlyNotice')}
          </p>
        </div>
      </div>

      {initial.type === 'repo' && initial.repository && (
        <div className="rounded-ctl border border-rule bg-surface p-4">
          <h3 className="text-13 font-semibold text-ink">{t('appSettings.identity')}</h3>
          <p className="mt-1 text-13 text-ink-2">
            {t('appSettings.identityRepo', { branch: initial.branch, repository: initial.repository })}
          </p>
          {initial.managed_by && (
            <p className="mt-1 text-12 text-ink-2">
              Managed by: <code className="rounded bg-chrome px-1 py-0.5 font-mono text-12">{initial.managed_by}</code>
            </p>
          )}
        </div>
      )}

      {/* Context Dimensions & Risk Score Contribution Grid */}
      <div className="space-y-4">
        {/* Environment */}
        <div className="rounded-ctl border border-rule bg-surface p-4">
          <div className="flex items-start justify-between">
            <div>
              <h4 className="text-13 font-semibold text-ink">{t('appSettings.environment')}</h4>
              <p className="mt-0.5 text-12 text-ink-2">{t('appSettings.environmentHelp')}</p>
            </div>
            {pointsText(['PRODUCTION_ENV'], isProduction)}
          </div>
          <div className="mt-2.5">
            <span className="inline-flex items-center rounded-ctl border border-rule bg-chrome px-2.5 py-1 text-12 font-medium text-ink">
              {initial.environment ? t(`appSettings.env_${initial.environment}`, { defaultValue: initial.environment }) : t('appSettings.env_none')}
            </span>
          </div>
        </div>

        {/* Business Criticality */}
        <div className="rounded-ctl border border-rule bg-surface p-4">
          <div className="flex items-start justify-between">
            <div>
              <h4 className="text-13 font-semibold text-ink">{t('appSettings.criticality')}</h4>
              <p className="mt-0.5 text-12 text-ink-2">{t('appSettings.criticalityHelp')}</p>
            </div>
            {pointsText(['APP_CRITICAL'], isCritical) ?? pointsText(['APP_HIGH'], isHigh)}
          </div>
          <div className="mt-2.5">
            <span className="inline-flex items-center rounded-ctl border border-rule bg-chrome px-2.5 py-1 text-12 font-medium text-ink capitalize">
              {t(`appSettings.crit_${initial.business_criticality}`, { defaultValue: initial.business_criticality })}
            </span>
          </div>
        </div>

        {/* Exposure */}
        <div className="rounded-ctl border border-rule bg-surface p-4">
          <div className="flex items-start justify-between">
            <div>
              <h4 className="text-13 font-semibold text-ink">{t('appSettings.exposure')}</h4>
              <p className="mt-0.5 text-12 text-ink-2">{t('appSettings.internetHelp')}</p>
            </div>
            {pointsText(['INTERNET_FACING'], initial.internet_facing)}
          </div>
          <div className="mt-2.5">
            <span className="inline-flex items-center rounded-ctl border border-rule bg-chrome px-2.5 py-1 text-12 font-medium text-ink">
              {initial.internet_facing ? t('appSettings.internet') : t('appSettings.exposureInternal')}
            </span>
          </div>
        </div>

        {/* Data Classification */}
        <div className="rounded-ctl border border-rule bg-surface p-4">
          <div className="flex items-start justify-between">
            <div>
              <h4 className="text-13 font-semibold text-ink">{t('appSettings.data')}</h4>
              <p className="mt-0.5 text-12 text-ink-2">{t('appSettings.dataHelp')}</p>
            </div>
            {pointsText(['SENSITIVE_DATA'], isSensitiveData)}
          </div>
          <div className="mt-2.5 flex flex-wrap gap-2">
            {initial.data_classification && initial.data_classification.length > 0 ? (
              initial.data_classification.map((d) => (
                <span key={d} className="inline-flex items-center rounded-ctl border border-rule bg-chrome px-2.5 py-0.5 text-12 font-medium text-ink">
                  {t(`appSettings.data_${d}`, { defaultValue: d })}
                </span>
              ))
            ) : (
              <span className="text-12 text-ink-2">{t('appSettings.noneConfigured')}</span>
            )}
          </div>
        </div>

        {/* Compensating Controls */}
        <div className="rounded-ctl border border-rule bg-surface p-4">
          <div className="flex items-start justify-between">
            <div>
              <h4 className="text-13 font-semibold text-ink">{t('appSettings.controls')}</h4>
              <p className="mt-0.5 text-12 text-ink-2">{t('appSettings.controlsHelp')}</p>
            </div>
            {pointsText(['COMPENSATING_CONTROL'], hasControls)}
          </div>
          <div className="mt-2.5 flex flex-wrap gap-2">
            {initial.compensating_controls && initial.compensating_controls.length > 0 ? (
              initial.compensating_controls.map((c) => (
                <span key={c} className="inline-flex items-center rounded-ctl border border-rule bg-chrome px-2.5 py-0.5 text-12 font-medium text-ink">
                  {t(`appSettings.control_${c}`, { defaultValue: c })}
                </span>
              ))
            ) : (
              <span className="text-12 text-ink-2">{t('appSettings.noneConfigured')}</span>
            )}
          </div>
        </div>

        {/* Lifecycle */}
        <div className="rounded-ctl border border-rule bg-surface p-4">
          <h4 className="text-13 font-semibold text-ink">{t('appSettings.lifecycle')}</h4>
          <p className="mt-0.5 text-12 text-ink-2">{t('appSettings.lifecycleHelp')}</p>
          <div className="mt-2.5">
            <span className="inline-flex items-center rounded-ctl border border-rule bg-chrome px-2.5 py-1 text-12 font-medium text-ink capitalize">
              {t(`appSettings.life_${initial.lifecycle}`, { defaultValue: initial.lifecycle })}
            </span>
          </div>
        </div>

        {/* Dynamic Enterprise Attributes */}
        <div className="rounded-ctl border border-rule bg-surface p-4">
          <h4 className="text-13 font-semibold text-ink">{t('appSettings.customAttributes')}</h4>
          <p className="mt-0.5 text-12 text-ink-2">
            Arbitrary key-value properties defined in the Application spec evaluated dynamically by custom CEL risk policies using <code className="rounded bg-chrome px-1 text-12">attr(app, 'key', default)</code>.
          </p>
          <div className="mt-3">
            {attributeEntries.length > 0 ? (
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {attributeEntries.map(([k, v]) => (
                  <div key={k} className="flex items-center justify-between rounded-ctl border border-rule/70 bg-chrome/50 px-3 py-1.5 text-12">
                    <dt className="font-mono text-ink-2">{k}</dt>
                    <dd className="font-medium text-ink">
                      {typeof v === 'boolean' ? (v ? 'true' : 'false') : typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)}
                    </dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="m-0 text-12 text-ink-2">{t('appSettings.noCustomAttributes')}</p>
            )}
          </div>
        </div>
      </div>

      <div className="pt-2">
        <Link to="/about" className="text-13 text-accent hover:underline">
          {t('appSettings.seeRules')} →
        </Link>
      </div>
    </section>
  );
}
