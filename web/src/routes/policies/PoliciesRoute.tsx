import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getScoring, qk, toProblem } from '@/api';
import { ProblemMessage, Spinner } from '@/components';
import { BaseAndBands, FactorsTable, SlaMatrix } from '@/routes/about/ScoringTables';

/**
 * The policies in force: how a finding is scored and how long it may stay open, read from the server (the tenant's own policy, else the default
 * one). Read-only: a policy is changed through its resource (RiskPolicy, SLAPolicy, or the rampart-policies chart), and the page says so. It shows
 * no number of its own: an earlier version drew a hard-coded table that was not the policy in force (docs/34 item 18).
 */
export function PoliciesRoute() {
  const { t } = useTranslation();
  useEffect(() => {
    document.title = `${t('nav.policies')} - Rampart`;
  }, [t]);
  const q = useQuery({ queryKey: qk.scoring(), queryFn: ({ signal }) => getScoring(signal), staleTime: 60_000 });

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto px-6 py-5">
      <header className="max-w-[80ch]">
        <h1 className="display text-20 font-semibold">{t('nav.policies')}</h1>
        <p className="mt-1 text-13 text-ink-2">{t('policies.subtitle')}</p>
      </header>

      {q.isPending && <div className="flex h-40 items-center justify-center" aria-busy="true"><Spinner size={24} /></div>}
      {q.isError && <ProblemMessage problem={toProblem(q.error)} title={t('policies.loadFailed')} onRetry={() => void q.refetch()} className="mt-4" />}
      {q.data && (
        <div className="mt-5 max-w-3xl space-y-8">
          <section aria-labelledby="pol-which">
            <h2 id="pol-which" className="text-16 font-semibold">{t('policies.whichTitle')}</h2>
            <p className="mt-1 text-13 text-ink-2">{t(q.data.customised ? 'about.policyCustom' : 'about.policyBuiltin')}</p>
            <p className="mt-1 text-13 text-ink-2">{t('policies.changeVia')}</p>
          </section>

          <section aria-labelledby="pol-sla">
            <h2 id="pol-sla" className="text-16 font-semibold">{t('about.slaTitle')}</h2>
            <p className="mb-2 mt-1 text-13 text-ink-2">{t('about.slaBody')}</p>
            <SlaMatrix scoring={q.data} />
          </section>

          <section aria-labelledby="pol-risk">
            <h2 id="pol-risk" className="text-16 font-semibold">{t('policies.riskTitle')}</h2>
            <div className="mt-2"><BaseAndBands scoring={q.data} /></div>
            <div className="mt-4"><FactorsTable factors={q.data.risk.factors} /></div>
          </section>
        </div>
      )}
    </div>
  );
}
