import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getScoring, qk, toProblem } from '@/api';
import { ProblemMessage, Spinner } from '@/components';
import { BaseAndBands, FactorsTable, SlaMatrix } from './ScoringTables';

/** The version of the program, and how a score and a deadline are worked out, from the policy in force. */
export function AboutRoute() {
  const { t } = useTranslation();
  useEffect(() => { document.title = `${t('nav.about')} · Rampart`; }, [t]);
  const q = useQuery({ queryKey: qk.scoring(), queryFn: ({ signal }) => getScoring(signal), staleTime: 60_000 });

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto px-6 py-5">
      <header className="max-w-[80ch]">
        <h1 className="display text-20 font-semibold">{t('about.title')}</h1>
        {q.data && <p className="mt-1 text-13 text-ink-2">{t('about.version', { version: q.data.version })}</p>}
      </header>

      {q.isPending && <div className="flex h-40 items-center justify-center"><Spinner size={24} /></div>}
      {q.isError && <ProblemMessage problem={toProblem(q.error)} title={t('about.loadFailed')} onRetry={() => void q.refetch()} className="mt-4" />}
      {q.data && (
        <div className="mt-5 max-w-3xl space-y-8">
          <section aria-labelledby="how">
            <h2 id="how" className="text-16 font-semibold">{t('about.howTitle')}</h2>
            <p className="mt-1 text-13 text-ink-2">{t('about.howBody')}</p>
            <p className="mt-1 text-13 text-ink-2">{t(q.data.customised ? 'about.policyCustom' : 'about.policyBuiltin')}</p>
            <div className="mt-4"><BaseAndBands scoring={q.data} /></div>
          </section>

          <section aria-labelledby="factors">
            <h2 id="factors" className="text-16 font-semibold">{t('about.factorsTitle')}</h2>
            <p className="mb-2 mt-1 text-13 text-ink-2">{t('about.factorsBody')}</p>
            <FactorsTable factors={q.data.risk.factors} />
          </section>

          <section aria-labelledby="sla">
            <h2 id="sla" className="text-16 font-semibold">{t('about.slaTitle')}</h2>
            <p className="mb-2 mt-1 text-13 text-ink-2">{t('about.slaBody')}</p>
            <SlaMatrix scoring={q.data} />
          </section>

          <section aria-labelledby="ctx">
            <h2 id="ctx" className="text-16 font-semibold">{t('about.contextTitle')}</h2>
            <p className="mb-1 mt-1 text-13 text-ink-2">{t('about.contextBody')}</p>
            <ul className="m-0 list-disc ps-5 text-13">
              <li>{t('about.ctxCriticality')}</li>
              <li>{t('about.ctxInternet')}</li>
              <li>{t('about.ctxData')}</li>
              <li>{t('about.ctxControls')}</li>
              <li>{t('about.ctxProduction')}</li>
            </ul>
          </section>
        </div>
      )}
    </div>
  );
}
