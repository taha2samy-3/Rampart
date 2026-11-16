import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { getApplicationCompliance, qk, toProblem } from '@/api';
import type { AppFramework } from '@/api/types';
import { EmptyState, FrameworkMark, ProblemMessage, Skeleton } from '@/components';

/**
 * What this application meets today: each framework that reads it, with a line that says why and a bar with one
 * stretch per kind of control. Read from the open findings and the scans of the evidence window, the same reading as
 * the Compliance page, narrowed to this application.
 */
export function ComplianceSummary({ appId }: { appId: string }) {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: qk.applications.compliance(appId), queryFn: ({ signal }) => getApplicationCompliance(appId, signal), retry: false });
  return (
    <section className="mt-6" aria-labelledby="app-compliance">
      <h2 id="app-compliance" className="mb-1 text-14 font-semibold">{t('apps.complianceTitle')}</h2>
      <p className="m-0 mb-2 text-12 text-ink-2">{t('apps.complianceHelp')}</p>
      {q.isPending && <Skeleton className="h-16 w-full" />}
      {q.isError && <ProblemMessage problem={toProblem(q.error)} title={t('apps.complianceFailed')} onRetry={() => void q.refetch()} />}
      {q.data && q.data.frameworks.length === 0 && <EmptyState className="p-0 text-left" title={t('apps.complianceEmpty')} />}
      {q.data && q.data.frameworks.length > 0 && (
        <ul className="m-0 list-none border-t border-rule p-0">
          {q.data.frameworks.map((f) => <Row key={f.id} f={f} appId={appId} />)}
        </ul>
      )}
      {q.data && q.data.not_in_scope.length > 0 && (
        <p className="m-0 mt-2 text-12 text-ink-2">{t('apps.complianceNotInScope', { names: q.data.not_in_scope.join(', ') })}</p>
      )}
    </section>
  );
}

function Row({ f, appId }: { f: AppFramework; appId: string }) {
  const { t } = useTranslation();
  const line =
    f.verdict === 'meets'
      ? t('apps.verdictMeets', { count: f.controls })
      : f.verdict === 'gaps'
        ? t('apps.verdictGaps', { count: f.open, open: f.open, total: f.controls, findings: f.open_findings })
        : t('apps.verdictPartial', { clear: f.clear, total: f.controls, unread: f.not_assessed });
  const counts = t('apps.stripLabel', { clear: f.clear, open: f.open, unread: f.not_assessed });
  const total = Math.max(f.controls, 1);
  return (
    <li className="flex items-center gap-3 border-b border-rule py-2.5">
      <FrameworkMark id={f.id} name={f.name} origin={f.origin} logo={f.logo} size={28} />
      <div className="min-w-0 flex-1">
        <Link to="/compliance" search={{ framework: f.id, application: appId }} className="text-13 font-medium text-ink no-underline hover:underline">
          {f.name} <span className="font-normal text-ink-2">{f.version}</span>
        </Link>
        <p className="m-0 text-12 text-ink-2">{line}</p>
      </div>
      <div role="img" aria-label={counts} className="flex h-2 w-44 shrink-0 overflow-hidden border border-rule">
        {f.clear > 0 && <span style={{ width: `${(f.clear / total) * 100}%`, background: 'var(--resolved)' }} />}
        {f.open > 0 && <span style={{ width: `${(f.open / total) * 100}%`, background: 'var(--seg-threat)' }} />}
      </div>
    </li>
  );
}
