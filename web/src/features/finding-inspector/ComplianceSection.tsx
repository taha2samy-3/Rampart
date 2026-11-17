import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { getFindingControls, qk, toProblem } from '@/api';
import type { Finding, FindingControl } from '@/api/types';
import { ProblemMessage } from '@/components';
import { absoluteDate, relativeDays } from '@/lib/format';

const DAY = 86_400_000;

/**
 * The compliance controls this finding counts against, and when it falls due. A finding is only a problem for a framework
 * once it is past its deadline, so the page says which date to meet and which control goes out of compliance if it is
 * missed. Nothing is shown for a finding that counts against no control.
 */
export function ComplianceSection({ finding }: { finding: Finding }) {
  const { t } = useTranslation();
  const [now] = useState(() => Date.now()); // the clock the page was opened at
  const open = ['open', 'under_investigation', 'affected'].includes(finding.state);
  const q = useQuery({ queryKey: [...qk.findings.controls(finding.id), finding.version], queryFn: ({ signal }) => getFindingControls(finding.id, signal), enabled: open, retry: false });
  // Nothing while it loads: a heading with nothing under it, which then disappears, is worse than no heading.
  if (!open || q.isPending || (q.isSuccess && q.data.length === 0)) return null;
  const rows = q.data ?? [];
  const first = rows[0];
  const overdue = rows.some((r) => r.overdue);
  return (
    <section className="mt-5" aria-labelledby="finding-controls">
      <h3 id="finding-controls" className="mb-1 text-13 font-semibold">{t('findingControls.title')}</h3>
      {q.isError && <ProblemMessage problem={toProblem(q.error)} title={t('findingControls.loadFailed')} onRetry={() => void q.refetch()} />}
      {first && (
        <>
          <p className="m-0 mb-1 text-12 text-ink-2">{t('findingControls.help')}</p>
          <p className={overdue ? 'm-0 mb-2 text-13 font-semibold' : 'm-0 mb-2 text-13'}>{deadline(first, now, t)}</p>
          <ul className="m-0 list-none p-0 text-13">
            {rows.map((r) => (
              <li key={`${r.framework_id}-${r.control_id}`} className="border-b border-rule py-1.5">
                <Link to="/compliance" search={{ framework: r.framework_id, application: finding.application_id }} className="font-medium no-underline hover:underline">
                  {r.framework} <span className="font-normal text-ink-2">{r.version}</span>
                </Link>
                <span className="block text-12 text-ink-2">{r.control_id}: {r.control}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function deadline(c: FindingControl, now: number, t: TFunction): string {
  if (!c.due) return t('findingControls.noDeadline');
  if (c.overdue) {
    const days = Math.floor((now - Date.parse(c.due)) / DAY); // whole days past it
    if (days < 1) return t('findingControls.overdueToday');
    return t('findingControls.overdue', { days: t('findingControls.days', { count: days }) });
  }
  return `${t('findingControls.dueIn', { when: relativeDays(c.due, now) })} (${absoluteDate(c.due)}).`;
}
