import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { getApplicationCompliance, qk, toProblem } from '@/api';
import type { AppFramework } from '@/api/types';
import { useApp } from '@/app/session';
import { Button, EmptyState, FrameworkMark, ProblemMessage, Skeleton } from '@/components';
import { absoluteDate } from '@/lib/format';

export const PIN_KEY = 'rampart.pinnedFrameworks';

export function pinStorageKey(tenantId?: string, userId?: string): string {
  return tenantId && userId ? `rampart.pinnedFrameworks.${tenantId}.${userId}` : PIN_KEY;
}

/** How many frameworks show before the rest fold away: the pinned ones and then the most urgent. */
export const VISIBLE = 3;

/** The frameworks a person pinned to the top, kept in this browser (scoped per tenant and user). */
export function readPins(key: string = PIN_KEY): string[] {
  try {
    const raw = JSON.parse(localStorage.getItem(key) ?? '[]');
    return Array.isArray(raw) ? raw.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}
export function writePins(pins: string[], key: string = PIN_KEY) {
  try {
    localStorage.setItem(key, JSON.stringify(pins));
  } catch {
    /* a private window: the pin lasts until the page is closed */
  }
}

const URGENCY: Record<AppFramework['verdict'], number> = { gaps: 0, at_risk: 1, partial: 2, meets: 3 };

/**
 * The order of the list: pinned first (in the order they are listed), then by urgency: out of compliance, then at risk
 * with the nearest deadline first, then not fully read, then met; the name decides ties. The most urgent framework of an
 * application is the one a person has to act on, so it must not sit under ten that are fine.
 */
export function orderFrameworks(frameworks: AppFramework[], pins: string[]): AppFramework[] {
  const due = (f: AppFramework) => (f.earliest_due ? Date.parse(f.earliest_due) : Number.MAX_SAFE_INTEGER);
  return [...frameworks].sort((a, b) => {
    const pa = pins.indexOf(a.id);
    const pb = pins.indexOf(b.id);
    if ((pa >= 0) !== (pb >= 0)) return pa >= 0 ? -1 : 1;
    if (pa >= 0 && pb >= 0) return pa - pb;
    return URGENCY[a.verdict] - URGENCY[b.verdict] || due(a) - due(b) || a.name.localeCompare(b.name);
  });
}

/**
 * What this application meets today: each framework that reads it, with a line that says why and a bar with one
 * stretch per kind of control. A control is out of compliance when a finding against it is past its deadline, and at
 * risk while findings are only open (PCI DSS 6.3.3 gives a month for a critical patch; Vanta and Drata count an item
 * overdue past its SLA), so the line says which date to meet. Pin the two or three that matter; the rest fold away.
 */
export function ComplianceSummary({ appId }: { appId: string }) {
  const { t } = useTranslation();
  let key = PIN_KEY;
  try {
    const appCtx = useApp();
    if (appCtx?.session?.tenant?.id && appCtx?.session?.user?.id) {
      key = pinStorageKey(appCtx.session.tenant.id, appCtx.session.user.id);
    }
  } catch {
    /* fallback if outside AppCtx */
  }
  const [pins, setPins] = useState(() => readPins(key));
  useEffect(() => {
    setPins(readPins(key));
  }, [key]);
  const [all, setAll] = useState(false);
  const q = useQuery({ queryKey: qk.applications.compliance(appId), queryFn: ({ signal }) => getApplicationCompliance(appId, signal), retry: false });
  const ordered = useMemo(() => orderFrameworks(q.data?.frameworks ?? [], pins), [q.data, pins]);
  const shown = all ? ordered : ordered.slice(0, VISIBLE);
  const toggle = (id: string) => {
    const next = pins.includes(id) ? pins.filter((p) => p !== id) : [...pins, id];
    setPins(next);
    writePins(next, key);
  };
  return (
    <section className="mt-6" aria-labelledby="app-compliance">
      <h2 id="app-compliance" className="mb-1 text-14 font-semibold">{t('apps.complianceTitle')}</h2>
      <p className="m-0 mb-2 text-12 text-ink-2">{t('apps.complianceHelp')}</p>
      {q.isPending && <Skeleton className="h-16 w-full" />}
      {q.isError && <ProblemMessage problem={toProblem(q.error)} title={t('apps.complianceFailed')} onRetry={() => void q.refetch()} />}
      {q.data && q.data.frameworks.length === 0 && <EmptyState className="p-0 text-left" title={t('apps.complianceEmpty')} />}
      {q.data && ordered.length > 0 && (
        <>
          <ul className="m-0 list-none border-t border-rule p-0">
            {shown.map((f) => <Row key={f.id} f={f} appId={appId} pinned={pins.includes(f.id)} onPin={() => toggle(f.id)} />)}
          </ul>
          {ordered.length > VISIBLE && (
            <Button variant="ghost" className="mt-1" aria-expanded={all} onClick={() => setAll(!all)}>
              {all ? t('apps.complianceShowFewer') : t('apps.complianceShowMore', { count: ordered.length - VISIBLE })}
            </Button>
          )}
        </>
      )}
      {q.data && q.data.not_in_scope.length > 0 && (
        <p className="m-0 mt-2 text-12 text-ink-2">{t('apps.complianceNotInScope', { names: q.data.not_in_scope.join(', ') })}</p>
      )}
    </section>
  );
}

function Row({ f, appId, pinned, onPin }: { f: AppFramework; appId: string; pinned: boolean; onPin: () => void }) {
  const { t } = useTranslation();
  const date = f.earliest_due ? absoluteDate(f.earliest_due) : '';
  const line =
    f.verdict === 'meets'
      ? t('apps.verdictMeets', { count: f.controls })
      : f.verdict === 'gaps'
        ? f.overdue_findings === 0
          ? t('apps.verdictGapsOther', { count: f.open, open: f.open, total: f.controls }) // a manual control attested as not met, or findings with no deadline
          : t('apps.verdictGaps', { count: f.open, open: f.open, total: f.controls, overdue: f.overdue_findings, findings: f.open_findings })
        : f.verdict === 'at_risk'
          ? date
            ? t('apps.verdictAtRisk', { count: f.at_risk, atRisk: f.at_risk, total: f.controls, date })
            : t('apps.verdictAtRiskNoDate', { count: f.at_risk, atRisk: f.at_risk, total: f.controls })
          : t('apps.verdictPartial', { clear: f.clear, total: f.controls, unread: f.not_assessed });
  const counts = t('apps.stripLabel', { clear: f.clear, atRisk: f.at_risk, open: f.open, unread: f.not_assessed });
  const total = Math.max(f.controls, 1);
  const pct = (n: number) => `${(n / total) * 100}%`;
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
        {f.clear > 0 && <span style={{ width: pct(f.clear), background: 'var(--resolved)' }} />}
        {f.at_risk > 0 && <span style={{ width: pct(f.at_risk), background: 'var(--seg-context)' }} />}
        {f.open > 0 && <span style={{ width: pct(f.open), background: 'var(--seg-threat)' }} />}
      </div>
      <button
        type="button"
        aria-pressed={pinned}
        aria-label={pinned ? t('apps.complianceUnpin', { name: f.name }) : t('apps.compliancePin', { name: f.name })}
        title={pinned ? t('apps.complianceUnpin', { name: f.name }) : t('apps.compliancePin', { name: f.name })}
        onClick={onPin}
        className="inline-flex size-8 shrink-0 items-center justify-center rounded-ctl border border-transparent text-16 leading-none text-ink-2 hover:border-rule hover:text-ink aria-pressed:text-accent"
      >
        <span aria-hidden="true">{pinned ? '★' : '☆'}</span>
      </button>
    </li>
  );
}
