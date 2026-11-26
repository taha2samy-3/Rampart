import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { listApplications, qk, toProblem } from '@/api';
import type { AppSummary } from '@/api/types';
import { BandMixBar, BandShape, BAND_TEXT_CLASS, EmptyState, ProblemMessage, ScoreBar, Skeleton, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { openText, worstBand } from '@/lib/apps';
import { absoluteDate, shortAge } from '@/lib/format';

/** Applications, the riskiest first (docs/13). A row opens the application page. */
export function ApplicationsRoute() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  useEffect(() => {
    document.title = `${t('apps.title')} - Rampart`;
  }, [t]);
  const q = useQuery({ queryKey: qk.applications.list(), queryFn: ({ signal }) => listApplications(signal) });
  const rows = q.data ?? [];
  // one scale for every row, so the bars compare across applications (D93)
  const maxOpen = Math.max(1, ...rows.map((a) => a.open.critical + a.open.high + a.open.medium + a.open.low));

  let body: React.ReactNode;
  if (q.isPending) {
    body = (
      <div aria-busy="true" aria-label={t('common.loading')}>
        {Array.from({ length: 6 }, (_, i) => (
          <div key={i} className="flex h-[46px] items-center gap-3 border-b border-rule px-3">
            <Skeleton className="h-3 flex-1" />
          </div>
        ))}
      </div>
    );
  } else if (q.isError) {
    body = <div className="p-4"><ProblemMessage problem={toProblem(q.error)} title={t('apps.loadFailed')} onRetry={() => void q.refetch()} /></div>;
  } else if (rows.length === 0) {
    body = <EmptyState title={t('apps.emptyTitle')}>{t('apps.emptyBody')}</EmptyState>;
  } else {
    body = (
      <Table role="grid" aria-label={t('apps.tableLabel')} aria-rowcount={rows.length}>
        <colgroup>
          <col />
          <col className="w-[240px] @max-[700px]/list:hidden" />
          <col className="w-[170px]" />
          <col className="w-[110px] @max-[520px]/list:hidden" />
          <col className="w-[116px]" />
        </colgroup>
        <THead className="sticky top-0 z-10">
          <tr role="row">
            <Th>{t('apps.colApp')}</Th>
            <Th>{t('apps.colOpen')}</Th>
            <Th>{t('apps.colRisk')}</Th>
            <Th align="end">{t('apps.colBreached')}</Th>
            <Th align="end">{t('apps.colScan')}</Th>
          </tr>
        </THead>
        <TBody>
          {rows.map((a, i) => (
            <AppRow key={a.id} app={a} index={i} maxOpen={maxOpen} onOpen={() => void navigate({ to: '/applications/$id', params: { id: a.id } })} />
          ))}
        </TBody>
      </Table>
    );
  }
  return (
    <div className="@container/list flex h-full min-h-0 flex-col">
      <h1 className="display border-b border-rule px-3 py-2 text-16">{t('apps.title')}</h1>
      <div className="min-h-0 flex-1 overflow-auto">{body}</div>
    </div>
  );
}

function AppRow({ app, index, maxOpen, onOpen }: { app: AppSummary; index: number; maxOpen: number; onOpen: () => void }) {
  const { t } = useTranslation();
  const text = openText(app.open, t);
  return (
    <Tr
      aria-rowindex={index + 2}
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === 'Enter') onOpen();
      }}
      className="h-[46px] cursor-pointer align-middle focus-visible:outline-offset-[-2px]"
    >
      <Td className="py-0">
        <Link to="/applications/$id" params={{ id: app.id }} className="block truncate font-medium text-ink no-underline hover:underline" onClick={(e) => e.stopPropagation()}>
          {app.name}
        </Link>
        <span className="block truncate text-[11.5px] leading-4 text-ink-2">
          {t('apps.criticality', { level: app.business_criticality })}
          {app.internet_facing ? `, ${t('apps.internetFacing')}` : ''}
        </span>
      </Td>
      <Td className="py-0 @max-[700px]/list:hidden">
        <BandMixBar open={app.open} max={maxOpen} label={text || t('apps.noOpen')} />
        <span className={`mt-1 block truncate text-[11.5px] leading-4 ${text ? '' : 'text-ink-2'}`}>{text || t('apps.noOpen')}</span>
      </Td>
      <Td>
        {(() => {
          // The band is the server's: the worst band among the open findings (docs/51 step 3.1).
          const b = worstBand(app.open);
          return (
            <span className="flex items-center gap-2">
              {b ? <BandShape band={b} size={11} /> : <span aria-hidden="true" className="inline-block w-[11px]" />}
              <span className={`w-9 text-end text-14 font-semibold tnum ${b ? BAND_TEXT_CLASS[b] : 'text-ink-2'}`}>{app.risk_score}</span>
              <ScoreBar breakdown={null} score={app.risk_score} band={b} />
            </span>
          );
        })()}
      </Td>
      <Td align="end" className={app.sla_breached > 0 ? 'font-semibold' : 'text-ink-2'}>{app.sla_breached}</Td>
      <Td align="end" className="text-ink-2" title={app.last_scan ? absoluteDate(app.last_scan) : undefined}>
        {app.last_scan ? shortAge(app.last_scan) : t('apps.never')}
      </Td>
    </Tr>
  );
}
