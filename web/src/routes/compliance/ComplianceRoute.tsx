import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { getTaxonomyStatus, listApplications, listTaxonomies, qk, taxonomyCsvUrl, toProblem } from '@/api';
import { BandShape, EmptyState, ProblemMessage, Select, Skeleton, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { openText, worstBand } from '@/lib/apps';
import { absoluteDate } from '@/lib/format';

/** Frameworks and the status of each control: what is open against it, and whether a scan could show it (D52). */
export function ComplianceRoute() {
  const { t } = useTranslation();
  useEffect(() => {
    document.title = `${t('compliance.title')} - Rampart`;
  }, [t]);
  const frameworks = useQuery({ queryKey: qk.taxonomies(), queryFn: ({ signal }) => listTaxonomies(signal), staleTime: 300_000 });
  const apps = useQuery({ queryKey: qk.applications.list(), queryFn: ({ signal }) => listApplications(signal), staleTime: 60_000 });
  const [picked, setPicked] = useState('');
  const [app, setApp] = useState('');
  const fw = picked || frameworks.data?.[0]?.id || '';
  const status = useQuery({ queryKey: qk.taxonomyStatus(fw, app), queryFn: ({ signal }) => getTaxonomyStatus(fw, app, signal), enabled: !!fw, retry: false });
  const st = status.data;

  return (
    <div className="mx-auto max-w-[1000px] px-6 py-5">
      <h1 className="display text-28">{t('compliance.title')}</h1>
      {frameworks.data?.length === 0 && <EmptyState className="p-0 text-left" title={t('compliance.emptyTitle')} />}
      {fw && (
        <>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Select label={t('compliance.framework')} value={fw} onValueChange={setPicked} options={(frameworks.data ?? []).map((f) => ({ value: f.id, label: `${f.name} ${f.version}` }))} />
            <Select label={t('compliance.application')} value={app} onValueChange={setApp} options={[{ value: '', label: t('compliance.allApps') }, ...(apps.data ?? []).map((a) => ({ value: a.id, label: a.name }))]} />
            <a className="ms-auto text-13" href={taxonomyCsvUrl(fw, app || undefined)} download>{t('compliance.export')}</a>
          </div>
          {st && (
            <div className="mt-2 text-12 text-ink-2">
              {st.note && <p className="m-0">{st.note}</p>}
              <p className="m-0 mt-1">{t('compliance.meaning')}</p>
              <p className="m-0 mt-1">
                {t('compliance.evaluated', { date: absoluteDate(st.evaluated_at), days: st.window_days })}{' '}
                {t('compliance.source')}: <a href={st.source} rel="noreferrer noopener" target="_blank">{st.source}</a>
              </p>
            </div>
          )}
          <div className="mt-3">
            {status.isPending && (
              <div aria-busy="true" aria-label={t('common.loading')}>
                {Array.from({ length: 6 }, (_, i) => <div key={i} className="flex h-[46px] items-center border-b border-rule"><Skeleton className="h-3 flex-1" /></div>)}
              </div>
            )}
            {status.isError && <ProblemMessage problem={toProblem(status.error)} title={t('compliance.loadFailed')} onRetry={() => void status.refetch()} />}
            {st && (
              <Table aria-label={t('compliance.tableLabel')}>
                <colgroup><col className="w-[100px]" /><col /><col className="w-[190px]" /><col className="w-[260px]" /></colgroup>
                <THead>
                  <tr>
                    <Th>{t('compliance.colControl')}</Th>
                    <Th><span className="sr-only">{t('compliance.colControl')}</span></Th>
                    <Th>{t('compliance.colStatus')}</Th>
                    <Th>{t('compliance.colOpen')}</Th>
                  </tr>
                </THead>
                <TBody>
                  {st.status.map((c) => {
                    const worst = worstBand(c.bands);
                    return (
                      <Tr key={c.id} className="align-top">
                        <Td className="py-2 font-mono text-12">{c.id}</Td>
                        <Td className="!whitespace-normal py-2">{c.name}</Td>
                        <Td className="!whitespace-normal py-2">
                          <span className={c.status === 'open' ? 'font-semibold' : c.status === 'not_assessed' ? 'text-ink-2' : ''}>{t(`compliance.status.${c.status}`)}</span>
                          {c.evidence && c.evidence.length > 0 && <span className="block text-12 text-ink-2">{t('compliance.evidence', { tools: c.evidence.join(', ') })}</span>}
                        </Td>
                        <Td className="!whitespace-normal py-2">
                          {c.open > 0 ? (
                            <>
                              <span className="inline-flex items-center gap-1.5">
                                {worst && <BandShape band={worst} />}
                                {c.open}: {openText(c.bands, t)}
                              </span>
                              <Link to="/findings" search={{ q: c.query }} className="block text-12">{t('compliance.seeFindings')}</Link>
                            </>
                          ) : (
                            <span className="text-ink-2">{t('compliance.noneOpen')}</span>
                          )}
                        </Td>
                      </Tr>
                    );
                  })}
                </TBody>
              </Table>
            )}
          </div>
        </>
      )}
    </div>
  );
}
