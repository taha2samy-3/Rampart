import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { listParsers, qk, toProblem } from '@/api';
import type { ParserDescriptor } from '@/api/types';
import { EmptyState, ProblemMessage, SearchField, Spinner, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { absoluteDateTime } from '@/lib/format';
import { cn } from '@/lib/cn';
import { StatusMark, type Health } from './StatusMark';

type Family = 'report' | 'sbom';

const healthOf = (p: ParserDescriptor): Health => (p.status === 'refused' || p.status === 'module_missing' ? 'problem' : 'ok');

/** What an SBOM parser reads: its format, from its id (builtin:sbom-cyclonedx is CycloneDX's). A report parser says its category. */
const readsOf = (p: ParserDescriptor, family: Family): string =>
  family === 'sbom' ? p.id.replace(/^builtin:sbom-/, '') : p.category ?? '';

/**
 * The parsers installed on the server, of one family (report parsers or SBOM parsers): what each is, whether it is installed correctly (ready, its
 * module missing, or its resource refused), and how it last worked. What is shown is what the server holds; nothing is listed that is not installed.
 */
export function ParserList({ family }: { family: Family }) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const q = useQuery({ queryKey: qk.parsers.list(), queryFn: ({ signal }) => listParsers(signal) });

  // A server that does not say the family (an older one) reads as report parsers, except the SBOM readers by their id.
  const all = useMemo(
    () => (q.data ?? []).filter((p) => (p.family ?? (p.id.startsWith('builtin:sbom-') ? 'sbom' : 'report')) === family),
    [q.data, family],
  );
  const shown = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return all.filter((p) => !needle || [p.name, p.id, p.description, readsOf(p, family)].some((v) => (v ?? '').toLowerCase().includes(needle)));
  }, [all, search, family]);
  const picked = all.find((p) => p.id === selected) ?? null;
  const problems = all.filter((p) => healthOf(p) === 'problem').length;
  const label = t(family === 'sbom' ? 'parsers.tableSbom' : 'parsers.tableReport');

  if (q.isPending) return <div className="flex h-48 items-center justify-center" aria-busy="true"><Spinner size={24} /></div>;
  if (q.isError) return <ProblemMessage problem={toProblem(q.error)} title={t('parsers.loadFailed')} onRetry={() => void q.refetch()} className="mt-4" />;

  return (
    <div>
      <p className="max-w-[80ch] text-13 text-ink-2">{t(family === 'sbom' ? 'parsers.sbomIntro' : 'parsers.reportIntro')}</p>
      <p className="mt-1 max-w-[80ch] text-13 text-ink-2">{t('parsers.addHelp')}</p>
      {all.length > 0 && <p className="mt-3 text-13 text-ink-2">{t('parsers.summary', { count: all.length, ready: all.length - problems, problems })}</p>}

      <div className="mt-3 flex flex-wrap items-center gap-3 border-y border-rule py-2">
        <SearchField className="w-64" aria-label={t('parsers.searchLabel')} placeholder={t('parsers.searchPlaceholder')} value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>

      <div className="grid shrink-0 grid-cols-1 border-b border-rule lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 overflow-x-auto">
          {all.length === 0 ? (
            <EmptyState title={t(family === 'sbom' ? 'parsers.emptySbom' : 'parsers.emptyReport')}>{t('parsers.emptyHint')}</EmptyState>
          ) : shown.length === 0 ? (
            <EmptyState title={t('parsers.noMatch')}>{t('analyzers.noMatchHint')}</EmptyState>
          ) : (
            <Table aria-label={label} className="md:min-w-[44rem]">
              <THead>
                <tr>
                  <Th className="md:w-[30%]">{t('parsers.colParser')}</Th>
                  <Th className="hidden md:table-cell md:w-[16%]">{t('parsers.colType')}</Th>
                  <Th className="hidden md:table-cell md:w-[14%]">{family === 'sbom' ? t('parsers.sbomFormat') : t('parsers.colWhat')}</Th>
                  <Th className="md:w-[16%]">{t('parsers.colStatus')}</Th>
                  <Th className="md:w-[24%]">{t('parsers.colLastRun')}</Th>
                </tr>
              </THead>
              <TBody>
                {shown.map((p) => (
                  <ParserRow key={p.id} p={p} family={family} selected={p.id === selected} onSelect={() => setSelected(p.id)} />
                ))}
              </TBody>
            </Table>
          )}
        </div>
        <aside aria-label={t('parsers.inspectorLabel')} className="border-t border-rule lg:border-s lg:border-t-0">
          <ParserInspector p={picked} />
        </aside>
      </div>
    </div>
  );
}

function ParserRow({ p, family, selected, onSelect }: { p: ParserDescriptor; family: Family; selected: boolean; onSelect: () => void }) {
  const { t } = useTranslation();
  const bad = healthOf(p) === 'problem';
  const last = p.last_run;
  return (
    <Tr selected={selected} className="h-12 align-middle">
      <Td className="whitespace-normal">
        <button type="button" onClick={onSelect} aria-pressed={selected} className="block max-w-full text-start hover:text-accent">
          <span className="block break-words font-medium md:truncate">{p.name}</span>
          <span className="block break-all font-mono text-12 text-ink-2 md:truncate">{p.id}</span>
        </button>
      </Td>
      <Td className="hidden whitespace-normal md:table-cell">{t(`parsers.runtime_${p.runtime || 'unknown'}`)}</Td>
      <Td className="hidden whitespace-normal font-mono text-12 md:table-cell">{readsOf(p, family)}</Td>
      <Td className="whitespace-normal">
        <span className={cn('inline-flex items-center gap-1.5', bad && 'text-critical')}>
          <StatusMark health={healthOf(p)} />
          {t(`parsers.status_${p.status ?? 'ready'}`)}
        </span>
      </Td>
      <Td className="whitespace-normal">
        {last ? (
          <span className="inline-flex items-start gap-1.5">
            <StatusMark health={last.status === 'failed' ? 'problem' : 'ok'} className="mt-0.5" />
            <span>
              <span className={cn('block', last.status === 'failed' && 'text-critical')}>{t(`ingestion.status.${last.status}`, { defaultValue: last.status })}</span>
              <span className="block font-mono text-12 text-ink-2">{absoluteDateTime(last.at)}</span>
            </span>
          </span>
        ) : (
          <span className="inline-flex items-center gap-1.5 text-ink-2"><StatusMark health="idle" />{t('parsers.neverUsed')}</span>
        )}
      </Td>
    </Tr>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <dt className="w-32 shrink-0 text-ink-2">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

function ParserInspector({ p }: { p: ParserDescriptor | null }) {
  const { t } = useTranslation();
  if (!p) return <p className="p-4 text-13 text-ink-2">{t('parsers.inspectorEmpty')}</p>;
  const status = p.status ?? 'ready';
  const problem = status === 'refused' ? p.error : status === 'module_missing' ? p.unavailable : undefined;
  return (
    <div className="space-y-5 p-4 text-13">
      <header>
        <h3 className="break-words text-14 font-semibold">{p.name}</h3>
        <p className="mt-0.5 break-all font-mono text-12 text-ink-2">{p.id}</p>
        {p.description && <p className="mt-1 text-ink-2">{p.description}</p>}
      </header>

      <section aria-labelledby="pi-status">
        <h4 id="pi-status" className="font-semibold">{t('parsers.colStatus')}</h4>
        <p className={cn('mt-1 inline-flex items-center gap-1.5', healthOf(p) === 'problem' && 'text-critical')}>
          <StatusMark health={healthOf(p)} />
          {t(`parsers.status_${status}`)}
        </p>
        {problem && (
          <>
            <p className="mt-2 font-semibold">{t('parsers.problem')}</p>
            <p className="mt-0.5 break-words text-critical">{problem}</p>
            <p className="mt-1 text-ink-2">{t(status === 'refused' ? 'parsers.refusedHelp' : 'parsers.moduleMissingHelp')}</p>
          </>
        )}
      </section>

      <dl className="space-y-1">
        <Row label={t('parsers.colType')}>{t(`parsers.runtime_${p.runtime || 'unknown'}`)}</Row>
        {p.module && <Row label={t('parsers.module')}><span className="font-mono text-12">{p.module}</span></Row>}
        {p.version && <Row label={t('parsers.version')}>{p.version}</Row>}
        {p.origin && <Row label={t('parsers.from')}>{t(`parsers.origin_${p.origin}`)}</Row>}
      </dl>

      <section aria-labelledby="pi-last">
        <h4 id="pi-last" className="font-semibold">{t('parsers.lastRun')}</h4>
        {p.last_run ? (
          <>
            <p className={cn('mt-1', p.last_run.status === 'failed' && 'text-critical')}>
              {t(`ingestion.status.${p.last_run.status}`, { defaultValue: p.last_run.status })}, <span className="font-mono text-12">{absoluteDateTime(p.last_run.at)}</span>
            </p>
            {p.last_run.error && <p className="mt-0.5 break-words font-mono text-12 text-critical">{p.last_run.error}</p>}
            <p className="mt-1 text-ink-2">
              {t('parsers.lastSuccess')}: {p.last_success ? <span className="font-mono text-12">{absoluteDateTime(p.last_success)}</span> : t('parsers.never')}
            </p>
            <p className="mt-1">
              <Link to="/ingestion" search={{ sel: p.last_run.id }} className="text-accent hover:underline">{t('parsers.openRun')}</Link>
            </p>
          </>
        ) : (
          <p className="mt-1 text-ink-2">{t('parsers.neverUsed')}</p>
        )}
      </section>
    </div>
  );
}
