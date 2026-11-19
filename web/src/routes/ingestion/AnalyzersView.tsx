import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { analyzeWithAnalyzer, listAnalyzers, qk, testAnalyzer, toProblem } from '@/api';
import type { AnalyzerItem, AnalyzerTestResult } from '@/api/types';
import { EmptyState, ProblemMessage, SearchField, Select, Spinner, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { IconWarning } from '@/components/icons';
import { useAccess } from '@/app/useAccess';
import { absoluteDateTime } from '@/lib/format';
import { cn } from '@/lib/cn';
import { AnalyzerInspector, eventPhrase } from './AnalyzerInspector';

type Filter = 'all' | 'external' | 'sbom';

/** One analyzer is told apart from another by its kind, scope, namespace and name. */
const keyOf = (a: Pick<AnalyzerItem, 'kind' | 'scope' | 'namespace' | 'name'>) => [a.kind, a.scope, a.namespace ?? '', a.name].join('/');

/** The address a service is called at, or the engine the matcher runs: the one thing that says where the work happens. */
const whereOf = (a: AnalyzerItem) => (a.kind === 'external' ? a.target ?? '' : a.engine ?? '');

function statusOf(a: AnalyzerItem): 'refused' | 'off' | 'ready' {
  if (!a.ready) return 'refused';
  return a.enabled ? 'ready' : 'off';
}

/**
 * The analyzers, by kind: the services Rampart calls and the matcher inside it. Each one shows how it is set up and what
 * the last test said, and an administrator can test it. The list is what the server holds, so a resource the server
 * refused is listed with the reason.
 */
export function AnalyzersView() {
  const { t } = useTranslation();
  const { can } = useAccess();
  const mayManage = can(undefined, 'admin'); // a test calls out from the server: the API needs an administrator
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const [selected, setSelected] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, AnalyzerTestResult>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [queued, setQueued] = useState<Record<string, number>>({});
  const [analyzeErrors, setAnalyzeErrors] = useState<Record<string, string>>({});

  const q = useQuery({ queryKey: qk.analyzers.list(), queryFn: ({ signal }) => listAnalyzers(signal) });
  const items = useMemo(() => q.data ?? [], [q.data]);

  const test = useMutation({
    mutationFn: (a: AnalyzerItem) => testAnalyzer(a),
    onSuccess: (res, a) => {
      setResults((cur) => ({ ...cur, [keyOf(a)]: res }));
      setErrors((cur) => Object.fromEntries(Object.entries(cur).filter(([k]) => k !== keyOf(a))));
    },
    onError: (e, a) => {
      const p = toProblem(e);
      setErrors((cur) => ({ ...cur, [keyOf(a)]: p.detail ?? p.title ?? '' }));
    },
    // The test wrote an event: the list's last result and the history both read it again.
    onSettled: () => void queryClient.invalidateQueries({ queryKey: qk.analyzers.all() }),
  });
  const testingKey = test.isPending && test.variables ? keyOf(test.variables) : null;

  const analyze = useMutation({
    mutationFn: (a: AnalyzerItem) => analyzeWithAnalyzer(a),
    onSuccess: (res, a) => {
      setQueued((cur) => ({ ...cur, [keyOf(a)]: res.queued }));
      setAnalyzeErrors((cur) => Object.fromEntries(Object.entries(cur).filter(([k]) => k !== keyOf(a))));
    },
    onError: (e, a) => {
      const p = toProblem(e);
      setAnalyzeErrors((cur) => ({ ...cur, [keyOf(a)]: p.detail ?? p.title ?? '' }));
    },
    // Each queued analysis writes an event when it ends: read the history again.
    onSettled: () => void queryClient.invalidateQueries({ queryKey: qk.analyzers.all() }),
  });
  const analyzingKey = analyze.isPending && analyze.variables ? keyOf(analyze.variables) : null;

  const shown = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return items.filter(
      (a) => (filter === 'all' || a.kind === filter) && (!needle || [a.name, a.namespace ?? '', whereOf(a)].some((v) => v.toLowerCase().includes(needle))),
    );
  }, [items, search, filter]);
  const selectedItem = items.find((a) => keyOf(a) === selected) ?? null;

  const external = items.filter((a) => a.kind === 'external').length;
  const failed = items.filter((a) => a.last_event?.event === 'test' && a.last_event.outcome === 'failed').length;

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto p-4 tablet:p-6">
      <header className="max-w-[80ch]">
        <h2 className="display text-16 font-semibold">{t('analyzers.title')}</h2>
        <p className="mt-1 text-13 text-ink-2">{t('analyzers.subtitle')}</p>
        <p role="note" className="mt-2 text-13 text-ink-2">{t('analyzers.analysisNote')}</p>
      </header>

      {q.isError ? (
        <ProblemMessage problem={toProblem(q.error)} title={t('analyzers.loadFailed')} onRetry={() => void q.refetch()} className="mt-4" />
      ) : q.isPending ? (
        <div className="flex h-48 items-center justify-center" aria-busy="true" aria-label={t('common.loading')}><Spinner size={24} /></div>
      ) : (
        <>
          <p className="mt-4 max-w-[80ch] text-13 text-ink-2">
            {t('analyzers.summary', { count: items.length, external, sbom: items.length - external, failed })}
          </p>

          <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2 border-y border-rule py-2">
            <SearchField className="w-64" aria-label={t('analyzers.searchLabel')} placeholder={t('analyzers.searchPlaceholder')} value={search} onChange={(e) => setSearch(e.target.value)} />
            <Select
              label={t('analyzers.filterLabel')}
              value={filter}
              onValueChange={(v) => setFilter(v as Filter)}
              options={[
                { value: 'all', label: t('analyzers.filterAll') },
                { value: 'external', label: t('analyzers.filterExternal') },
                { value: 'sbom', label: t('analyzers.filterSbom') },
              ]}
            />
          </div>

          {/* shrink-0: in a column that scrolls, a grid that may shrink squeezes its first row to nothing (a scroll container has no minimum height)
                and the inspector then covers the table, on a phone. */}
          <div className="grid shrink-0 grid-cols-1 border-b border-rule lg:grid-cols-[minmax(0,1fr)_22rem]">
            <div className="min-w-0 overflow-x-auto">
              {items.length === 0 ? (
                <EmptyState title={t('analyzers.noneConfigured')}>{t('analyzers.noneConfiguredHint')}</EmptyState>
              ) : shown.length === 0 ? (
                <EmptyState title={t('analyzers.noMatch')}>{t('analyzers.noMatchHint')}</EmptyState>
              ) : (
                <Table aria-label={t('analyzers.tableLabel')} className="md:min-w-[44rem]">
                  <THead>
                    <tr>
                      <Th className="md:w-[28%]">{t('analyzers.colAnalyzer')}</Th>
                      <Th className="hidden md:table-cell md:w-[16%]">{t('analyzers.colKind')}</Th>
                      <Th className="hidden md:table-cell md:w-[22%]">{t('analyzers.colWhere')}</Th>
                      <Th className="md:w-[12%]">{t('analyzers.colStatus')}</Th>
                      <Th className="md:w-[22%]">{t('analyzers.colLastEvent')}</Th>
                    </tr>
                  </THead>
                  <TBody>
                    {shown.map((a) => (
                      <AnalyzerRow key={keyOf(a)} a={a} selected={keyOf(a) === selected} onSelect={() => setSelected(keyOf(a))} />
                    ))}
                  </TBody>
                </Table>
              )}
            </div>
            <aside aria-label={t('analyzers.inspectorLabel')} className="border-t border-rule lg:border-s lg:border-t-0">
              <AnalyzerInspector
                analyzer={selectedItem}
                mayManage={mayManage}
                testing={testingKey !== null && selectedItem !== null && testingKey === keyOf(selectedItem)}
                result={selectedItem ? results[keyOf(selectedItem)] : undefined}
                testError={selectedItem ? errors[keyOf(selectedItem)] : undefined}
                onTest={(a) => test.mutate(a)}
                analyzing={analyzingKey !== null && selectedItem !== null && analyzingKey === keyOf(selectedItem)}
                queued={selectedItem ? queued[keyOf(selectedItem)] : undefined}
                analyzeError={selectedItem ? analyzeErrors[keyOf(selectedItem)] : undefined}
                onAnalyze={(a) => analyze.mutate(a)}
              />
            </aside>
          </div>
        </>
      )}
    </div>
  );
}

function AnalyzerRow({ a, selected, onSelect }: { a: AnalyzerItem; selected: boolean; onSelect: () => void }) {
  const { t } = useTranslation();
  const status = statusOf(a);
  const lastBad = a.last_event?.outcome === 'failed';
  return (
    <Tr selected={selected} className="h-12 align-middle">
      <Td className="whitespace-normal">
        <button type="button" onClick={onSelect} aria-pressed={selected} className="block max-w-full text-start hover:text-accent">
          <span className="block truncate font-medium">{a.name}</span>
          <span className="block truncate text-12 text-ink-2">
            <span className="md:hidden">{t(`analyzers.kind_${a.kind}`)}, </span>
            {t(`analyzers.scope_${a.scope}`)}
            {a.namespace ? `, ${a.namespace}` : ''}
          </span>
        </button>
      </Td>
      <Td className="hidden whitespace-normal md:table-cell">{t(`analyzers.kind_${a.kind}`)}</Td>
      <Td className="hidden whitespace-normal md:table-cell"><span className="block truncate font-mono text-12" title={whereOf(a)}>{whereOf(a)}</span></Td>
      <Td className="whitespace-normal">
        <span className={cn('inline-flex items-center gap-1.5', status === 'refused' && 'text-critical')}>
          {status === 'refused' && <IconWarning className="size-3.5 shrink-0" />}
          {t(`analyzers.status_${status}`)}
        </span>
      </Td>
      <Td className="whitespace-normal">
        {a.last_event ? (
          <>
            <span className={cn('block', lastBad && 'text-critical')}>{eventPhrase(t, a.last_event)}</span>
            <span className="block font-mono text-12 text-ink-2">{absoluteDateTime(a.last_event.created_at)}</span>
          </>
        ) : (
          <span className="text-ink-2">{t('analyzers.neverTested')}</span>
        )}
      </Td>
    </Tr>
  );
}
