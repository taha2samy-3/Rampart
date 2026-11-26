import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { listTrackers, qk, testTracker, toProblem } from '@/api';
import type { TrackerContainerItem, TrackerTestResult } from '@/api/types';
import { useAccess } from '@/app/useAccess';
import { EmptyState, ProblemMessage, Spinner, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { cn } from '@/lib/cn';
import { absoluteDateTime } from '@/lib/format';
import { StatusMark } from '@/routes/parsers/StatusMark';
import { TrackerInspector } from './TrackerInspector';

const keyOf = (t: Pick<TrackerContainerItem, 'scope' | 'namespace' | 'name'>) => `${t.scope}/${t.namespace ?? ''}/${t.name}`;

export function TrackerContainersView() {
  const { t } = useTranslation();
  const { can } = useAccess();
  const qc = useQueryClient();
  const mayManage = can(undefined, 'admin');

  const q = useQuery({ queryKey: qk.trackers.list(), queryFn: ({ signal }) => listTrackers(signal) });
  const [selected, setSelected] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, TrackerTestResult>>({});
  const [testErrors, setTestErrors] = useState<Record<string, string>>({});

  const test = useMutation({
    mutationFn: (item: TrackerContainerItem) => testTracker(item),
    onSuccess: (res, item) => {
      const k = keyOf(item);
      setResults((r) => ({ ...r, [k]: res }));
      setTestErrors((e) => {
        const next = { ...e };
        delete next[k];
        return next;
      });
      void qc.invalidateQueries({ queryKey: qk.trackers.list() });
      void qc.invalidateQueries({ queryKey: qk.trackers.events(item) });
    },
    onError: (err, item) => {
      const p = toProblem(err);
      setTestErrors((e) => ({ ...e, [keyOf(item)]: p.detail ?? p.title }));
    },
  });

  if (q.isPending) {
    return (
      <div className="flex items-center gap-2 py-8 text-13 text-ink-2">
        <Spinner size={16} /> Checking registered tracker containers…
      </div>
    );
  }
  if (q.isError) {
    return <ProblemMessage problem={toProblem(q.error)} title={t('ticketing.loadFailed')} onRetry={() => void q.refetch()} className="mt-4" />;
  }

  const all = q.data ?? [];
  if (all.length === 0) {
    return (
      <EmptyState title={t('ticketing.noneConfigured')} className="mt-6">
        {t('ticketing.noneConfiguredHint')}
      </EmptyState>
    );
  }

  const readyCount = all.filter((x) => x.state === 'ready').length;
  const refusedCount = all.filter((x) => x.state === 'refused').length;
  const selectedItem = all.find((x) => keyOf(x) === selected) ?? all[0] ?? null;
  const testingKey = test.isPending && test.variables ? keyOf(test.variables) : null;

  return (
    <div className="mt-4">
      <p className="text-13 text-ink-2">
        {t('ticketing.summary', { count: all.length, ready: readyCount, refused: refusedCount })}
      </p>

      <div className="mt-3 border-t border-rule lg:grid lg:grid-cols-[minmax(0,1fr)_24rem]">
        <div className="min-w-0">
          <Table aria-label="Tracker containers" className="table-fixed">
            <THead>
              <Tr>
                <Th className="w-[30%]">{t('ticketing.colTracker')}</Th>
                <Th className="hidden w-[28%] md:table-cell">{t('ticketing.colTarget')}</Th>
                <Th className="w-[10%] text-right">{t('ticketing.colBound')}</Th>
                <Th className="w-[14%]">{t('ticketing.colStatus')}</Th>
                <Th className="w-[18%]">{t('ticketing.colLastEvent')}</Th>
              </Tr>
            </THead>
            <TBody>
              {all.map((item) => {
                const k = keyOf(item);
                const isSelected = selectedItem ? keyOf(selectedItem) === k : false;
                const lastBad = item.last_event?.outcome === 'failed';
                return (
                  <Tr key={k} selected={isSelected} className="h-12 align-middle">
                    <Td className="whitespace-normal">
                      <button type="button" onClick={() => setSelected(k)} aria-pressed={isSelected} className="block max-w-full text-start hover:text-accent">
                        <span className="block break-words font-medium md:truncate">{item.name}</span>
                        <span className="block break-words text-12 text-ink-2 md:truncate">
                          {t(`ticketing.scope_${item.scope}`, { defaultValue: item.scope })}
                          {item.namespace ? `, ${item.namespace}` : ''}
                        </span>
                      </button>
                    </Td>
                    <Td className="hidden whitespace-normal md:table-cell">
                      <span className="block truncate font-mono text-12" title={item.target ?? ''}>
                        {item.target || 'Not configured'}
                      </span>
                    </Td>
                    <Td className="text-right font-mono tabular-nums">{item.bound_connectors}</Td>
                    <Td className="whitespace-normal">
                      <span className={cn('inline-flex items-center gap-1.5', item.state === 'refused' && 'text-critical')}>
                        <StatusMark health={item.state === 'refused' ? 'problem' : item.state === 'ready' ? 'ok' : 'idle'} />
                        {t(`ticketing.status_${item.state}`, { defaultValue: item.state })}
                      </span>
                    </Td>
                    <Td className="whitespace-normal">
                      {item.last_event ? (
                        <span className="inline-flex items-start gap-1.5">
                          <StatusMark health={lastBad ? 'problem' : 'ok'} className="mt-0.5" />
                          <span>
                            <span className={cn('block', lastBad && 'text-critical')}>
                              {lastBad ? 'Probe failed' : 'Probe succeeded'}
                            </span>
                            <span className="block font-mono text-12 text-ink-2">{absoluteDateTime(item.last_event.at)}</span>
                          </span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-ink-2">
                          <StatusMark health="idle" />
                          {t('ticketing.neverTested')}
                        </span>
                      )}
                    </Td>
                  </Tr>
                );
              })}
            </TBody>
          </Table>
        </div>
        <aside aria-label="Tracker container details" className="border-t border-rule lg:border-s lg:border-t-0">
          <TrackerInspector
            tracker={selectedItem}
            mayManage={mayManage}
            testing={testingKey !== null && selectedItem !== null && testingKey === keyOf(selectedItem)}
            result={selectedItem ? results[keyOf(selectedItem)] : undefined}
            testError={selectedItem ? testErrors[keyOf(selectedItem)] : undefined}
            onTest={(item) => test.mutate(item)}
          />
        </aside>
      </div>
    </div>
  );
}
