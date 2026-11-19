import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { get, ProblemError, toProblem } from '@/api';
import type { ApplicationPage } from '@/api/types';
import { BandShape, Button, CommandLine, EmptyState, ProblemMessage, SearchField, Spinner } from '@/components';
import { cn } from '@/lib/cn';
import { GraphCanvas } from './graph/GraphCanvas';
import { GraphList } from './graph/GraphList';
import { NodeInspector } from './graph/NodeInspector';
import {
  allExpandable, buildIndex, initialExpanded, layoutTree, MAX_ITEMS, pathFromRoot, revealed, searchNodes, visibleTree,
  type GraphResponse,
} from './graph/model';

/**
 * The dependency graph of the application's SBOM: what the application depends on, how each package is reached, and
 * which of them have open findings. Everything shown comes from the stored SBOM; nothing is guessed except where the page
 * says so (a root the document does not link to anything).
 */
export function ApplicationDependencyGraphSection({ app, active = true }: { app: ApplicationPage; active?: boolean }) {
  const { t } = useTranslation();
  const q = useQuery({
    queryKey: ['applications', app.id, 'sbom-graph'],
    enabled: active, // the tab keeps its content mounted: it loads when it is opened, not with the page
    queryFn: ({ signal }) => get<GraphResponse>(`/api/v1/applications/${encodeURIComponent(app.id)}/sbom/graph`, { signal }),
  });

  if (q.isPending) {
    return <div className="flex h-48 items-center justify-center"><Spinner size={24} /></div>;
  }
  if (q.isError) {
    const problem = toProblem(q.error);
    if (q.error instanceof ProblemError && q.error.problem.status === 404) {
      return (
        <EmptyState title={t('apps.graph.emptyNoSbomTitle')} action={<CommandLine command="rampart sbom upload bom.json --parser cyclonedx --app <application>" />}>
          {t('apps.graph.emptyNoSbomBody')}
        </EmptyState>
      );
    }
    return <ProblemMessage problem={problem} title={t('apps.graph.failed')} onRetry={() => void q.refetch()} className="py-4" />;
  }
  if (!q.data.has_dependencies) {
    return (
      <EmptyState title={t('apps.graph.emptyNoDepsTitle')}>
        {t('apps.graph.emptyNoDepsBody', { count: q.data.total_components, format: q.data.format })}
      </EmptyState>
    );
  }
  return <GraphWorkbench data={q.data} />;
}

type Mode = 'graph' | 'list';

function GraphWorkbench({ data }: { data: GraphResponse }) {
  const { t } = useTranslation();
  const index = useMemo(() => buildIndex(data), [data]);
  const [expanded, setExpanded] = useState<Set<string>>(() => initialExpanded(buildIndex(data)));
  const [onlyRisk, setOnlyRisk] = useState(false);
  const [mode, setMode] = useState<Mode>('graph');
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [centerToken, setCenterToken] = useState(0);

  const { tree, size } = useMemo(() => {
    const tree = visibleTree(index, expanded, onlyRisk);
    return { tree, size: layoutTree(tree) };
  }, [index, expanded, onlyRisk]);

  const matches = useMemo(() => searchNodes(data, query), [data, query]);
  const matchIds = useMemo(() => new Set(matches.map((m) => m.id)), [matches]);
  const path = useMemo(() => (selectedId ? pathFromRoot(index, selectedId) : null), [index, selectedId]);
  const pathIds = useMemo(() => new Set(path ?? []), [path]);
  const selected = selectedId ? (index.byId.get(selectedId) ?? null) : null;

  const toggle = (id: string) =>
    setExpanded((cur) => {
      const next = new Set(cur);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  // A component picked from the path, the search or the inspector must be on screen: open the way to it.
  const goTo = (id: string) => {
    setExpanded((cur) => revealed(index, id, cur));
    setOnlyRisk((on) => on && (index.riskBelow.get(id) ?? 0) > 0);
    setSelectedId(id);
    setCenterToken((n) => n + 1);
  };

  const withFindings = data.nodes.filter((n) => n.vulnerabilities.critical + n.vulnerabilities.high + n.vulnerabilities.medium + n.vulnerabilities.low > 0).length;
  const canvasProps = { tree, nodes: index.byId, selectedId, pathIds, matchIds, onSelect: (id: string) => setSelectedId(id), onToggle: toggle };

  return (
    <div className="space-y-3 pt-2">
      <p className="max-w-[80ch] text-13 text-ink-2">
        {t('apps.graph.summary', { total: data.total_components, direct: data.direct_components, transitive: data.transitive_components })}{' '}
        {withFindings > 0 ? t('apps.graph.summaryFindings', { count: withFindings }) : t('apps.graph.summaryClean')}
      </p>
      {data.inferred_root && <p className="max-w-[80ch] text-13 text-ink-2">{t('apps.graph.inferredNote')}</p>}
      {data.unreachable_components > 0 && <p className="max-w-[80ch] text-13 text-ink-2">{t('apps.graph.unreachableNote', { count: data.unreachable_components })}</p>}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-y border-rule py-2">
        <div className="relative w-64">
          <SearchField aria-label={t('apps.graph.searchLabel')} placeholder={t('apps.graph.searchPlaceholder')} value={query} onChange={(e) => setQuery(e.target.value)} />
          {matches.length > 0 && (
            <ul className="absolute inset-x-0 top-9 z-10 max-h-64 overflow-auto border border-rule bg-surface">
              {matches.map((m) => (
                <li key={m.id}>
                  <button type="button" className="flex w-full items-center gap-2 px-2.5 py-1.5 text-start text-13 hover:bg-chrome" onClick={() => { goTo(m.id); setQuery(''); }}>
                    <span className="truncate">{m.name}</span><span className="text-ink-2">{m.version}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
        <label className="inline-flex items-center gap-2 text-13">
          <input type="checkbox" checked={onlyRisk} onChange={(e) => setOnlyRisk(e.target.checked)} className="size-4 accent-[var(--accent)]" />
          {t('apps.graph.onlyFindings')}
        </label>
        <div className="flex gap-1">
          <Button variant="ghost" onClick={() => setExpanded(initialExpanded(index))} disabled={onlyRisk}>{t('apps.graph.collapseAll')}</Button>
          <Button variant="ghost" onClick={() => setExpanded(allExpandable(index))} disabled={onlyRisk}>{t('apps.graph.expandAll')}</Button>
        </div>
        <div role="group" aria-label={t('apps.graph.viewLabel')} className="ms-auto flex overflow-hidden rounded-ctl border border-rule">
          {(['graph', 'list'] as const).map((m) => (
            <button key={m} type="button" aria-pressed={mode === m} onClick={() => setMode(m)}
              className={cn('h-8 px-3 text-13', m === 'list' && 'border-s border-rule', mode === m ? 'bg-chrome font-semibold' : 'hover:bg-chrome')}>
              {t(`apps.graph.view_${m}`)}
            </button>
          ))}
        </div>
      </div>

      <ul aria-label={t('apps.graph.legendLabel')} className="flex flex-wrap items-center gap-x-4 gap-y-1 text-12 text-ink-2">
        {(['critical', 'high', 'medium', 'low'] as const).map((b) => (
          <li key={b} className="inline-flex items-center gap-1.5"><BandShape band={b} />{t(`apps.graph.band.${b}`)}</li>
        ))}
        <li className="inline-flex items-center gap-1.5"><span aria-hidden="true" className="size-1.5 rounded-full bg-ink-2 opacity-70" />{t('apps.graph.legendNone')}</li>
      </ul>

      <div className="grid grid-cols-1 border border-rule lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="h-[min(72vh,46rem)] min-w-0">
          {mode === 'graph'
            ? <GraphCanvas {...canvasProps} size={size} centerToken={centerToken} />
            : <GraphList {...canvasProps} />}
        </div>
        <aside aria-label={t('apps.graph.inspectorLabel')} className="max-h-[min(72vh,46rem)] overflow-auto border-t border-rule lg:border-s lg:border-t-0">
          <NodeInspector node={selected} index={index} path={path} onSelect={goTo} />
        </aside>
      </div>
      {tree.truncated && <p className="text-13 text-ink-2" role="status">{t('apps.graph.truncated', { count: MAX_ITEMS })}</p>}
    </div>
  );
}
