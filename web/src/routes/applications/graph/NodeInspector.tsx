import { useTranslation } from 'react-i18next';
import { BandShape } from '@/components';
import { toBand } from '@/lib/band';
import { riskTotal, type GraphIndex, type GraphNodeData } from './model';

const BANDS = ['critical', 'high', 'medium', 'low'] as const;

/** What is known about the selected component, and how the application reaches it. */
export function NodeInspector({
  node, index, path, onSelect,
}: {
  node: GraphNodeData | null;
  index: GraphIndex;
  path: string[] | null;
  onSelect: (id: string) => void;
}) {
  const { t } = useTranslation();
  if (!node) return <p className="p-4 text-13 text-ink-2">{t('apps.graph.inspectorEmpty')}</p>;

  const usedBy = index.parents.get(node.id) ?? [];
  const dependsOn = index.children.get(node.id) ?? [];
  const role = node.root ? 'roleRoot' : node.direct ? 'roleDirect' : node.depth > 1 ? 'roleTransitive' : 'roleUnreached';
  const name = (id: string) => index.byId.get(id)?.name ?? id;

  return (
    <div className="space-y-5 p-4 text-13">
      <header>
        <h3 className="break-words text-14 font-semibold">{node.name}{node.version && <span className="ms-2 font-normal text-ink-2">{node.version}</span>}</h3>
        <p className="mt-0.5 text-ink-2">{t(`apps.graph.${role}`, { depth: node.depth })}</p>
        {node.purl && <p className="mt-2 break-all font-mono text-12 text-ink-2">{node.purl}</p>}
      </header>

      <section aria-labelledby="g-find">
        <h4 id="g-find" className="font-semibold">{t('apps.graph.findings')}</h4>
        {riskTotal(node.vulnerabilities) === 0 ? (
          <p className="mt-1 text-ink-2">{t('apps.graph.noFindings')}</p>
        ) : (
          <ul className="mt-1 space-y-1">
            {BANDS.filter((b) => node.vulnerabilities[b] > 0).map((b) => (
              <li key={b} className="flex items-center gap-2">
                <BandShape band={toBand(b)} />
                <span>{t(`apps.graph.band.${b}`)}</span>
                <span className="ms-auto font-semibold tabular-nums">{node.vulnerabilities[b]}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {path && path.length > 1 && (
        <section aria-labelledby="g-path">
          <h4 id="g-path" className="font-semibold">{t('apps.graph.pathTitle')}</h4>
          <ol className="mt-1 border-s border-rule">
            {path.map((id, i) => (
              <li key={id} style={{ paddingInlineStart: 8 + Math.min(i, 6) * 10 }}>
                <button
                  type="button"
                  onClick={() => onSelect(id)}
                  aria-current={id === node.id ? 'true' : undefined}
                  className={`block w-full truncate py-0.5 text-start hover:text-accent ${id === node.id ? 'font-semibold' : 'text-ink-2'}`}
                >
                  {name(id)}
                </button>
              </li>
            ))}
          </ol>
        </section>
      )}

      {usedBy.length > 0 && (
        <section aria-labelledby="g-used">
          <h4 id="g-used" className="font-semibold">{t('apps.graph.usedBy', { count: usedBy.length })}</h4>
          <ul className="mt-1">
            {usedBy.slice(0, 8).map((id) => (
              <li key={id}><button type="button" onClick={() => onSelect(id)} className="block w-full truncate py-0.5 text-start text-ink-2 hover:text-accent">{name(id)}</button></li>
            ))}
            {usedBy.length > 8 && <li className="py-0.5 text-ink-2">{t('apps.graph.andMore', { count: usedBy.length - 8 })}</li>}
          </ul>
        </section>
      )}

      {dependsOn.length > 0 && (
        <p className="text-ink-2">{t('apps.graph.dependsOn', { count: dependsOn.length })}</p>
      )}

      {(node.licenses?.length || node.scope) && (
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
          {node.licenses?.length ? (<><dt className="text-ink-2">{t('apps.graph.licenses')}</dt><dd>{node.licenses.join(', ')}</dd></>) : null}
          {node.scope ? (<><dt className="text-ink-2">{t('apps.graph.scope')}</dt><dd>{node.scope}</dd></>) : null}
        </dl>
      )}
    </div>
  );
}
