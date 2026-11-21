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

/** Resolves the CRD resource kind for a parser. */
export function parserResourceKind(p: ParserDescriptor): 'ClusterParser' | 'ClusterSBOMParser' | 'Parser' {
  if (p.resource_kind) return p.resource_kind;
  if (p.family === 'sbom' || p.id.startsWith('cluster:sbom-') || p.resource_kind === 'ClusterSBOMParser') return 'ClusterSBOMParser';
  if (p.origin === 'tenant' || p.id.startsWith('mapping:')) return 'Parser';
  return 'ClusterParser';
}

/** Resolves the clean resource name / upload format of a parser. */
export function parserResourceName(p: ParserDescriptor): string {
  if (p.resource_name) return p.resource_name;
  return p.id
    .replace(/^cluster:sbom-/, '')
    .replace(/^cluster:/, '')
    .replace(/^mapping:/, '');
}

/** Returns the Kubernetes CRD reference, e.g. ClusterParser/bandit or ClusterSBOMParser/cyclonedx */
export function parserResourceRef(p: ParserDescriptor): string {
  const kind = parserResourceKind(p);
  const name = parserResourceName(p);
  return `${kind}/${name}`;
}

/** What an SBOM parser reads: its format, from its id or CRD resource name. A report parser says its category. */
const readsOf = (p: ParserDescriptor, family: Family): string =>
  family === 'sbom' ? parserResourceName(p) : p.category ?? '';

/** Resolves the category ID of a parser (e.g. sast, sca, secrets, iac, dast, compliance, vex). */
export function parserCategory(p: ParserDescriptor): string {
  const raw = (p.category ?? '').toLowerCase().trim();
  if (raw === 'sast') return 'sast';
  if (raw === 'sca') return 'sca';
  if (raw === 'secrets' || raw === 'secret') return 'secrets';
  if (raw === 'iac' || raw === 'cloud') return 'iac';
  if (raw === 'dast') return 'dast';
  if (raw === 'compliance' || raw === 'cspm') return 'compliance';
  if (raw === 'vex') return 'vex';

  const lower = (p.id + ' ' + (p.name || '') + ' ' + (p.description || '')).toLowerCase();
  if (lower.includes('sarif') || lower.includes('semgrep') || lower.includes('bandit') || lower.includes('sast')) return 'sast';
  if (lower.includes('gitleaks') || lower.includes('trufflehog') || lower.includes('secret')) return 'secrets';
  if (lower.includes('checkov') || lower.includes('iac')) return 'iac';
  if (lower.includes('kubebench') || lower.includes('prowler') || lower.includes('compliance')) return 'compliance';
  if (lower.includes('openvex') || lower.includes('vex')) return 'vex';
  if (lower.includes('zap') || lower.includes('nuclei') || lower.includes('dast')) return 'dast';
  if (lower.includes('trivy') || lower.includes('grype') || lower.includes('snyk') || lower.includes('dependency') || lower.includes('sca')) return 'sca';

  return raw || 'other';
}

/**
 * The parsers installed on the server, of one family (report parsers or SBOM parsers): what each is, whether it is installed correctly (ready, its
 * module missing, or its resource refused), and how it last worked. What is shown is what the server holds; nothing is listed that is not installed.
 */
export function ParserList({ family }: { family: Family }) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string>('all');
  const [selected, setSelected] = useState<string | null>(null);
  const q = useQuery({ queryKey: qk.parsers.list(), queryFn: ({ signal }) => listParsers(signal) });

  // A server that does not say the family (an older one) reads as report parsers, except the SBOM readers by their id.
  const all = useMemo(
    () => (q.data ?? []).filter((p) => (p.family ?? (p.id.startsWith('cluster:sbom-') || p.resource_kind === 'ClusterSBOMParser' ? 'sbom' : 'report')) === family),
    [q.data, family],
  );

  // Compute categories and counts for sub-tabs.
  // SBOM parsers all belong to the single SBOM inventory domain and have no sub-categories in their CRD (spec.format).
  // Category sub-tabs only apply to report parsers (SAST, SCA, Secrets, IaC, DAST, etc.) which have spec.category.
  const categories = useMemo(() => {
    if (family === 'sbom' || all.length === 0) return [];
    const counts = new Map<string, number>();
    counts.set('all', all.length);

    for (const p of all) {
      const cat = parserCategory(p);
      counts.set(cat, (counts.get(cat) ?? 0) + 1);
    }

    const order = ['all', 'sast', 'sca', 'secrets', 'iac', 'dast', 'compliance', 'vex', 'other'];

    const result: Array<{ id: string; label: string; count: number }> = [];
    for (const id of order) {
      const count = counts.get(id);
      if (count && count > 0) {
        const label = t(`parsers.cat_${id}`, {
          defaultValue: id === 'all' ? 'All' :
            id === 'sast' ? 'SAST' :
            id === 'sca' ? 'SCA' :
            id === 'secrets' ? 'Secrets' :
            id === 'iac' ? 'IaC & Cloud' :
            id === 'dast' ? 'DAST' :
            id === 'compliance' ? 'Compliance' :
            id === 'vex' ? 'VEX' : 'Other',
        });
        result.push({ id, label, count });
      }
    }
    for (const [id, count] of counts.entries()) {
      if (!order.includes(id) && count > 0) {
        result.push({ id, label: id, count });
      }
    }
    return result;
  }, [all, family, t]);

  const shown = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return all.filter((p) => {
      if (family !== 'sbom' && category !== 'all') {
        const cat = parserCategory(p);
        if (cat !== category) return false;
      }
      if (!needle) return true;
      return [p.name, p.id, parserResourceRef(p), parserResourceName(p), p.description, readsOf(p, family)].some((v) => (v ?? '').toLowerCase().includes(needle));
    });
  }, [all, search, family, category]);

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

      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-y border-rule py-2">
        {categories.length > 1 && (
          <nav aria-label={t('parsers.categoryTabsLabel')} className="flex flex-wrap items-center gap-1.5">
            {categories.map((c) => (
              <button
                key={c.id}
                type="button"
                onClick={() => setCategory(c.id)}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-ctl px-2.5 py-1 text-12 font-medium transition-colors',
                  category === c.id
                    ? 'border border-rule bg-surface font-semibold text-ink shadow-xs'
                    : 'text-ink-2 hover:bg-chrome hover:text-ink',
                )}
              >
                <span>{c.label}</span>
                <span className={cn('text-11', category === c.id ? 'font-semibold text-accent' : 'text-ink-3')}>
                  ({c.count})
                </span>
              </button>
            ))}
          </nav>
        )}
        <div className="ms-auto">
          <SearchField
            className="w-64"
            aria-label={t('parsers.searchLabel')}
            placeholder={t('parsers.searchPlaceholder')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
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
  const ref = parserResourceRef(p);
  return (
    <Tr selected={selected} className="h-12 align-middle">
      <Td className="whitespace-normal">
        <button type="button" onClick={onSelect} aria-pressed={selected} className="block max-w-full text-start hover:text-accent">
          <span className="block break-words font-medium md:truncate">{p.name}</span>
          <span className="block break-all font-mono text-12 text-ink-2 md:truncate">{ref}</span>
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
  const ref = parserResourceRef(p);
  const cleanName = parserResourceName(p);
  const kind = parserResourceKind(p);
  return (
    <div className="space-y-5 p-4 text-13">
      <header>
        <div className="flex items-center gap-2">
          <h3 className="break-words text-14 font-semibold">{p.name}</h3>
          <span className="rounded bg-chrome px-1.5 py-0.5 text-10 font-semibold uppercase tracking-wider text-ink-3">
            {kind}
          </span>
        </div>
        <p className="mt-0.5 break-all font-mono text-12 text-ink-2">{ref}</p>
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
        <Row label={t('parsers.crdResource')}><span className="font-mono text-12 font-medium text-accent">{ref}</span></Row>
        <Row label={t('parsers.uploadFormat')}><span className="font-mono text-12">--parser {cleanName}</span></Row>
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
