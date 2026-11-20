import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { listFindings, qk, toProblem } from '@/api';
import type { VulnerabilityRow } from '@/api/types';
import {
  EmptyState,
  Input,
  ProblemMessage,
  Spinner,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
} from '@/components';
import { cn } from '@/lib/cn';

export function VulnerabilitiesRoute() {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [onlyKev, setOnlyKev] = useState(false);

  useEffect(() => {
    document.title = `${t('nav.vulnerabilities', { defaultValue: 'Vulnerabilities' })} - Rampart`;
  }, [t]);

  // Query real findings from the backend
  const findingsQuery = useQuery({
    queryKey: qk.findings.list('state:open', '-score'),
    queryFn: async ({ signal }) => {
      // An error used to become an empty list: "No vulnerabilities tracked" for a server that was down.
      const res = await listFindings({ q: 'state:open', sort: '-score', limit: 200, signal });
      return res.items ?? [];
    },
  });

  // Aggregate real findings by CVE ID
  const cveRows: VulnerabilityRow[] = useMemo(() => {
    const items = findingsQuery.data ?? [];
    const map = new Map<string, {
      row: VulnerabilityRow;
      assets: Set<string>;
      apps: Set<string>;
    }>();

    for (const item of items) {
      const f = item.finding;
      const cveId = f.vulnerability_id || (f.rule_id?.toUpperCase().startsWith('CVE-') ? f.rule_id.toUpperCase() : null);
      if (!cveId) continue;

      // The probability and the KEV flag are on the score breakdown. The EPSS was read from the points of its factor
      // (150 points / 100 = "150%"), which is not a probability.
      const epssVal = item.risk?.epss_score;
      const isKev = Boolean(item.risk?.has_kev);

      const existing = map.get(cveId);
      if (existing) {
        existing.row.open_findings += 1;
        if (f.risk_score > existing.row.score) {
          existing.row.score = f.risk_score;
          existing.row.severity = f.severity;
        }
        if (isKev) existing.row.kev = true;
        if (epssVal !== undefined && (existing.row.epss === undefined || epssVal > existing.row.epss)) {
          existing.row.epss = epssVal;
        }
        if (f.asset_id) existing.assets.add(f.asset_id);
        if (f.application_id) existing.apps.add(f.application_id);
        existing.row.affected_assets = existing.assets.size;
        existing.row.affected_applications = existing.apps.size;
      } else {
        const assets = new Set<string>();
        const apps = new Set<string>();
        if (f.asset_id) assets.add(f.asset_id);
        if (f.application_id) apps.add(f.application_id);

        map.set(cveId, {
          row: {
            cve_id: cveId,
            title: f.title || cveId,
            severity: f.severity,
            score: f.risk_score,
            epss: epssVal,
            kev: isKev,
            affected_assets: assets.size,
            affected_applications: apps.size,
            open_findings: 1,
          },
          assets,
          apps,
        });
      }
    }

    return Array.from(map.values()).map((e) => e.row);
  }, [findingsQuery.data]);

  const filtered = useMemo(() => {
    return cveRows.filter((row) => {
      const matchesSearch =
        !search.trim() ||
        row.cve_id.toLowerCase().includes(search.toLowerCase()) ||
        row.title.toLowerCase().includes(search.toLowerCase());
      const matchesKev = !onlyKev || row.kev;
      return matchesSearch && matchesKev;
    });
  }, [cveRows, search, onlyKev]);

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto p-6">
      <div className="mb-6 flex flex-col gap-1">
        <h1 className="display text-20 font-semibold text-ink">
          {t('nav.vulnerabilities', { defaultValue: 'Enterprise Vulnerability Hub' })}
        </h1>
        <p className="text-13 text-ink-2">
          {t('vulnerabilities.subtitle', { defaultValue: 'CVE-centric impact analysis correlated with EPSS exploit probabilities, CISA KEV active exploitation, and organizational asset blast radius.' })}
        </p>
      </div>

      <div className="mb-4 flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-72">
            <Input
              placeholder="Search by CVE ID or keyword..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <label className="flex items-center gap-1.5 text-12 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={onlyKev}
              onChange={(e) => setOnlyKev(e.target.checked)}
              className="rounded border-rule"
            />
            <span className="font-medium text-ink">CISA KEV Known Exploited Only</span>
          </label>
        </div>
        <span className="text-12 text-ink-2">
          {filtered.length} {filtered.length === 1 ? 'vulnerability' : 'vulnerabilities'} tracked
        </span>
      </div>

      {findingsQuery.isLoading ? (
        <div className="flex h-48 items-center justify-center">
          <Spinner />
        </div>
      ) : findingsQuery.isError ? (
        <ProblemMessage problem={toProblem(findingsQuery.error)} title={t('vulnerabilities.loadFailed', { defaultValue: 'Vulnerabilities could not be loaded.' })} onRetry={() => void findingsQuery.refetch()} />
      ) : filtered.length === 0 ? (
        <EmptyState title={search || onlyKev ? "No vulnerabilities match the current filter" : "No vulnerabilities tracked"}>
          {search || onlyKev
            ? "Try clearing your search or unchecking the CISA KEV filter."
            : "Vulnerabilities automatically populate when scan reports containing CVEs are ingested."}
        </EmptyState>
      ) : (
        <Table aria-label="Vulnerabilities by CVE">
          <THead>
            <tr>
              <Th>Vulnerability / CVE</Th>
              <Th>Severity</Th>
              <Th>EPSS</Th>
              <Th>Exploited (KEV)</Th>
              <Th align="end">Affected Apps</Th>
              <Th align="end">Affected Assets</Th>
              <Th align="end">Open Findings</Th>
            </tr>
          </THead>
          <TBody>
            {filtered.map((v) => (
              <Tr key={v.cve_id} className="h-14">
                <Td className="font-medium text-ink max-w-md">
                  <div className="flex flex-col">
                    <Link
                      to="/vulnerabilities/$id"
                      params={{ id: v.cve_id }}
                      className="font-mono text-13 text-accent hover:underline font-semibold"
                    >
                      {v.cve_id}
                    </Link>
                    <span className="text-12 text-ink-2 truncate">{v.title}</span>
                  </div>
                </Td>
                <Td>
                  <span
                    className={cn(
                      'inline-flex items-center gap-1 rounded px-2 py-0.5 text-12 font-medium uppercase',
                      v.severity === 'critical' && 'bg-rose-500/10 text-rose-600 dark:text-rose-400',
                      v.severity === 'high' && 'bg-high/10 text-high',
                    )}
                  >
                    {v.severity} ({v.score.toFixed(1)})
                  </span>
                </Td>
                <Td className="font-mono text-12 text-ink">
                  {v.epss !== undefined ? `${(v.epss * 100).toFixed(1)}%` : '—'}
                </Td>
                <Td>
                  {v.kev ? (
                    <span className="inline-flex rounded-full bg-critical/15 px-2 py-0.5 text-12 font-semibold text-critical">
                      CISA KEV
                    </span>
                  ) : (
                    <span className="text-12 text-ink-2">No</span>
                  )}
                </Td>
                <Td align="end" className="text-12 text-ink font-medium">
                  {v.affected_applications}
                </Td>
                <Td align="end" className="text-12 text-ink font-medium">
                  {v.affected_assets}
                </Td>
                <Td align="end">
                  <Link
                    to="/findings"
                    search={{ q: `cve:${v.cve_id}` }}
                    className="text-12 font-medium text-accent hover:underline"
                  >
                    {v.open_findings} findings →
                  </Link>
                </Td>
              </Tr>
            ))}
          </TBody>
        </Table>
      )}
    </div>
  );
}
