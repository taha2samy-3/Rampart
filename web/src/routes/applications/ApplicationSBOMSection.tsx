import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { get, listFindings, post, toProblem } from '@/api';
import type { ApplicationPage, FindingRow } from '@/api/types';
import {
  BandShape,
  Button,
  EmptyState,
  IconRefresh,
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
import { toBand } from '@/lib/band';
import { FindingDetailModal, type FindingDetailTarget } from './ChangesSection';

export interface AppPackage {
  asset_id?: string;
  asset_name?: string;
  application_name?: string;
  track?: string;
  purl: string;
  name: string;
  version: string;
  type: string;
  license?: string;
  vulnerabilities: number;
}

const purlBase = (purl: string) => purl.split(/[@?#]/)[0] ?? purl;

export function ApplicationSBOMSection({
  app,
  onSelectFinding,
}: {
  app: ApplicationPage;
  onSelectFinding?: (f: FindingDetailTarget) => void;
}) {
  const [search, setSearch] = useState('');
  const [scanningPurl, setScanningPurl] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<{ purl: string; message: string; ok: boolean } | null>(null);
  const [expandedPurls, setExpandedPurls] = useState<Set<string>>(new Set());
  const [localSelectedFinding, setLocalSelectedFinding] = useState<FindingDetailTarget | null>(null);

  const handleSelectFinding = onSelectFinding ?? setLocalSelectedFinding;

  const toggleExpand = (purl: string) => {
    setExpandedPurls((prev) => {
      const next = new Set(prev);
      if (next.has(purl)) {
        next.delete(purl);
      } else {
        next.add(purl);
      }
      return next;
    });
  };

  const query = useQuery({
    queryKey: ['applications', app.id, 'components'],
    queryFn: async ({ signal }) => {
      try {
        const res = await get<{ components: AppPackage[] }>(`/api/v1/applications/${encodeURIComponent(app.id)}/components`, { signal });
        return res.components ?? [];
      } catch {
        // Fallback to tenant inventory filtered by application name
        const res = await get<{ components: AppPackage[] }>('/api/v1/inventory/components?limit=1000', { signal });
        return (res.components ?? []).filter(
          (c) =>
            c.application_name &&
            (c.application_name.toLowerCase() === app.name.toLowerCase() ||
              (app.slug && c.application_name.toLowerCase() === app.slug.toLowerCase()))
        );
      }
    },
  });

  const packages = query.data ?? [];
  const lowerSearch = search.trim().toLowerCase();
  const filtered = packages.filter(
    (p) =>
      !lowerSearch ||
      p.name.toLowerCase().includes(lowerSearch) ||
      p.purl.toLowerCase().includes(lowerSearch) ||
      p.version.toLowerCase().includes(lowerSearch) ||
      p.type.toLowerCase().includes(lowerSearch) ||
      (p.asset_name ?? '').toLowerCase().includes(lowerSearch)
  );

  const vulnPackages = packages.filter((p) => p.vulnerabilities > 0);

  const handleScan = async (pkg: AppPackage) => {
    try {
      setScanningPurl(pkg.purl);
      const res = await post<{ status: string; message: string; purl: string }>('/api/v1/inventory/components/scan', {
        purl: pkg.purl,
        name: pkg.name,
        version: pkg.version,
        asset_id: pkg.asset_id,
        force: true,
      });
      setScanStatus({
        purl: pkg.purl,
        message: res.message || `On-demand scan initiated for ${pkg.name}`,
        ok: true,
      });
      void query.refetch();
    } catch (err) {
      const p = toProblem(err);
      setScanStatus({
        purl: pkg.purl,
        message: p.detail || `Scan failed to start for ${pkg.name}`,
        ok: false,
      });
    } finally {
      setScanningPurl(null);
    }
  };

  const appQuerySlug = app.slug || `"${app.name}"`;

  return (
    <section aria-labelledby="app-sbom-section">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 id="app-sbom-section" className="text-16 font-semibold text-ink">
            Software Bill of Materials (SBOM) & Packages
          </h2>
          <p className="m-0 text-12 text-ink-2">
            Dependencies and packages ingested for this application. Review packages affected by CVEs or download standardized SBOM manifests.
          </p>
        </div>
        <div className="mt-2 flex flex-wrap gap-2 sm:mt-0">
          <a
            href={`/api/v1/applications/${encodeURIComponent(app.id)}/sbom?format=cyclonedx`}
            download
            className="inline-flex h-7 items-center rounded-ctl border border-rule bg-surface px-2.5 text-11 font-medium text-ink hover:bg-chrome no-underline"
            title="Download CycloneDX SBOM (JSON)"
          >
            CycloneDX SBOM
          </a>
          <a
            href={`/api/v1/applications/${encodeURIComponent(app.id)}/sbom?format=spdx`}
            download
            className="inline-flex h-7 items-center rounded-ctl border border-rule bg-surface px-2.5 text-11 font-medium text-ink hover:bg-chrome no-underline"
            title="Download SPDX SBOM (JSON)"
          >
            SPDX SBOM
          </a>
          <a
            href={`/api/v1/applications/${encodeURIComponent(app.id)}/vex?format=cyclonedx`}
            download
            className="inline-flex h-7 items-center rounded-ctl border border-rule bg-surface px-2.5 text-11 font-medium text-ink hover:bg-chrome no-underline"
            title="Download CycloneDX VEX Advisory"
          >
            CycloneDX VEX
          </a>
          <a
            href={`/api/v1/applications/${encodeURIComponent(app.id)}/vex?format=openvex`}
            download
            className="inline-flex h-7 items-center rounded-ctl border border-rule bg-surface px-2.5 text-11 font-medium text-ink hover:bg-chrome no-underline"
            title="Download OpenVEX Advisory"
          >
            OpenVEX
          </a>
        </div>
      </div>

      {scanStatus && (
        <div
          role="status"
          className={`mt-3 flex items-center justify-between rounded border px-3 py-2 text-12 font-medium ${
            scanStatus.ok
              ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
              : 'border-red-500/20 bg-red-500/10 text-red-700 dark:text-red-400'
          }`}
        >
          <span>{scanStatus.message}</span>
          <button
            type="button"
            onClick={() => setScanStatus(null)}
            className="ml-2 text-11 opacity-70 hover:opacity-100"
            aria-label="Dismiss scan status"
          >
            ✕
          </button>
        </div>
      )}

      {vulnPackages.length > 0 && (
        <div className="mt-3 flex items-center gap-2 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-12 text-amber-800 dark:text-amber-300">
          <span className="font-semibold">⚠️ Action needed:</span>
          <span>
            {vulnPackages.length} package{vulnPackages.length > 1 ? 's' : ''} in this application {vulnPackages.length > 1 ? 'have' : 'has'} active CVEs.
          </span>
          <Link
            to="/findings"
            search={{ q: `app:${appQuerySlug} state:open,under_investigation,affected` }}
            className="ml-auto font-medium text-accent underline hover:opacity-85 text-12"
          >
            View all application CVEs →
          </Link>
        </div>
      )}

      <div className="mt-3 flex items-center justify-between gap-4">
        <div className="w-64">
          <Input
            placeholder="Filter application packages..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <span className="text-12 text-ink-2">
          {packages.length} package{packages.length === 1 ? '' : 's'} total
          {vulnPackages.length > 0 && ` • ${vulnPackages.length} vulnerable`}
        </span>
      </div>

      <div className="mt-3">
        {query.isLoading ? (
          <div className="flex h-32 items-center justify-center">
            <Spinner />
          </div>
        ) : query.isError ? (
          <ProblemMessage problem={toProblem(query.error)} title="Failed to load SBOM packages" onRetry={() => void query.refetch()} />
        ) : filtered.length === 0 ? (
          <EmptyState title="No packages found">
            {search.trim()
              ? 'No packages match your search filter.'
              : 'No SBOM packages have been ingested for this application yet. Ingest CycloneDX or SPDX reports to populate the dependency list.'}
          </EmptyState>
        ) : (
          <Table aria-label="Application packages table">
            <THead>
              <tr>
                <Th>Package</Th>
                <Th>Version</Th>
                <Th>Ecosystem</Th>
                <Th>Asset / Target</Th>
                <Th>License</Th>
                <Th align="end">CVEs / Status</Th>
                <Th align="end">Actions</Th>
              </tr>
            </THead>
            <TBody>
              {filtered.map((pkg) => {
                const pkgKey = `${pkg.asset_id ?? ''}|${pkg.track ?? ''}|${pkg.purl}`;
                const isExpanded = expandedPurls.has(pkgKey);
                return (
                  <PackageRowGroup
                    key={pkgKey}
                    pkgKey={pkgKey}
                    pkg={pkg}
                    app={app}
                    isExpanded={isExpanded}
                    onToggleExpand={() => toggleExpand(pkgKey)}
                    onSelectFinding={handleSelectFinding}
                    scanningPurl={scanningPurl}
                    onScan={handleScan}
                  />
                );
              })}
            </TBody>
          </Table>
        )}
      </div>

      {localSelectedFinding && (
        <FindingDetailModal change={localSelectedFinding} onClose={() => setLocalSelectedFinding(null)} />
      )}
    </section>
  );
}

function PackageRowGroup({
  pkgKey,
  pkg,
  app,
  isExpanded,
  onToggleExpand,
  onSelectFinding,
  scanningPurl,
  onScan,
}: {
  pkgKey: string;
  pkg: AppPackage;
  app: ApplicationPage;
  isExpanded: boolean;
  onToggleExpand: () => void;
  onSelectFinding: (f: FindingDetailTarget) => void;
  scanningPurl: string | null;
  onScan: (pkg: AppPackage) => void;
}) {
  const { t } = useTranslation();
  return (
    <>
      <Tr className="h-11">
        <Td className="font-medium text-ink">
          <div className="flex flex-col">
            <span className="font-mono text-12">{pkg.name}</span>
            <span className="max-w-xs truncate text-11 text-ink-2" title={pkg.purl}>
              {pkg.purl}
            </span>
          </div>
        </Td>
        <Td className="font-mono text-12 text-ink-2">{pkg.version}</Td>
        <Td className="text-12 uppercase text-ink-2">{pkg.type}</Td>
        <Td className="text-12 text-ink-2">
          <span className="block max-w-[10rem] truncate" title={pkg.asset_name}>
            {pkg.asset_name || '—'}
          </span>
        </Td>
        <Td className="text-12 text-ink-2">{pkg.license || 'Unknown'}</Td>
        <Td align="end">
          {pkg.vulnerabilities > 0 ? (
            <div className="inline-flex items-center gap-1.5">
              <Link
                to="/findings"
                search={{ q: `app:${app.slug || `"${app.name}"`} purl:"${purlBase(pkg.purl)}"` }}
                className="inline-flex items-center gap-1 rounded border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-11 font-medium text-red-600 no-underline hover:underline dark:text-red-400"
                title={`${pkg.vulnerabilities} open CVEs found in this package`}
              >
                ⚠️ {pkg.vulnerabilities} open CVE{pkg.vulnerabilities > 1 ? 's' : ''}
              </Link>
              <button
                type="button"
                onClick={onToggleExpand}
                aria-expanded={isExpanded}
                aria-controls={`pkg-cves-${pkgKey}`}
                className="inline-flex h-6 w-6 items-center justify-center rounded border border-red-500/30 bg-red-500/15 text-11 font-bold text-red-600 transition-colors hover:bg-red-500/25 dark:text-red-400"
                title={isExpanded ? 'Collapse CVE list' : 'Expand CVE list'}
                aria-label={isExpanded ? `Collapse CVEs for ${pkg.name}` : `Expand CVEs for ${pkg.name}`}
              >
                <span aria-hidden="true">{isExpanded ? '▲' : '▼'}</span>
              </button>
            </div>
          ) : (
            <span className="inline-flex items-center gap-1 rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-11 font-medium text-emerald-600 dark:text-emerald-400">
              Clean
            </span>
          )}
        </Td>
        <Td align="end">
          <Button
            variant="ghost"
            disabled={scanningPurl !== null}
            loading={scanningPurl === pkg.purl}
            onClick={() => void onScan(pkg)}
            className="h-7 px-2 text-11 text-accent hover:bg-accent/10 hover:text-accent"
            title={`Force on-demand vulnerability scan for ${pkg.name}`}
            aria-label={`Scan ${pkg.name}`}
          >
            <IconRefresh className="mr-1 size-3" />
            <span>{t('inventory.scanNow', { defaultValue: 'Scan Now' })}</span>
          </Button>
        </Td>
      </Tr>

      {isExpanded && (
        <Tr id={`pkg-cves-${pkgKey}`} className="border-b border-rule bg-surface-2/40">
          <Td colSpan={7} className="px-4 py-3">
            <PackageCVEsDrawer app={app} pkg={pkg} onSelectFinding={onSelectFinding} />
          </Td>
        </Tr>
      )}
    </>
  );
}

function PackageCVEsDrawer({
  app,
  pkg,
  onSelectFinding,
}: {
  app: ApplicationPage;
  pkg: AppPackage;
  onSelectFinding: (f: FindingDetailTarget) => void;
}) {
  const base = purlBase(pkg.purl);
  const qStr = `app:${app.slug || `"${app.name}"`} purl:"${base}"`;

  const query = useQuery({
    queryKey: ['findings', 'package', app.id, base],
    queryFn: () => listFindings({ q: qStr, sort: '-score', limit: 50 }),
    retry: false,
  });

  const findings = query.data?.items ?? [];

  return (
    <div className="rounded-md border border-border bg-surface p-3 shadow-sm">
      <div className="mb-2 flex items-center justify-between border-b border-border pb-2">
        <div className="flex items-center gap-2">
          <span className="text-12 font-semibold text-ink">
            Vulnerabilities in <span className="font-mono text-accent">{pkg.name}@{pkg.version}</span>
          </span>
          <span className="rounded bg-surface-2 px-1.5 py-0.5 text-11 font-mono text-ink-2">
            {pkg.vulnerabilities} reported
          </span>
        </div>
        <Link
          to="/findings"
          search={{ q: `app:${app.slug || `"${app.name}"`} purl:"${base}"` }}
          className="text-11 font-medium text-accent hover:underline"
        >
          View all in Findings Explorer →
        </Link>
      </div>

      {query.isLoading ? (
        <div className="flex h-16 items-center justify-center gap-2 text-12 text-ink-2">
          <Spinner />
          <span>Loading package CVE details...</span>
        </div>
      ) : query.isError ? (
        <ProblemMessage problem={toProblem(query.error)} title="Failed to query CVE findings for package" />
      ) : findings.length === 0 ? (
        <div className="flex flex-col gap-1 py-2 text-12 text-ink-2">
          <p className="m-0">
            {pkg.vulnerabilities} vulnerability finding{pkg.vulnerabilities > 1 ? 's are' : ' is'} recorded for this package.
          </p>
          <Link
            to="/findings"
            search={{ q: `purl:"${base}"` }}
            className="text-11 font-medium text-accent hover:underline"
          >
            Search matching findings across all assets →
          </Link>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-12">
            <thead>
              <tr className="border-b border-border/60 text-11 text-ink-2">
                <th className="py-1 font-medium">CVE / Vulnerability ID</th>
                <th className="py-1 font-medium">Severity</th>
                <th className="py-1 font-medium">Title & Summary</th>
                <th className="py-1 font-medium">Fixed Version</th>
                <th className="py-1 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {findings.map((item: FindingRow) => {
                const f = item.finding;
                const cveId = f.vulnerability_id || f.rule_id || f.id;
                const searchQ = f.vulnerability_id ? `cve:${f.vulnerability_id}` : (f.rule_id ? `rule:${f.rule_id}` : '');
                return (
                  <tr key={f.id} className="transition-colors hover:bg-surface-2/50">
                    <td className="py-2 pr-3 font-mono font-semibold text-ink">
                      <button
                        type="button"
                        onClick={() =>
                          onSelectFinding({
                            id: f.id,
                            vulnerability_id: f.vulnerability_id,
                            rule_id: f.rule_id,
                            title: f.title,
                            severity: f.severity,
                            risk_score: item.risk?.total_score ?? f.risk_score,
                            state: f.state,
                            asset: pkg.asset_name,
                            first_seen: f.first_seen,
                          })
                        }
                        className="text-left font-mono text-accent hover:underline"
                      >
                        {cveId}
                      </button>
                    </td>
                    <td className="py-2 pr-3">
                      <span className="inline-flex items-center gap-1.5 text-11">
                        <BandShape band={toBand(f.severity)} size={10} />
                        <span className="capitalize">{f.severity}</span>
                      </span>
                    </td>
                    <td className="max-w-xs truncate py-2 pr-3 text-ink-2" title={f.title}>
                      {f.title}
                    </td>
                    <td className="py-2 pr-3 font-mono text-11 text-ink-2">
                      {f.location?.fixed_version || '—'}
                    </td>
                    <td className="py-2 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Button
                          variant="secondary"
                          onClick={() =>
                            onSelectFinding({
                              id: f.id,
                              vulnerability_id: f.vulnerability_id,
                              rule_id: f.rule_id,
                              title: f.title,
                              severity: f.severity,
                              risk_score: item.risk?.total_score ?? f.risk_score,
                              state: f.state,
                              asset: pkg.asset_name,
                              first_seen: f.first_seen,
                            })
                          }
                          className="h-6 px-2 text-11"
                        >
                          Details
                        </Button>
                        <Link
                          to="/findings"
                          search={{
                            q: searchQ || undefined,
                            sel: f.id,
                          }}
                          className="text-11 font-medium text-accent hover:underline"
                          title="Open and filter directly in Findings Explorer"
                        >
                          Explorer →
                        </Link>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
