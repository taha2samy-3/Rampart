import { useState } from 'react';
import { locationOf } from '@/lib/location';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { get, listFindings, post, toProblem, ProblemError } from '@/api';
import { useAccess } from '@/app/useAccess';
import type { ApplicationPage, FindingRow } from '@/api/types';
import {
  BandShape,
  Button,
  EmptyState,
  IconChevronDown,
  IconRefresh,
  Input,
  Menu,
  MenuContent,
  MenuItem,
  MenuLabel,
  MenuSeparator,
  MenuTrigger,
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
  const [refreshing, setRefreshing] = useState(false);
  const { can } = useAccess();
  const mayTriage = can(app.id, 'triager'); // both buttons need the triage right the API checks
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
      } catch (err: unknown) {
        // Fallback to tenant inventory filtered by application name on 404 only
        if (err instanceof ProblemError && err.status === 404) {
          const res = await get<{ components: AppPackage[] }>(`/api/v1/inventory/components?limit=1000&application=${encodeURIComponent(app.id)}`, { signal });
          return (res.components ?? []).filter(
            (c) =>
              c.application_name &&
              (c.application_name.toLowerCase() === app.name.toLowerCase() ||
                (app.slug && c.application_name.toLowerCase() === app.slug.toLowerCase()))
          );
        }
        throw err;
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

  // The application's vulnerabilities come from Dependency-Track, per project: sync it now.
  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      const res = await post<{ message: string; projects: number }>(`/api/v1/applications/${encodeURIComponent(app.id)}/refresh-vulnerabilities`, {});
      setScanStatus({ purl: '', message: `${res.message} (${res.projects} ${res.projects === 1 ? 'project' : 'projects'}). The list updates when the sync ends.`, ok: true });
      window.setTimeout(() => void query.refetch(), 4000);
    } catch (err) {
      setScanStatus({ purl: '', message: toProblem(err).detail || 'The refresh could not be started.', ok: false });
    } finally {
      setRefreshing(false);
    }
  };

  const appQuerySlug = app.slug || `"${app.name}"`;

  return (
    <section aria-labelledby="app-sbom-section">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 id="app-sbom-section" className="text-16 font-semibold text-ink">
            Software Bill of Materials (SBOM) & Packages
          </h2>
          <p className="m-0 text-12 text-ink-2">
            Dependencies and packages ingested for this application. Review packages affected by CVEs or download standardized SBOM manifests.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {mayTriage && (
            <Button
              variant="secondary"
              loading={refreshing}
              disabled={refreshing}
              onClick={() => void handleRefresh()}
              className="h-8 gap-1.5 px-3 text-12 font-medium"
              title="Pull the vulnerabilities of this application's Dependency-Track projects now"
            >
              <IconRefresh className="size-3" />
              <span>Refresh from Dependency-Track</span>
            </Button>
          )}
          <Menu>
            <MenuTrigger asChild>
              <Button variant="secondary" className="h-8 gap-1.5 px-3 text-12 font-medium">
                <span>Export manifests</span>
                <IconChevronDown width={12} height={12} className="opacity-70" />
              </Button>
            </MenuTrigger>
            <MenuContent align="end" className="w-56">
              <MenuLabel>Software Bill of Materials (SBOM)</MenuLabel>
              <MenuItem asChild>
                <a
                  href={`/api/v1/applications/${encodeURIComponent(app.id)}/sbom?format=cyclonedx`}
                  download={`${app.slug || 'application'}-sbom-cyclonedx.json`}
                  className="flex items-center justify-between text-12 text-ink no-underline hover:text-accent"
                >
                  <span>CycloneDX SBOM</span>
                  <span className="font-mono text-12 text-ink-2">JSON</span>
                </a>
              </MenuItem>
              <MenuItem asChild>
                <a
                  href={`/api/v1/applications/${encodeURIComponent(app.id)}/sbom?format=spdx`}
                  download={`${app.slug || 'application'}-sbom-spdx.json`}
                  className="flex items-center justify-between text-12 text-ink no-underline hover:text-accent"
                >
                  <span>SPDX SBOM</span>
                  <span className="font-mono text-12 text-ink-2">JSON</span>
                </a>
              </MenuItem>
              <MenuSeparator />
              <MenuLabel>VEX Advisories</MenuLabel>
              <MenuItem asChild>
                <a
                  href={`/api/v1/applications/${encodeURIComponent(app.id)}/vex?format=cyclonedx`}
                  download={`${app.slug || 'application'}-vex-cyclonedx.json`}
                  className="flex items-center justify-between text-12 text-ink no-underline hover:text-accent"
                >
                  <span>CycloneDX VEX</span>
                  <span className="font-mono text-12 text-ink-2">JSON</span>
                </a>
              </MenuItem>
              <MenuItem asChild>
                <a
                  href={`/api/v1/applications/${encodeURIComponent(app.id)}/vex?format=openvex`}
                  download={`${app.slug || 'application'}-openvex.json`}
                  className="flex items-center justify-between text-12 text-ink no-underline hover:text-accent"
                >
                  <span>OpenVEX</span>
                  <span className="font-mono text-12 text-ink-2">JSON</span>
                </a>
              </MenuItem>
            </MenuContent>
          </Menu>
        </div>
      </div>

      {scanStatus && (
        <div
          role="status"
          className={`mt-3 flex items-center justify-between rounded-ctl border px-3 py-2 text-12 font-medium ${
            scanStatus.ok
              ? 'border-resolved/20 bg-resolved/10 text-resolved'
              : 'border-critical/20 bg-critical/10 text-critical'
          }`}
        >
          <span>{scanStatus.message}</span>
          <button
            type="button"
            onClick={() => setScanStatus(null)}
            className="ml-2 text-12 opacity-70 hover:opacity-100"
            aria-label="Dismiss scan status"
          >
            ✕
          </button>
        </div>
      )}

      {vulnPackages.length > 0 && (
        <div className="mt-3 flex items-center justify-between border-b border-rule pb-2 text-13">
          <p className="m-0 text-ink">
            <span className="font-semibold text-critical">
              {vulnPackages.length} package{vulnPackages.length > 1 ? 's' : ''} in this application {vulnPackages.length > 1 ? 'have' : 'has'} active CVEs.
            </span>
          </p>
          <Link
            to="/findings"
            search={{ q: `app:${appQuerySlug} state:open,under_investigation,affected` }}
            className="text-12 font-medium text-accent hover:underline"
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
            <span className="max-w-xs truncate text-12 text-ink-2" title={pkg.purl}>
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
        <Td className="text-12 text-ink-2">
          {pkg.license && pkg.license.trim() !== '' ? (
            <span
              className={`inline-flex items-center rounded px-2 py-0.5 text-12 font-medium ${
                pkg.license.toLowerCase().includes('gpl') ||
                pkg.license.toLowerCase().includes('agpl') ||
                pkg.license.toLowerCase().includes('lgpl') ||
                pkg.license.toLowerCase().includes('mpl')
                  ? 'bg-high text-high border border-high'
                  : 'bg-resolved text-resolved border border-resolved'
              }`}
            >
              {pkg.license}
            </span>
          ) : (
            <span className="text-12 text-ink-3">Unknown</span>
          )}
        </Td>
        <Td align="end">
          {pkg.vulnerabilities > 0 ? (
            <div className="inline-flex items-center gap-1.5">
              <Link
                to="/findings"
                search={{ q: `app:${app.slug || `"${app.name}"`} purl:"${purlBase(pkg.purl)}"` }}
                className="inline-flex items-center gap-1 rounded border border-critical/20 bg-critical/10 px-2 py-0.5 text-12 font-medium text-critical no-underline hover:underline"
                title={`${pkg.vulnerabilities} open CVEs found in this package`}
              >
                ⚠️ {pkg.vulnerabilities} open CVE{pkg.vulnerabilities > 1 ? 's' : ''}
              </Link>
              <button
                type="button"
                onClick={onToggleExpand}
                aria-expanded={isExpanded}
                aria-controls={`pkg-cves-${pkgKey}`}
                className="inline-flex h-6 w-6 items-center justify-center rounded border border-critical/30 bg-critical/15 text-12 font-bold text-critical transition-colors hover:bg-critical/25"
                title={isExpanded ? 'Collapse CVE list' : 'Expand CVE list'}
                aria-label={isExpanded ? `Collapse CVEs for ${pkg.name}` : `Expand CVEs for ${pkg.name}`}
              >
                <span aria-hidden="true">{isExpanded ? '▲' : '▼'}</span>
              </button>
            </div>
          ) : (
            <span className="inline-flex items-center gap-1 rounded border border-resolved/20 bg-resolved/10 px-2 py-0.5 text-12 font-medium text-resolved">
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
            className="h-7 px-2 text-12 text-accent hover:bg-accent/10 hover:text-accent"
            title={t('inventory.scanNowTooltip', { name: pkg.name })}
            aria-label={`Re-evaluate ${pkg.name}`}
          >
            <IconRefresh className="mr-1 size-3" />
            <span>{t('inventory.scanNow')}</span>
          </Button>
        </Td>
      </Tr>

      {isExpanded && (
        <Tr id={`pkg-cves-${pkgKey}`} className="border-b border-rule bg-chrome/40">
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
    <div className="rounded-ctl border border-rule bg-surface p-3">
      <div className="mb-2 flex items-center justify-between border-b border-rule pb-2">
        <div className="flex items-center gap-2">
          <span className="text-12 font-semibold text-ink">
            Vulnerabilities in <span className="font-mono text-accent">{pkg.name}@{pkg.version}</span>
          </span>
          <span className="rounded bg-chrome px-1.5 py-0.5 text-12 font-mono text-ink-2">
            {pkg.vulnerabilities} reported
          </span>
        </div>
        <Link
          to="/findings"
          search={{ q: `app:${app.slug || `"${app.name}"`} purl:"${base}"` }}
          className="text-12 font-medium text-accent hover:underline"
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
            className="text-12 font-medium text-accent hover:underline"
          >
            Search matching findings across all assets →
          </Link>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-12">
            <thead>
              <tr className="border-b border-rule/60 text-12 text-ink-2">
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
                const searchQ = f.vulnerability_id ? `cve:${f.vulnerability_id}` : (f.rule_id ? `rule:${f.rule_id}` : `id:${f.id}`);
                return (
                  <tr key={f.id} className="transition-colors hover:bg-chrome/50">
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
                      <span className="inline-flex items-center gap-1.5 text-12">
                        <BandShape band={toBand(f.severity)} size={10} />
                        <span className="capitalize">{f.severity}</span>
                      </span>
                    </td>
                    <td className="max-w-xs truncate py-2 pr-3 text-ink-2" title={f.title}>
                      {f.title}
                    </td>
                    <td className="py-2 pr-3 font-mono text-12 text-ink-2">
                      {locationOf(f.location).fixed_version || '—'}
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
                          className="h-6 px-2 text-12"
                        >
                          Details
                        </Button>
                        <Link
                          to="/findings"
                          search={{
                            q: searchQ || undefined,
                            sel: f.id,
                          }}
                          className="text-12 font-medium text-accent hover:underline"
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
