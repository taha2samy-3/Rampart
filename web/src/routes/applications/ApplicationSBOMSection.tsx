import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { get, post, toProblem } from '@/api';
import type { ApplicationPage } from '@/api/types';
import {
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

interface AppPackage {
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

export function ApplicationSBOMSection({ app }: { app: ApplicationPage }) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [scanningPurl, setScanningPurl] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<{ purl: string; message: string; ok: boolean } | null>(null);

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

  return (
    <section className="mt-8 border-t border-rule pt-6" aria-labelledby="app-sbom-section">
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
            search={{ q: `app:${app.slug || app.name} is:open` }}
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
              {filtered.map((pkg) => (
                <Tr key={`${pkg.asset_id ?? ''}|${pkg.track ?? ''}|${pkg.purl}`} className="h-11">
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
                      <Link
                        to="/findings"
                        search={{ q: `app:${app.slug || app.name} purl:"${purlBase(pkg.purl)}"` }}
                        className="inline-flex items-center gap-1 rounded border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-11 font-medium text-red-600 no-underline hover:underline dark:text-red-400"
                        title={`${pkg.vulnerabilities} open CVEs found in this package`}
                      >
                        ⚠️ {pkg.vulnerabilities} open CVE{pkg.vulnerabilities > 1 ? 's' : ''}
                      </Link>
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
                      onClick={() => void handleScan(pkg)}
                      className="h-7 px-2 text-11 text-accent hover:bg-accent/10 hover:text-accent"
                      title={`Force on-demand vulnerability scan for ${pkg.name}`}
                      aria-label={`Scan ${pkg.name}`}
                    >
                      <IconRefresh className="mr-1 size-3" />
                      <span>{t('inventory.scanNow', { defaultValue: 'Scan Now' })}</span>
                    </Button>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </div>
    </section>
  );
}
