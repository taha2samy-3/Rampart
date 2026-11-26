import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { get, ProblemError, toProblem } from '@/api';
import type { ApplicationPage } from '@/api/types';
import type { AppPackage } from './ApplicationSBOMSection';
import {
  EmptyState,
  Input,
  ProblemMessage,
  Select,
  Spinner,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
} from '@/components';
import { IconWarning } from '@/components/icons';
import { classifyLicenseRisk, type LicenseRisk } from '@/lib/license';

export { classifyLicenseRisk, type LicenseRisk };

export function LicenseRiskMark({ risk }: { risk: LicenseRisk }) {
  if (risk === 'copyleft') {
    return (
      <span className="inline-flex items-center gap-1.5 text-13 font-medium text-ink">
        <IconWarning className="size-3.5 shrink-0 text-high" role="img" aria-label="Copyleft licence" />
        Copyleft
      </span>
    );
  }
  return <span className="text-13 text-ink-2">{risk === 'permissive' ? 'Permissive' : 'Unknown'}</span>;
}

interface LicenseGroup {
  name: string;
  risk: LicenseRisk;
  packages: AppPackage[];
}

export function ApplicationLicensesSection({ app }: { app: ApplicationPage }) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<string>('all');
  const [selectedLicense, setSelectedLicense] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ['applications', app.id, 'components'],
    queryFn: async ({ signal }) => {
      try {
        const res = await get<{ components: AppPackage[] }>(
          `/api/v1/applications/${encodeURIComponent(app.id)}/components`,
          { signal }
        );
        return res.components ?? [];
      } catch (err: unknown) {
        if (err instanceof ProblemError && err.status === 404) {
          const res = await get<{ components: AppPackage[] }>(
            `/api/v1/inventory/components?limit=1000&application=${encodeURIComponent(app.id)}`,
            { signal }
          );
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

  const packages = useMemo(() => query.data ?? [], [query.data]);

  const licenseGroups = useMemo(() => {
    const map = new Map<string, AppPackage[]>();
    for (const p of packages) {
      const lic = (p.license && p.license.trim() !== '') ? p.license : 'Unknown';
      const arr = map.get(lic) ?? [];
      arr.push(p);
      map.set(lic, arr);
    }

    const groups: LicenseGroup[] = [];
    for (const [name, pkgs] of map.entries()) {
      groups.push({
        name,
        risk: classifyLicenseRisk(name),
        packages: pkgs,
      });
    }

    return groups.sort((a, b) => b.packages.length - a.packages.length);
  }, [packages]);

  const stats = useMemo(() => {
    let permissive = 0;
    let copyleft = 0;
    let unknown = 0;

    for (const g of licenseGroups) {
      if (g.risk === 'permissive') permissive += g.packages.length;
      else if (g.risk === 'copyleft') copyleft += g.packages.length;
      else unknown += g.packages.length;
    }

    return {
      totalLicenses: licenseGroups.length,
      totalPackages: packages.length,
      permissive,
      copyleft,
      unknown,
    };
  }, [licenseGroups, packages.length]);

  const filteredGroups = useMemo(() => {
    let list = licenseGroups;
    if (riskFilter !== 'all') {
      list = list.filter((g) => g.risk === riskFilter);
    }
    if (search.trim() !== '') {
      const q = search.toLowerCase();
      list = list.filter(
        (g) =>
          g.name.toLowerCase().includes(q) ||
          g.packages.some(
            (p) =>
              p.name.toLowerCase().includes(q) ||
              (p.purl && p.purl.toLowerCase().includes(q))
          )
      );
    }
    return list;
  }, [licenseGroups, riskFilter, search]);

  const activeGroup = useMemo(() => {
    if (!selectedLicense) return null;
    return licenseGroups.find((g) => g.name === selectedLicense) ?? null;
  }, [licenseGroups, selectedLicense]);

  if (query.isPending) {
    return (
      <div className="flex h-48 items-center justify-center">
        <Spinner size={24} />
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="py-4">
        <ProblemMessage
          problem={toProblem(query.error)}
          title={t('apps.sbomLoadFailed', { defaultValue: 'Failed to load license inventory' })}
          onRetry={() => void query.refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6 pt-2">
      {/* Metric Cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-ctl border border-rule bg-surface p-3.5">
          <span className="text-12 font-medium text-ink-2">Total Packages</span>
          <p className="mt-1 text-20 font-semibold text-ink">{stats.totalPackages}</p>
        </div>
        <div className="rounded-ctl border border-rule bg-surface p-3.5">
          <span className="text-12 font-medium text-ink-2">Unique Licenses</span>
          <p className="mt-1 text-20 font-semibold text-ink">{stats.totalLicenses}</p>
        </div>
        <div className="rounded-ctl border border-rule bg-surface p-3.5">
          <span className="text-12 font-medium text-ink-2">Permissive</span>
          <p className="mt-1 text-20 font-semibold text-ink">
            {stats.permissive} <span className="text-12 font-normal text-ink-2">pkgs</span>
          </p>
        </div>
        <div className="rounded-ctl border border-rule bg-surface p-3.5">
          <span className="text-12 font-medium text-ink-2">Copyleft / Restricted</span>
          <p className="mt-1 text-20 font-semibold text-ink">
            {stats.copyleft} <span className="text-12 font-normal text-ink-2">pkgs</span>
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="w-full sm:w-72">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search license or package..."
          />
        </div>
        <div className="flex items-center gap-2">
          <Select
            label="License Risk Filter"
            value={riskFilter}
            onValueChange={(val) => setRiskFilter(val)}
            options={[
              { value: 'all', label: 'All Risk Levels' },
              { value: 'permissive', label: 'Permissive (Low Risk)' },
              { value: 'copyleft', label: 'Copyleft (High / Viral Risk)' },
              { value: 'unknown', label: 'Unknown / Unspecified' },
            ]}
          />
        </div>
      </div>

      {filteredGroups.length === 0 ? (
        <EmptyState
          title="No licenses found"
        >
          {packages.length === 0
            ? 'No packages or SBOM components have been uploaded for this application yet.'
            : 'No licenses matched your filter criteria.'}
        </EmptyState>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Licenses Summary Table */}
          <div className={activeGroup ? 'lg:col-span-7' : 'lg:col-span-12'}>
            <div className="overflow-hidden rounded-ctl border border-rule bg-surface">
              <Table>
                <THead>
                  <Tr>
                    <Th>License</Th>
                    <Th>Risk Category</Th>
                    <Th align="end">Packages</Th>
                    <Th align="end">Action</Th>
                  </Tr>
                </THead>
                <TBody>
                  {filteredGroups.map((group) => {
                    const isSelected = selectedLicense === group.name;
                    return (
                      <Tr
                        key={group.name}
                        className={isSelected ? 'bg-chrome' : undefined}
                      >
                        <Td className="font-mono text-13 font-semibold text-ink">
                          {group.name}
                        </Td>
                        <Td>
                          <LicenseRiskMark risk={group.risk} />
                        </Td>
                        <Td align="end" className="text-13 text-ink">
                          {group.packages.length}
                        </Td>
                        <Td align="end">
                          <button
                            type="button"
                            onClick={() =>
                              setSelectedLicense(isSelected ? null : group.name)
                            }
                            className="text-12 font-medium text-accent hover:underline"
                          >
                            {isSelected ? 'Hide Packages' : 'View Packages'}
                          </button>
                        </Td>
                      </Tr>
                    );
                  })}
                </TBody>
              </Table>
            </div>
          </div>

          {/* Drill-down Package Drawer/Panel */}
          {activeGroup && (
            <div className="lg:col-span-5">
              <div className="rounded-ctl border border-rule bg-surface p-4">
                <div className="mb-3 flex items-center justify-between border-b border-rule pb-3">
                  <div>
                    <h3 className="text-14 font-semibold text-ink">{activeGroup.name}</h3>
                    <p className="text-12 text-ink-2">
                      {activeGroup.packages.length} package
                      {activeGroup.packages.length === 1 ? '' : 's'} using this license
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setSelectedLicense(null)}
                    className="text-12 text-ink-2 hover:text-ink"
                  >
                    Close
                  </button>
                </div>

                <div className="max-h-[32rem] space-y-2.5 overflow-y-auto pr-1">
                  {activeGroup.packages.map((pkg, idx) => (
                    <div
                      key={pkg.purl || `${pkg.name}@${pkg.version}-${idx}`}
                      className="rounded-ctl border border-rule/60 bg-chrome p-2.5 text-12"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-ink">{pkg.name}</span>
                        <span className="font-mono text-12 text-ink-2">{pkg.version}</span>
                      </div>
                      {pkg.purl && (
                        <p className="mt-1 truncate font-mono text-12 text-ink-2" title={pkg.purl}>
                          {pkg.purl}
                        </p>
                      )}
                      <div className="mt-2 flex items-center justify-between text-12 text-ink-2">
                        <span>{pkg.type || 'library'}</span>
                        {pkg.vulnerabilities > 0 ? (
                          <span className="font-medium text-critical">
                            {pkg.vulnerabilities} CVE{pkg.vulnerabilities === 1 ? '' : 's'}
                          </span>
                        ) : (
                          <span className="text-ink-2">No known CVEs</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
