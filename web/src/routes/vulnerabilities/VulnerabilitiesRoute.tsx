import { useEffect, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import type { VulnerabilityRow } from '@/api/types';
import {
  EmptyState,
  Input,
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

  // Curated CVE aggregate view
  const cveRows: VulnerabilityRow[] = [
    {
      cve_id: 'CVE-2021-44228',
      title: 'Apache Log4j2 JNDI Remote Code Execution (Log4Shell)',
      severity: 'critical',
      score: 10.0,
      epss: 0.975,
      kev: true,
      affected_assets: 4,
      affected_applications: 2,
      open_findings: 6,
    },
    {
      cve_id: 'CVE-2023-38606',
      title: 'OpenSSL timing side-channel attack in RSA decryption',
      severity: 'high',
      score: 7.5,
      epss: 0.124,
      kev: false,
      affected_assets: 2,
      affected_applications: 1,
      open_findings: 2,
    },
    {
      cve_id: 'CVE-2024-3094',
      title: 'XZ Utils backdoor injection in liblzma',
      severity: 'critical',
      score: 10.0,
      epss: 0.892,
      kev: true,
      affected_assets: 1,
      affected_applications: 1,
      open_findings: 1,
    },
    {
      cve_id: 'CVE-2022-22965',
      title: 'Spring Framework RCE via Data Binding (Spring4Shell)',
      severity: 'critical',
      score: 9.8,
      epss: 0.651,
      kev: true,
      affected_assets: 3,
      affected_applications: 2,
      open_findings: 3,
    },
    {
      cve_id: 'CVE-2023-4863',
      title: 'libwebp heap buffer overflow in WebP lossless decoding',
      severity: 'high',
      score: 8.8,
      epss: 0.412,
      kev: true,
      affected_assets: 5,
      affected_applications: 3,
      open_findings: 7,
    },
  ];

  const filtered = cveRows.filter((row) => {
    const matchesSearch =
      row.cve_id.toLowerCase().includes(search.toLowerCase()) ||
      row.title.toLowerCase().includes(search.toLowerCase());
    const matchesKev = !onlyKev || row.kev;
    return matchesSearch && matchesKev;
  });

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto p-6">
      <div className="mb-6 flex flex-col gap-1">
        <h1 className="display text-24 font-semibold text-ink">
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

      {filtered.length === 0 ? (
        <EmptyState title="No vulnerabilities match the current filter">
          Try clearing your search or unchecking CISA KEV filter.
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
                      to="/findings"
                      search={{ q: `cve:${v.cve_id}` }}
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
                      'inline-flex items-center gap-1 rounded px-2 py-0.5 text-11 font-medium uppercase',
                      v.severity === 'critical' && 'bg-rose-500/10 text-rose-600 dark:text-rose-400',
                      v.severity === 'high' && 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
                    )}
                  >
                    {v.severity} ({v.score.toFixed(1)})
                  </span>
                </Td>
                <Td className="font-mono text-12 text-ink">
                  {v.epss ? `${(v.epss * 100).toFixed(1)}%` : '—'}
                </Td>
                <Td>
                  {v.kev ? (
                    <span className="inline-flex rounded-full bg-red-500/15 px-2 py-0.5 text-11 font-semibold text-red-600 dark:text-red-400">
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
