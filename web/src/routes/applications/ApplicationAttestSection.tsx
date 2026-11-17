import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getApplicationCompliance, listTaxonomies, qk, toProblem } from '@/api';
import type { ApplicationPage, ControlStatus } from '@/api/types';
import {
  Button,
  EmptyState,
  ProblemMessage,
  Skeleton,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
} from '@/components';
import { AttestDialog } from '../compliance/ComplianceRoute';
import { absoluteDate } from '@/lib/format';

export function ApplicationAttestSection({ app }: { app: ApplicationPage }) {
  const { t } = useTranslation();
  const [attestingControl, setAttestingControl] = useState<{ framework: string; control: ControlStatus } | null>(null);

  const complianceQuery = useQuery({
    queryKey: qk.applications.compliance(app.id),
    queryFn: ({ signal }) => getApplicationCompliance(app.id, signal),
  });

  const taxonomiesQuery = useQuery({
    queryKey: qk.taxonomies(),
    queryFn: ({ signal }) => listTaxonomies(signal),
  });

  const frameworks = complianceQuery.data?.frameworks ?? [];
  const taxonomies = taxonomiesQuery.data ?? [];

  // Default framework to use when opening general attestation
  const defaultFramework = taxonomies[0]?.id || frameworks[0]?.id || 'soc2-type2';

  const handleOpenGeneralAttestation = () => {
    setAttestingControl({
      framework: defaultFramework,
      control: {
        id: 'SEC-REVIEW',
        name: `${app.name} Application Security Review`,
        status: 'not_assessed',
        open: 0,
        bands: { critical: 0, high: 0, medium: 0, low: 0 },
        manual: true,
      },
    });
  };

  return (
    <section className="mt-8 border-t border-rule pt-6" aria-labelledby="app-attest-section">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 id="app-attest-section" className="text-16 font-semibold text-ink">
            Compliance Attestations (Attest)
          </h2>
          <p className="m-0 text-12 text-ink-2">
            Record, sign, and review human-verified security attestations, threat model sign-offs, and compliance evidence for this application.
          </p>
        </div>
        <Button
          variant="primary"
          onClick={handleOpenGeneralAttestation}
          className="h-8 px-3 text-12 whitespace-nowrap self-start sm:self-auto"
        >
          {t('compliance.attest', { defaultValue: 'Record Attestation' })}
        </Button>
      </div>

      <div className="mt-4">
        {complianceQuery.isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : complianceQuery.isError ? (
          <ProblemMessage problem={toProblem(complianceQuery.error)} title="Failed to load compliance status" onRetry={() => void complianceQuery.refetch()} />
        ) : frameworks.length === 0 ? (
          <EmptyState title="No compliance frameworks in scope">
            Configure compliance frameworks or assign compliance scopes in Administration to track automated and manual controls for this application.
          </EmptyState>
        ) : (
          <div className="flex flex-col gap-3">
            <Table aria-label="Application compliance frameworks table">
              <THead>
                <tr>
                  <Th>Framework / Standard</Th>
                  <Th>Status</Th>
                  <Th>Controls Evaluated</Th>
                  <Th>Earliest Deadline</Th>
                  <Th align="end">Actions</Th>
                </tr>
              </THead>
              <TBody>
                {frameworks.map((fw) => (
                  <Tr key={fw.id} className="h-11">
                    <Td className="font-medium text-ink">
                      <div className="flex flex-col">
                        <span>{fw.name}</span>
                        <span className="text-11 text-ink-2 font-mono">{fw.id}</span>
                      </div>
                    </Td>
                    <Td>
                      <span
                        className={`inline-flex items-center rounded px-2 py-0.5 text-11 font-medium capitalize ${
                          fw.verdict === 'meets'
                            ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20'
                            : fw.verdict === 'gaps'
                              ? 'bg-red-500/10 text-red-700 dark:text-red-400 border border-red-500/20'
                              : 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20'
                        }`}
                      >
                        {fw.verdict.replace('_', ' ')}
                      </span>
                    </Td>
                    <Td className="text-12 text-ink-2">
                      {fw.clear} / {fw.controls} clear
                      {fw.open > 0 && <span className="text-red-600 dark:text-red-400 font-medium ml-1">({fw.open} open)</span>}
                    </Td>
                    <Td className="text-12 text-ink-2">
                      {fw.earliest_due ? absoluteDate(fw.earliest_due) : '—'}
                    </Td>
                    <Td align="end">
                      <Button
                        variant="ghost"
                        onClick={() =>
                          setAttestingControl({
                            framework: fw.id,
                            control: {
                              id: `${fw.id}-APP-ATTEST`,
                              name: `${app.name} - ${fw.name} Compliance Sign-off`,
                              status: 'not_assessed',
                              open: fw.open,
                              bands: { critical: 0, high: 0, medium: 0, low: 0 },
                              manual: true,
                            },
                          })
                        }
                        className="h-7 px-2.5 text-11 text-accent hover:bg-accent/10 hover:text-accent"
                      >
                        {t('compliance.attest', { defaultValue: 'Attest' })}
                      </Button>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </div>
        )}
      </div>

      {attestingControl && (
        <AttestDialog
          framework={attestingControl.framework}
          control={attestingControl.control}
          application={app.id}
          onClose={() => setAttestingControl(null)}
        />
      )}
    </section>
  );
}
