import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
} from '@/components';

export function PoliciesRoute() {
  const { t } = useTranslation();

  useEffect(() => {
    document.title = `${t('nav.policies', { defaultValue: 'Policies' })} - Rampart`;
  }, [t]);

  const slaRules = [
    { severity: 'Critical', breachDays: '7 days', graceDays: '2 days', notifyChannels: 'Jira + Slack + In-App' },
    { severity: 'High', breachDays: '30 days', graceDays: '5 days', notifyChannels: 'Slack + In-App' },
    { severity: 'Medium', breachDays: '90 days', graceDays: '14 days', notifyChannels: 'In-App' },
    { severity: 'Low', breachDays: '180 days', graceDays: '30 days', notifyChannels: 'In-App' },
  ];

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto p-6">
      <div className="mb-6 flex flex-col gap-1">
        <h1 className="display text-20 font-semibold text-ink">
          {t('nav.policies', { defaultValue: 'Security & Remediation Policies' })}
        </h1>
        <p className="text-13 text-ink-2">
          {t('policies.subtitle', { defaultValue: 'Governing SLA breach targets, automated issue tracking rules, and mass-close safety guard limits.' })}
        </p>
      </div>

      <div className="flex flex-col gap-8 max-w-4xl">
        {/* SLA Policy Section */}
        <section className="flex flex-col gap-3">
          <div className="border-b border-rule pb-2">
            <h2 className="text-14 font-semibold text-ink">Service Level Agreement (SLA) Targets</h2>
            <p className="text-12 text-ink-2">Standard remediation deadlines enforced across all applications and asset scans.</p>
          </div>
          <Table aria-label="SLA policies table">
            <THead>
              <tr>
                <Th>Severity Band</Th>
                <Th>Breach Target (Max Days)</Th>
                <Th>Grace Period</Th>
                <Th align="end">Escalation Routing</Th>
              </tr>
            </THead>
            <TBody>
              {slaRules.map((rule) => (
                <Tr key={rule.severity} className="h-11">
                  <Td className="font-semibold text-ink">{rule.severity}</Td>
                  <Td className="font-mono text-12 text-ink">{rule.breachDays}</Td>
                  <Td className="text-12 text-ink-2">{rule.graceDays}</Td>
                  <Td align="end" className="text-12 text-ink-2">{rule.notifyChannels}</Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        </section>

        {/* Ticketing Policy Section */}
        <section className="flex flex-col gap-3">
          <div className="border-b border-rule pb-2">
            <h2 className="text-14 font-semibold text-ink">Automated Ticketing & Issue Dispatch Policy</h2>
            <p className="text-12 text-ink-2">Rules governing when and how Rampart automatically creates tracker tickets in Jira or GitHub.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="rounded-ctl border border-rule bg-surface p-4 flex flex-col gap-2">
              <span className="text-13 font-semibold text-ink">Automatic Issue Creation on Critical</span>
              <p className="text-12 text-ink-2">
                Every newly discovered active Critical finding automatically opens a ticket on the configured tracker with state bound to policy.
              </p>
              <span className="text-12 font-mono text-resolved font-medium">Status: Active (onCritical: true)</span>
            </div>

            <div className="rounded-ctl border border-rule bg-surface p-4 flex flex-col gap-2">
              <span className="text-13 font-semibold text-ink">Hourly Rate Limiting & Fair Cap</span>
              <p className="text-12 text-ink-2">
                Prevents tracker API exhaustion by enforcing dynamic connector caps (default 100 tickets/hour) and fair round-robin scheduling.
              </p>
              <span className="text-12 font-mono text-accent font-medium">Limit: 100 requests / hour / connector</span>
            </div>
          </div>
        </section>

        {/* Mass-Close Guard Section */}
        <section className="flex flex-col gap-3">
          <div className="border-b border-rule pb-2">
            <h2 className="text-14 font-semibold text-ink">Mass-Close Safety Guard (D22 / D71)</h2>
            <p className="text-12 text-ink-2">Prevents catastrophic false-positive closures when scanners fail or return partial empty payloads.</p>
          </div>
          <div className="rounded-ctl border border-rule bg-surface p-4 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-13 font-semibold text-ink">Close Guard Trigger Threshold</span>
              <span className="font-mono text-12 font-medium text-ink">maxClosePercent: 20%</span>
            </div>
            <p className="text-12 text-ink-2">
              If an incoming scan report omits more than 20% of previously active findings for its scanner family, Rampart places the closures on hold as a <code>Held Close</code> requiring maintainer approval in the Workflow tab before closing findings.
            </p>
          </div>
        </section>
      </div>
    </div>
  );
}
