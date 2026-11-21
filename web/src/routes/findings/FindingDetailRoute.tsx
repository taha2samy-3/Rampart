import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { getFinding, getFindingControls, getFindingEvents, qk, toProblem } from '@/api';
import {
  Button,
  EmptyState,
  ProblemMessage,
  Spinner,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components';
import { ScannerEvidenceSection } from '@/features/finding-inspector/ScannerEvidenceSection';
import { AcceptanceDialog } from '@/features/acceptance/AcceptanceDialog';
import { TriageDialog } from '@/features/triage/TriageDialog';
import { EditDialog } from '@/features/triage/EditDialog';
import { useAccess } from '@/app/useAccess';
import { locationOf, whereText } from '@/lib/location';
import { absoluteDate, absoluteDateTime, sinceShort } from '@/lib/format';
import { cn } from '@/lib/cn';

interface FindingDetailRouteProps {
  id: string;
}

type FindingTab = 'evidence' | 'technical' | 'risk' | 'compliance' | 'timeline' | 'raw';

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-danger/15 text-danger border-danger/30',
  high: 'bg-warning/15 text-warning border-warning/30',
  medium: 'bg-accent/15 text-accent border-accent/30',
  low: 'bg-ink-2/15 text-ink-2 border-ink-2/30',
  info: 'bg-ink-3/15 text-ink-3 border-ink-3/30',
};

const STATE_STYLES: Record<string, string> = {
  open: 'bg-danger/10 text-danger border-danger/20',
  under_investigation: 'bg-warning/10 text-warning border-warning/20',
  fixed: 'bg-success/10 text-success border-success/20',
  risk_accepted: 'bg-accent/10 text-accent border-accent/20',
  out_of_scope: 'bg-ink-2/10 text-ink-2 border-ink-2/20',
  duplicate: 'bg-ink-2/10 text-ink-2 border-ink-2/20',
};

export function FindingDetailRoute({ id }: FindingDetailRouteProps) {
  const { t } = useTranslation();
  const [activeTab, setActiveTab] = useState<FindingTab>('evidence');
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [triageOpen, setTriageOpen] = useState(false);
  const [acceptOpen, setAcceptOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);

  const { can } = useAccess();
  const cleanId = id.trim();

  const q = useQuery({
    queryKey: qk.findings.one(cleanId),
    queryFn: ({ signal }) => getFinding(cleanId, signal),
  });

  const controlsQuery = useQuery({
    queryKey: qk.findings.controls(cleanId),
    queryFn: ({ signal }) => getFindingControls(cleanId, signal),
    enabled: !!q.data,
  });

  const eventsQuery = useQuery({
    queryKey: qk.findings.events(cleanId),
    queryFn: ({ signal }) => getFindingEvents(cleanId, signal),
    enabled: !!q.data,
  });

  const row = q.data;
  const f = row?.finding;
  const risk = row?.risk;

  useEffect(() => {
    if (f?.title) {
      document.title = `${f.title} - Finding Details - Rampart`;
    }
  }, [f?.title]);

  if (q.isPending) {
    return (
      <main className="mx-auto flex max-w-6xl items-center justify-center p-16">
        <div className="flex items-center gap-3 text-ink-2">
          <Spinner size={24} />
          <span>{t('common.loading', { defaultValue: 'Loading finding details...' })}</span>
        </div>
      </main>
    );
  }

  if (q.isError) {
    return (
      <main className="mx-auto max-w-4xl p-8">
        <Link to="/findings" className="mb-4 inline-flex items-center gap-1.5 text-13 font-medium text-accent hover:underline">
          ← {t('nav.findings', { defaultValue: 'Back to Findings' })}
        </Link>
        <ProblemMessage
          problem={toProblem(q.error)}
          title="Could not load finding details"
          onRetry={() => void q.refetch()}
        />
      </main>
    );
  }

  if (!row || !f) {
    return (
      <main className="mx-auto max-w-4xl p-8">
        <Link to="/findings" className="mb-4 inline-flex items-center gap-1.5 text-13 font-medium text-accent hover:underline">
          ← {t('nav.findings', { defaultValue: 'Back to Findings' })}
        </Link>
        <EmptyState title="Finding not found">
          No security finding exists with identifier {cleanId}. It may have been closed or removed.
        </EmptyState>
      </main>
    );
  }

  const sev = (f.severity || 'medium').toLowerCase();
  const state = (f.state || 'open').toLowerCase();
  const loc = locationOf(f.location);
  const where = whereText(loc);
  const canTriage = can(f.application_id, 'triager');

  const rawFindingJson = JSON.stringify(row, null, 2);

  return (
    <main className="mx-auto max-w-6xl p-6 md:p-8">
      {/* Breadcrumb Navigation */}
      <div className="mb-4 flex items-center justify-between text-13">
        <Link
          to="/findings"
          className="inline-flex items-center gap-1.5 font-medium text-accent hover:underline"
        >
          ← {t('nav.findings', { defaultValue: 'Back to Findings' })}
        </Link>
        <span className="font-mono text-12 text-ink-3">ID: {f.id}</span>
      </div>

      {/* Hero Header */}
      <div className="rounded-lg border border-rule bg-layer-1 p-6 shadow-xs">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div className="min-w-0 flex-1">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              {f.category && (
                <span className="rounded bg-chrome px-2 py-0.5 text-11 font-medium tracking-wide uppercase text-ink-2">
                  {f.category}
                </span>
              )}
              <span className={cn('rounded border px-2 py-0.5 text-11 font-semibold uppercase', SEVERITY_STYLES[sev] || SEVERITY_STYLES.medium)}>
                {f.severity || 'Medium'}
              </span>
              <span className={cn('rounded border px-2 py-0.5 text-11 font-medium capitalize', STATE_STYLES[state] || STATE_STYLES.open)}>
                {t(`state.${state}`, { defaultValue: state.replace(/_/g, ' ') })}
              </span>
              {f.justification && (
                <span className="rounded border border-resolved/30 bg-resolved/10 px-2 py-0.5 text-11 font-medium text-resolved" title={`VEX Justification: ${f.justification}`}>
                  VEX: {f.justification.replace(/_/g, ' ')}
                </span>
              )}
              {risk && (
                <span className="rounded bg-accent/10 px-2 py-0.5 text-11 font-semibold text-accent">
                  Risk Score: {risk.total_score} / 1000
                </span>
              )}
              {row.sla_due_date && (
                <span className="rounded bg-chrome px-2 py-0.5 text-11 text-ink-2">
                  SLA: {absoluteDate(row.sla_due_date)} ({sinceShort(row.sla_due_date)})
                </span>
              )}
            </div>

            <h1 className="m-0 text-22 font-bold tracking-tight text-ink md:text-24">
              {f.title}
            </h1>

            {f.description && (
              <p className="mt-2.5 mb-0 text-13 leading-relaxed text-ink-2 whitespace-pre-wrap">
                {f.description}
              </p>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex shrink-0 flex-wrap items-center gap-2 pt-1">
            {canTriage && (
              <>
                <Button variant="secondary" onClick={() => setTriageOpen(true)}>
                  Change State
                </Button>
                <Button variant="secondary" onClick={() => setEditOpen(true)}>
                  Edit
                </Button>
                <Button variant="secondary" onClick={() => setAcceptOpen(true)}>
                  Risk Acceptance
                </Button>
              </>
            )}
          </div>
        </div>

        {/* Fact Strip */}
        <div className="mt-6 grid grid-cols-2 gap-4 border-t border-rule/60 pt-4 text-12 md:grid-cols-4">
          <div>
            <span className="text-ink-3">Scanner Family:</span>
            <div className="font-semibold text-ink">{f.rule_scanner_family || 'Generic'}</div>
          </div>
          <div>
            <span className="text-ink-3">Rule Identifier:</span>
            <div className="font-mono text-ink">{f.rule_id || 'N/A'}</div>
          </div>
          <div>
            <span className="text-ink-3">Location:</span>
            <div className="font-mono text-ink [overflow-wrap:anywhere]">{where || 'Global'}</div>
          </div>
          <div>
            <span className="text-ink-3">Detection Window:</span>
            <div className="text-ink">
              {absoluteDate(f.first_seen)} → {absoluteDate(f.last_seen)}
            </div>
          </div>
        </div>

        {/* VEX Exploitability Assertion Card */}
        {f.justification && (
          <div className="mt-4 rounded-ctl border border-rule bg-canvas-subtle p-3.5 text-12">
            <div className="flex items-center justify-between border-b border-rule pb-2">
              <div className="flex items-center gap-2">
                <span className="text-14">🛡️</span>
                <span className="font-semibold text-ink">VEX Exploitability Assertion</span>
                <span className="rounded bg-accent/10 px-1.5 py-0.5 font-mono text-11 text-accent">
                  {f.state.replace(/_/g, ' ').toUpperCase()}
                </span>
              </div>
              {f.last_seen && (
                <span className="text-11 text-ink-3">Seen {sinceShort(f.last_seen)}</span>
              )}
            </div>
            <div className="mt-2.5 grid grid-cols-1 gap-2 md:grid-cols-2">
              <div>
                <span className="font-medium text-ink-3">Standard Justification:</span>
                <div className="mt-0.5 font-mono text-12 font-medium text-ink">
                  {f.justification}
                </div>
              </div>
              {f.impact_statement && (
                <div>
                  <span className="font-medium text-ink-3">Impact Analysis:</span>
                  <div className="mt-0.5 text-ink leading-relaxed">
                    {f.impact_statement}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Tabs Layout */}
      <div className="mt-6">
        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as FindingTab)}>
          <TabsList label="Finding details sections">
            <TabsTrigger value="evidence">
              Scanner Evidence & Occurrences
            </TabsTrigger>
            <TabsTrigger value="technical">
              Technical Details & Location
            </TabsTrigger>
            <TabsTrigger value="risk">
              Risk & Scoring Breakdown
            </TabsTrigger>
            <TabsTrigger value="compliance">
              Compliance Controls ({controlsQuery.data?.length ?? 0})
            </TabsTrigger>
            <TabsTrigger value="timeline">
              Activity Timeline
            </TabsTrigger>
            <TabsTrigger value="raw">
              Raw Finding JSON
            </TabsTrigger>
          </TabsList>

          {/* Tab 1: Scanner Evidence & Occurrences */}
          <TabsContent value="evidence" className="pt-4">
            <div className="rounded-lg border border-rule bg-layer-1 p-6">
              <div className="mb-4">
                <h2 className="m-0 text-16 font-semibold text-ink">
                  Concrete Scanner Occurrences & Dynamic Evidence
                </h2>
                <p className="mt-1 text-13 text-ink-2">
                  Multi-scanner reports, dynamic key-value attributes (commits, URLs, tags, entropy), and raw tool outputs stored during ingestion.
                </p>
              </div>
              <ScannerEvidenceSection finding={f} />
            </div>
          </TabsContent>

          {/* Tab 2: Technical Details & Location */}
          <TabsContent value="technical" className="pt-4">
            <div className="rounded-lg border border-rule bg-layer-1 p-6">
              <h2 className="m-0 mb-4 text-16 font-semibold text-ink">
                Technical Location & Code Context
              </h2>

              <dl className="m-0 grid grid-cols-[140px_1fr] gap-x-4 gap-y-3 text-13">
                <dt className="font-medium text-ink-2">Rule ID</dt>
                <dd className="m-0 font-mono text-ink">{f.rule_id || 'N/A'}</dd>

                {loc.file_path && (
                  <>
                    <dt className="font-medium text-ink-2">File Path</dt>
                    <dd className="m-0 font-mono text-ink">{loc.file_path}</dd>
                  </>
                )}

                {loc.start_line && (
                  <>
                    <dt className="font-medium text-ink-2">Line Range</dt>
                    <dd className="m-0 font-mono text-ink">
                      Lines {loc.start_line}
                      {loc.end_line && loc.end_line !== loc.start_line ? ` - ${loc.end_line}` : ''}
                    </dd>
                  </>
                )}

                {loc.purl && (
                  <>
                    <dt className="font-medium text-ink-2">Package PURL</dt>
                    <dd className="m-0 font-mono text-ink">{loc.purl}</dd>
                  </>
                )}

                {loc.url && (
                  <>
                    <dt className="font-medium text-ink-2">Web Target</dt>
                    <dd className="m-0 font-mono text-ink">
                      <a href={loc.url} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                        {loc.url}
                      </a>
                      {loc.method && ` [${loc.method}]`}
                      {loc.param && ` (param: ${loc.param})`}
                    </dd>
                  </>
                )}

                {loc.resource_address && (
                  <>
                    <dt className="font-medium text-ink-2">Resource Address</dt>
                    <dd className="m-0 font-mono text-ink">{loc.resource_address}</dd>
                  </>
                )}

                {f.cwes && f.cwes.length > 0 && (
                  <>
                    <dt className="font-medium text-ink-2">Common Weaknesses</dt>
                    <dd className="m-0 flex flex-wrap gap-1.5">
                      {f.cwes.map((c) => (
                        <a
                          key={c}
                          href={`https://cwe.mitre.org/data/definitions/${c}.html`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="rounded border border-rule bg-chrome px-2 py-0.5 font-mono text-12 text-accent hover:underline"
                        >
                          CWE-{c}
                        </a>
                      ))}
                    </dd>
                  </>
                )}

                {f.vulnerability_id && (
                  <>
                    <dt className="font-medium text-ink-2">Advisory Reference</dt>
                    <dd className="m-0">
                      <Link
                        to="/vulnerabilities/$id"
                        params={{ id: f.vulnerability_id }}
                        className="font-mono text-accent hover:underline"
                      >
                        {f.vulnerability_id} →
                      </Link>
                    </dd>
                  </>
                )}
              </dl>

              {loc.snippet && (
                <div className="mt-6 border-t border-rule pt-4">
                  <h3 className="mb-2 text-13 font-semibold text-ink">Code Snippet</h3>
                  <pre className="m-0 overflow-auto rounded bg-chrome p-3 font-mono text-12 leading-relaxed text-ink">
                    {loc.snippet}
                  </pre>
                </div>
              )}
            </div>
          </TabsContent>

          {/* Tab 3: Risk & Scoring Breakdown */}
          <TabsContent value="risk" className="pt-4">
            <div className="rounded-lg border border-rule bg-layer-1 p-6">
              <h2 className="m-0 mb-2 text-16 font-semibold text-ink">
                Risk Score Calculation ({risk?.total_score ?? 'N/A'} / 1000)
              </h2>
              <p className="mb-4 text-13 text-ink-2">
                Rampart calculates dynamic risk by combining scanner base severity, real-time threat intelligence (CISA KEV, EPSS), asset exposure, and compensating controls.
              </p>

              {risk?.factors && risk.factors.length > 0 ? (
                <ul className="m-0 list-none p-0 divide-y divide-rule text-13">
                  <li className="flex items-center justify-between py-2.5">
                    <span className="font-medium text-ink">Base Scanner Severity ({risk.base_severity})</span>
                    <span className="font-mono font-semibold text-ink">+{risk.base_points} pts</span>
                  </li>
                  {risk.factors.map((factor, idx) => (
                    <li key={idx} className="flex items-start justify-between py-2.5">
                      <div>
                        <div className="font-medium text-ink">{factor.name}</div>
                        {factor.reason && (
                          <div className="text-12 text-ink-2">{factor.reason}</div>
                        )}
                      </div>
                      <span className={cn('font-mono font-semibold', factor.points >= 0 ? 'text-danger' : 'text-success')}>
                        {factor.points >= 0 ? `+${factor.points}` : factor.points} pts
                      </span>
                    </li>
                  ))}
                  <li className="flex items-center justify-between pt-3 font-bold text-ink">
                    <span>Total Computed Risk Score</span>
                    <span className="text-16 text-accent">{risk.total_score} pts</span>
                  </li>
                </ul>
              ) : (
                <p className="text-13 text-ink-2">No detailed scoring factors recorded for this finding.</p>
              )}
            </div>
          </TabsContent>

          {/* Tab 4: Compliance Controls */}
          <TabsContent value="compliance" className="pt-4">
            <div className="rounded-lg border border-rule bg-layer-1 p-6">
              <h2 className="m-0 mb-4 text-16 font-semibold text-ink">
                Applicable Security & Compliance Controls
              </h2>

              {controlsQuery.isPending && (
                <div className="flex items-center gap-2 text-12 text-ink-2">
                  <Spinner size={14} />
                  <span>Loading compliance controls...</span>
                </div>
              )}

              {controlsQuery.data && controlsQuery.data.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-13">
                    <thead className="border-b border-rule text-12 font-semibold text-ink-2">
                      <tr>
                        <th className="py-2 pr-4">Framework</th>
                        <th className="py-2 pr-4">Control ID</th>
                        <th className="py-2 pr-4">Control Description</th>
                        <th className="py-2">Due Date</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-rule/60">
                      {controlsQuery.data.map((c, i) => (
                        <tr key={i}>
                          <td className="py-2.5 pr-4 font-medium text-ink">{c.framework} ({c.version})</td>
                          <td className="py-2.5 pr-4 font-mono text-accent">{c.control_id}</td>
                          <td className="py-2.5 pr-4 text-ink-2">{c.control}</td>
                          <td className="py-2.5">
                            {c.due ? (
                              <span className={cn(c.overdue ? 'text-danger font-semibold' : 'text-ink-2')}>
                                {absoluteDate(c.due)} {c.overdue ? '(Overdue)' : ''}
                              </span>
                            ) : (
                              'None'
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="m-0 text-13 text-ink-2">
                  This finding does not breach any active framework compliance controls.
                </p>
              )}
            </div>
          </TabsContent>

          {/* Tab 5: Activity Timeline */}
          <TabsContent value="timeline" className="pt-4">
            <div className="rounded-lg border border-rule bg-layer-1 p-6">
              <h2 className="m-0 mb-4 text-16 font-semibold text-ink">
                Finding History & Audit Timeline
              </h2>

              {eventsQuery.isPending && (
                <div className="flex items-center gap-2 text-12 text-ink-2">
                  <Spinner size={14} />
                  <span>Loading event timeline...</span>
                </div>
              )}

              {eventsQuery.data && eventsQuery.data.length > 0 ? (
                <ul className="m-0 list-none p-0 divide-y divide-rule/60 text-13">
                  {eventsQuery.data.map((evt) => (
                    <li key={evt.id} className="py-2.5">
                      <div className="flex items-center justify-between text-12 text-ink-3">
                        <span className="font-semibold text-ink capitalize">{evt.type.replace(/_/g, ' ')}</span>
                        <span>{absoluteDateTime(evt.at)}</span>
                      </div>
                      <div className="mt-0.5 text-12 text-ink-2">
                        Actor: <span className="font-mono text-ink">{evt.actor}</span>
                      </div>
                      {evt.note && <div className="mt-1 text-13 text-ink">{evt.note}</div>}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="m-0 text-13 text-ink-2">No activity events recorded yet.</p>
              )}
            </div>
          </TabsContent>

          {/* Tab 6: Raw Finding JSON */}
          <TabsContent value="raw" className="pt-4">
            <div className="rounded-lg border border-rule bg-layer-1 p-6">
              <div className="mb-3 flex items-center justify-between">
                <div>
                  <h2 className="m-0 text-16 font-semibold text-ink">Raw API Payload</h2>
                  <p className="mt-0.5 text-12 text-ink-2">The complete normalized record returned by GET /api/v1/findings/:id</p>
                </div>
                <Button
                  variant="secondary"
                  onClick={() => {
                    navigator.clipboard.writeText(rawFindingJson);
                    setCopiedRaw(true);
                    setTimeout(() => setCopiedRaw(false), 2000);
                  }}
                >
                  {copiedRaw ? 'Copied!' : 'Copy Finding JSON'}
                </Button>
              </div>
              <pre className="m-0 max-h-96 overflow-auto rounded bg-chrome p-3 font-mono text-11 leading-relaxed text-ink">
                {rawFindingJson}
              </pre>
            </div>
          </TabsContent>
        </Tabs>
      </div>

      {/* Triage, Edit, and Acceptance Dialogs */}
      {canTriage && (
        <>
          <TriageDialog
            open={triageOpen}
            onOpenChange={setTriageOpen}
            row={row}
          />
          <EditDialog
            open={editOpen}
            onOpenChange={setEditOpen}
            row={row}
          />
          <AcceptanceDialog
            open={acceptOpen}
            onOpenChange={setAcceptOpen}
            row={row}
          />
        </>
      )}
    </main>
  );
}
