import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import {
  listApplications,
  listMappedProjects,
  listSourceDecisions,
  listSources,
  listUnmappedProjects,
  mapSourceProject,
  qk,
  toProblem,
} from '@/api';
import type { DTrackProjectRecord, SourceStatus } from '@/api/types';
import {
  Button,
  Dialog,
  DialogClose,
  DialogContent,
  EmptyState,
  ProblemMessage,
  Select,
  Spinner,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
  useToast,
} from '@/components';
import { absoluteDate, shortId, sinceShort } from '@/lib/format';

const EXAMPLE = `apiVersion: rampart.aspm.dev/v1alpha1
kind: ScanSource
metadata: {name: dtrack-portfolio, namespace: <tenant-namespace>}
spec:
  type: apiPull
  scannerFamily: dependency-track
  connector: dtrack            # a Connector of type dependencyTrack
  schedule: 30m
  dependencyTrack:
    projects: {versions: latest}
    webhook: {enabled: false}`;

/** What put a project in its application, in words: a person, the default application, or the rule that matched. */
export function mappedBy(rule: string | undefined): string {
  if (!rule) return 'A rule';
  if (rule === 'manual_ui_mapping') return 'You';
  if (rule === 'defaultApplication') return 'The default application';
  if (rule.startsWith('property:')) return `A project property (${rule.slice('property:'.length)})`;
  if (rule.startsWith('tag:')) return `A project tag (${rule.slice('tag:'.length)})`;
  if (rule.startsWith('cel:')) return 'A CEL rule';
  return `The rule ${rule}`;
}

/** One sentence that says how a source is doing, from what the server recorded (D92). */
export function sourceSentence(s: SourceStatus, now = Date.now()): string {
  const every = Math.round(s.schedule_seconds / 60);
  if (s.last_portfolio_error) return `The last portfolio sync failed: ${s.last_portfolio_error}`;
  if (!s.last_portfolio_sync_at) return `Not synced yet. The first sync starts within a minute, then every ${every} min.`;
  const base = `Portfolio synced ${sinceShort(s.last_portfolio_sync_at, now)}, every ${every} min.`;
  return s.last_project_error ? `${base} One project failed: ${s.last_project_error}` : base;
}

/**
 * Dependency-Track sources (docs/10, D92): their state, the projects waiting for an application, and the decisions
 * Dependency-Track made that wait for a person. Everything shown is read from the server; nothing is assumed.
 */
export function DependencyTrackView() {
  const qc = useQueryClient();
  const toast = useToast();
  const [chosen, setChosen] = useState('');
  const [mapping, setMapping] = useState<DTrackProjectRecord | null>(null);
  const [appId, setAppId] = useState('');

  const sourcesQuery = useQuery({ queryKey: qk.dtrack.sources(), queryFn: ({ signal }) => listSources(signal) });
  const sources = sourcesQuery.data ?? [];
  const source = sources.find((s) => s.id === chosen) ?? sources[0];
  const sourceId = source?.id ?? '';

  const unmappedQuery = useQuery({
    queryKey: qk.dtrack.unmapped(sourceId),
    queryFn: ({ signal }) => listUnmappedProjects(sourceId, signal),
    enabled: !!sourceId,
  });
  const mappedQuery = useQuery({
    queryKey: qk.dtrack.mapped(sourceId),
    queryFn: ({ signal }) => listMappedProjects(sourceId, signal),
    enabled: !!sourceId,
  });
  const decisionsQuery = useQuery({
    queryKey: qk.dtrack.decisions(sourceId),
    queryFn: ({ signal }) => listSourceDecisions(sourceId, signal),
    enabled: !!sourceId,
  });
  const appsQuery = useQuery({
    queryKey: qk.applications.list(),
    queryFn: ({ signal }) => listApplications(signal),
    enabled: !!mapping,
  });

  const mapMutation = useMutation({
    mutationFn: () => mapSourceProject(sourceId, mapping!.project_uuid, appId),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: qk.dtrack.all() });
      toast.info(res.sync_queued ? `Mapped ${mapping?.name}. Its findings are being read now.` : `Mapped ${mapping?.name}. Its findings arrive with the next sync.`);
      setMapping(null);
      setAppId('');
    },
  });

  if (sourcesQuery.isLoading) {
    return (
      <div className="flex h-48 items-center justify-center">
        <Spinner />
      </div>
    );
  }
  if (sourcesQuery.isError) return <ProblemMessage problem={toProblem(sourcesQuery.error)} />;
  if (!source) {
    return (
      <EmptyState title="No Dependency-Track source yet">
        <p>
          Rampart reads findings from Dependency-Track when a ScanSource names a Connector of type dependencyTrack. Apply
          one like this, with the Connector and its API key, and the first sync starts within a minute.
        </p>
        <pre className="mt-3 overflow-x-auto border border-rule bg-chrome p-3 font-mono text-12 text-ink">{EXAMPLE}</pre>
      </EmptyState>
    );
  }

  const unmapped = unmappedQuery.data ?? [];
  const mapped = mappedQuery.data ?? [];
  const decisions = decisionsQuery.data ?? [];
  const apps = appsQuery.data ?? [];

  return (
    <div className="flex max-w-[1100px] flex-col gap-8 p-6">
      <section aria-labelledby="dt-source" className="flex flex-col gap-2">
        <div className="flex flex-wrap items-baseline gap-3">
          <h2 id="dt-source" className="text-16 font-semibold">
            {source.name}
          </h2>
          {sources.length > 1 && (
            <Select
              label="Source"
              value={source.id}
              onValueChange={setChosen}
              options={sources.map((s) => ({ value: s.id, label: s.name }))}
            />
          )}
        </div>
        <p className="max-w-[72ch] text-13 text-ink-2">{sourceSentence(source)}</p>
        <p className="max-w-[72ch] text-13 text-ink-2">
          Reads through connector <span className="font-mono text-12">{source.connector}</span>.{' '}
          {source.projects} projects seen, {source.unmapped} without an application.{' '}
          {source.webhook_enabled
            ? 'Dependency-Track can notify Rampart at /hooks/dependency-track/' + source.id + '.'
            : 'The webhook is off; the schedule alone starts syncs.'}{' '}
          {source.trust_upstream_decisions
            ? 'Decisions made in Dependency-Track are applied here, except risk acceptances.'
            : 'Decisions made in Dependency-Track wait for a person here.'}
        </p>
      </section>

      <section aria-labelledby="dt-unmapped" className="flex flex-col gap-2">
        <h3 id="dt-unmapped" className="text-14 font-semibold">
          Projects without an application
        </h3>
        {unmappedQuery.isError ? (
          <ProblemMessage problem={toProblem(unmappedQuery.error)} />
        ) : unmapped.length === 0 ? (
          <p className="text-13 text-ink-2">Every project this source reads belongs to an application.</p>
        ) : (
          <>
            <p className="max-w-[72ch] text-13 text-ink-2">
              No mapping rule matched these projects, so their findings are not read. Map one by hand and the mapping is
              kept across syncs.
            </p>
            <Table aria-label="Projects without an application">
              <THead>
                <tr>
                  <Th>Project</Th>
                  <Th>Version</Th>
                  <Th>Why it is not mapped</Th>
                  <Th align="end">
                    <span className="sr-only">Action</span>
                  </Th>
                </tr>
              </THead>
              <TBody>
                {unmapped.map((p) => (
                  <Tr key={p.project_uuid}>
                    <Td>
                      <span className="text-13 text-ink">{p.name}</span>
                      {p.purl && <span className="block truncate font-mono text-11 text-ink-2">{p.purl}</span>}
                    </Td>
                    <Td className="text-13 text-ink-2">{p.version || 'none'}</Td>
                    <Td className="text-13 text-ink-2">{p.unmapped_reason || 'No rule matched'}</Td>
                    <Td align="end">
                      <Button variant="secondary" onClick={() => setMapping(p)}>
                        Map to application
                      </Button>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </>
        )}
      </section>

      <section aria-labelledby="dt-mapped" className="flex flex-col gap-2">
        <h3 id="dt-mapped" className="text-14 font-semibold">
          Projects in an application
        </h3>
        {mappedQuery.isError ? (
          <ProblemMessage problem={toProblem(mappedQuery.error)} />
        ) : mapped.length === 0 ? (
          <p className="text-13 text-ink-2">No project is in an application yet.</p>
        ) : (
          <>
            <p className="max-w-[72ch] text-13 text-ink-2">
              The rule that put each project in its application is shown. A project the default application took was not
              claimed by any other rule: check that it belongs there, and change it if it does not. Its findings move with it.
            </p>
            <Table aria-label="Projects in an application">
              <THead>
                <tr>
                  <Th>Project</Th>
                  <Th>Version</Th>
                  <Th>Application</Th>
                  <Th>Put there by</Th>
                  <Th align="end">
                    <span className="sr-only">Action</span>
                  </Th>
                </tr>
              </THead>
              <TBody>
                {mapped.map((p) => (
                  <Tr key={p.project_uuid}>
                    <Td className="text-13 text-ink">{p.name}</Td>
                    <Td className="text-13 text-ink-2">{p.version || 'none'}</Td>
                    <Td className="text-13">
                      <Link to="/applications" className="text-accent hover:underline">{p.application_name || p.application_slug || 'An application'}</Link>
                    </Td>
                    <Td className={p.mapping_rule === 'defaultApplication' ? 'text-13 font-medium text-ink' : 'text-13 text-ink-2'}>
                      {mappedBy(p.mapping_rule)}
                    </Td>
                    <Td align="end">
                      <Button variant="secondary" onClick={() => setMapping(p)}>
                        Change application
                      </Button>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </>
        )}
      </section>

      <section aria-labelledby="dt-decisions" className="flex flex-col gap-2">
        <h3 id="dt-decisions" className="text-14 font-semibold">
          Decisions made in Dependency-Track
        </h3>
        {decisionsQuery.isError ? (
          <ProblemMessage problem={toProblem(decisionsQuery.error)} />
        ) : decisions.length === 0 ? (
          <p className="text-13 text-ink-2">None waiting. When an analyst marks a finding in Dependency-Track, it appears here.</p>
        ) : (
          <>
            <p className="max-w-[72ch] text-13 text-ink-2">
              These are requests: open the finding and decide it here to apply one.
            </p>
            <Table aria-label="Decisions made in Dependency-Track">
              <THead>
                <tr>
                  <Th>Finding</Th>
                  <Th>Dependency-Track says</Th>
                  <Th>Seen</Th>
                </tr>
              </THead>
              <TBody>
                {decisions.map((d) => (
                  <Tr key={d.finding_id}>
                    <Td>
                      <Link to="/findings" search={{ sel: d.finding_id }} className="text-13 text-accent hover:underline">
                        Finding {shortId(d.finding_id)}
                      </Link>
                    </Td>
                    <Td className="text-13">
                      {d.state.replaceAll('_', ' ')}
                      {d.justification && <span className="text-ink-2">, {d.justification.replaceAll('_', ' ')}</span>}
                    </Td>
                    <Td className="text-13 text-ink-2" title={absoluteDate(d.seen_at)}>
                      {sinceShort(d.seen_at)}
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </>
        )}
      </section>

      <Dialog open={!!mapping} onOpenChange={(open) => !open && setMapping(null)}>
        {mapping && (
          <DialogContent
            title={`Map ${mapping.name}`}
            description="Its findings are read into the application you choose, and the mapping survives later syncs."
            closeLabel="Close"
          >
            <div className="flex flex-col gap-4">
              {appsQuery.isLoading ? (
                <Spinner />
              ) : (
                <Select
                  label="Application"
                  value={appId}
                  onValueChange={setAppId}
                  options={[{ value: '', label: 'Choose an application' }, ...apps.map((a) => ({ value: a.id, label: a.name }))]}
                />
              )}
              {mapMutation.isError && <ProblemMessage problem={toProblem(mapMutation.error)} />}
              <div className="flex justify-end gap-2 border-t border-rule pt-3">
                <DialogClose asChild>
                  <Button variant="ghost">Cancel</Button>
                </DialogClose>
                <Button variant="primary" loading={mapMutation.isPending} disabled={!appId} onClick={() => mapMutation.mutate()}>
                  Map project
                </Button>
              </div>
            </div>
          </DialogContent>
        )}
      </Dialog>
    </div>
  );
}
