import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { listApplications, listUnmappedDTrackProjects, mapDTrackProject, qk, toProblem } from '@/api';
import type { DTrackProjectRecord } from '@/api/types';
import {
  Button,
  Dialog,
  DialogClose,
  DialogContent,
  EmptyState,
  ProblemMessage,
  Spinner,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
  useToast,
} from '@/components';

export function DependencyTrackView() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const toast = useToast();
  const [mappingProject, setMappingProject] = useState<DTrackProjectRecord | null>(null);
  const [selectedAppId, setSelectedAppId] = useState<string>('');

  const unmappedQuery = useQuery({
    queryKey: qk.dtrack.unmapped(),
    queryFn: ({ signal }) => listUnmappedDTrackProjects(signal),
  });

  const appsQuery = useQuery({
    queryKey: qk.applications.list(),
    queryFn: ({ signal }) => listApplications(signal),
  });

  const mapMutation = useMutation({
    mutationFn: () => {
      if (!mappingProject || !selectedAppId) throw new Error('Missing selection');
      return mapDTrackProject(mappingProject.project_uuid, selectedAppId);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.dtrack.unmapped() });
      toast.info(t('dtrack.mappedSuccess', { defaultValue: 'Project successfully mapped to application' }));
      setMappingProject(null);
      setSelectedAppId('');
    },
  });

  const unmappedList = unmappedQuery.data ?? [];
  const apps = appsQuery.data ?? [];

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Connector Header & Metric Cards */}
      <div className="grid grid-cols-1 gap-4 tablet:grid-cols-3">
        <div className="rounded border border-rule bg-canvas-2 p-4">
          <span className="text-11 font-medium uppercase tracking-wider text-ink-2">Upstream Integration</span>
          <div className="mt-1 flex items-center gap-2">
            <span className="size-2 rounded-full bg-success" />
            <span className="text-14 font-semibold text-ink">Dependency-Track v4.14</span>
          </div>
          <p className="mt-1 text-12 text-ink-2">Portfolio sync, FPF parser & trailing debounce active</p>
        </div>

        <div className="rounded border border-rule bg-canvas-2 p-4">
          <span className="text-11 font-medium uppercase tracking-wider text-ink-2">Webhook Receiver</span>
          <div className="mt-1 flex items-center gap-2">
            <span className="size-2 rounded-full bg-success" />
            <span className="text-14 font-semibold text-ink">Listening</span>
          </div>
          <p className="mt-1 text-12 text-ink-2">Thin event, fat fetch with constant-time token verification</p>
        </div>

        <div className="rounded border border-rule bg-canvas-2 p-4">
          <span className="text-11 font-medium uppercase tracking-wider text-ink-2">Unmapped Projects</span>
          <div className="mt-1 flex items-center gap-2">
            <span className="text-20 font-bold text-ink tnum">{unmappedList.length}</span>
            <span className="text-12 text-ink-2">pending mapping</span>
          </div>
          <p className="mt-1 text-12 text-ink-2">Projects lacking a matching name, tag, or purl rule</p>
        </div>
      </div>

      {/* Unmapped Projects Section */}
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-16 font-semibold text-ink">Unmapped Portfolio Projects</h2>
            <p className="text-12 text-ink-2">
              Discovered projects in Dependency-Track that did not match an automatic mapping rule. Assign an application to roll up scores.
            </p>
          </div>
        </div>

        {unmappedQuery.isLoading ? (
          <div className="flex h-48 items-center justify-center">
            <Spinner />
          </div>
        ) : unmappedQuery.isError ? (
          <ProblemMessage problem={toProblem(unmappedQuery.error)} />
        ) : unmappedList.length === 0 ? (
          <EmptyState title={t('dtrack.allMapped', { defaultValue: 'All Dependency-Track projects mapped' })}>
            {t('dtrack.allMappedBody', {
              defaultValue: 'Every discovered project in the Dependency-Track portfolio is linked to an application in Rampart.',
            })}
          </EmptyState>
        ) : (
          <Table aria-label="Unmapped Projects Table">
            <THead>
              <tr>
                <Th>Project Name</Th>
                <Th>Version</Th>
                <Th>Package URL (purl)</Th>
                <Th>Unmapped Reason</Th>
                <Th align="end">Actions</Th>
              </tr>
            </THead>
            <TBody>
              {unmappedList.map((p) => (
                <Tr key={p.project_uuid} className="h-12">
                  <Td className="font-medium text-ink">
                    <div className="flex flex-col">
                      <span className="text-13">{p.name}</span>
                      <span className="font-mono text-11 text-ink-2">{p.project_uuid}</span>
                    </div>
                  </Td>
                  <Td className="font-mono text-12 text-ink-2">{p.version || '—'}</Td>
                  <Td className="font-mono text-12 text-ink-2 truncate max-w-xs">{p.purl || '—'}</Td>
                  <Td className="text-12 text-ink-2">{p.unmapped_reason || 'No matching application rule'}</Td>
                  <Td align="end">
                    <Button
                      variant="secondary"
                      onClick={() => {
                        setMappingProject(p);
                        setSelectedAppId(apps[0]?.id ?? '');
                      }}
                    >
                      Map to Application
                    </Button>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </div>

      {/* Map to Application Dialog */}
      <Dialog open={!!mappingProject} onOpenChange={(open) => !open && setMappingProject(null)}>
        {mappingProject && (
          <DialogContent
            title="Map Project to Application"
            description={`Assign "${mappingProject.name}" to a Rampart application so findings, risk scores, and SLA adhere correctly.`}
            closeLabel="Close"
          >
            <div className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label htmlFor="app-select" className="text-12 font-medium text-ink">
                  Target Application
                </label>
                <select
                  id="app-select"
                  className="h-9 w-full rounded border border-rule bg-canvas px-3 text-13 text-ink focus:outline-none focus:ring-1 focus:ring-accent"
                  value={selectedAppId}
                  onChange={(e) => setSelectedAppId(e.target.value)}
                >
                  <option value="" disabled>Select an application</option>
                  {apps.map((app) => (
                    <option key={app.id} value={app.id}>
                      {app.name} ({app.slug})
                    </option>
                  ))}
                </select>
              </div>

              {mapMutation.isError && (
                <ProblemMessage problem={toProblem(mapMutation.error)} />
              )}

              <div className="flex justify-end gap-2 pt-2 border-t border-rule">
                <DialogClose asChild>
                  <Button variant="ghost">Cancel</Button>
                </DialogClose>
                <Button
                  variant="primary"
                  loading={mapMutation.isPending}
                  disabled={!selectedAppId}
                  onClick={() => mapMutation.mutate()}
                >
                  Confirm Mapping
                </Button>
              </div>
            </div>
          </DialogContent>
        )}
      </Dialog>
    </div>
  );
}
