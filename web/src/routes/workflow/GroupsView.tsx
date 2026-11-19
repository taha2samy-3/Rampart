import { useId, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import {
  createFindingGroup,
  deleteFindingGroup,
  getFindingGroup,
  listApplications,
  listFindingGroups,
  removeGroupMembers,
  requestGroupTicket,
  qk,
  toProblem,
} from '@/api';
import type { AppSummary, FindingGroup, GroupTicket } from '@/api/types';
import {
  Button,
  Dialog,
  DialogContent,
  EmptyState,
  ProblemMessage,
  Select,
  Skeleton,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
  useToast,
} from '@/components';
import { useAccess } from '@/app/useAccess';
import { cn } from '@/lib/cn';
import { absoluteDate } from '@/lib/format';
import type { WorkflowSearch } from './WorkflowRoute';

export function GroupsView({
  search,
  set,
}: {
  search: WorkflowSearch;
  set: (patch: Partial<WorkflowSearch>) => void;
}) {
  const { t } = useTranslation();
  const [createOpen, setCreateOpen] = useState(false);
  const q = useQuery({
    queryKey: qk.groups.list(),
    queryFn: ({ signal }) => listFindingGroups(signal),
  });
  const rows = q.data ?? [];
  const selected = rows.find((r) => r.id === search.sel);
  const appsQ = useQuery({ queryKey: qk.applications.list(), queryFn: ({ signal }) => listApplications(signal) });
  const appName = (id?: string) => (id ? appsQ.data?.find((a) => a.id === id)?.name ?? 'an application' : 'Whole tenant');

  let list: React.ReactNode;
  if (q.isPending) {
    list = (
      <div className="flex-1" aria-busy="true" aria-label={t('common.loading')}>
        {Array.from({ length: 5 }, (_, i) => (
          <div key={i} className="flex h-[46px] items-center gap-3 border-b border-rule px-3">
            <Skeleton className="h-3 flex-1" />
          </div>
        ))}
      </div>
    );
  } else if (q.isError) {
    list = (
      <div className="p-4">
        <ProblemMessage
          problem={toProblem(q.error)}
          title="Failed to load finding groups"
          onRetry={() => void q.refetch()}
        />
      </div>
    );
  } else if (rows.length === 0) {
    list = (
      <EmptyState
        title="No finding groups yet"
        action={
          <Button variant="secondary" onClick={() => setCreateOpen(true)}>
            New group
          </Button>
        }
      >
        A group gathers findings of one application that are fixed together, and can be tracked by one ticket.
      </EmptyState>
    );
  } else {
    const tabbable = selected?.id ?? rows[0]?.id;
    list = (
      <div className="min-h-0 flex-1 overflow-auto">
        <Table role="grid" aria-label="Finding groups table" aria-rowcount={rows.length}>
          <colgroup>
            <col />
            <col className="w-[160px]" />
            <col className="w-[110px]" />
            <col className="w-[140px]" />
          </colgroup>
          <THead className="sticky top-0 z-10">
            <tr role="row">
              <Th>Group</Th>
              <Th>Application</Th>
              <Th>Findings</Th>
              <Th>Ticket</Th>
            </tr>
          </THead>
          <TBody>
            {rows.map((r, i) => (
              <Tr
                key={r.id}
                data-row-id={r.id}
                aria-rowindex={i + 2}
                selected={r.id === selected?.id}
                tabIndex={r.id === tabbable ? 0 : -1}
                onClick={() => set({ sel: r.id })}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    set({ sel: r.id });
                  }
                }}
                className="h-[46px] cursor-default align-middle focus-visible:outline-offset-[-2px]"
              >
                <Td className={cn('py-0', r.id === selected?.id && 'shadow-[inset_3px_0_0_var(--accent)]')}>
                  <span className="block truncate font-medium">{r.name}</span>
                  {r.description && (
                    <span className="block truncate text-[11.5px] leading-4 text-ink-2">
                      {r.description}
                    </span>
                  )}
                </Td>
                <Td className="truncate text-12 text-ink-2">{appName(r.application_id)}</Td>
                <Td className="text-ink-2">{r.member_count ?? 0} findings</Td>
                <Td className="truncate text-12 text-ink-2">{ticketShort(r.ticket)}</Td>
              </Tr>
            ))}
          </TBody>
        </Table>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col tablet:flex-row">
      <section aria-label="Finding groups" className="flex min-h-0 min-w-0 flex-1 basis-3/5 flex-col tablet:basis-auto">
        <div className="flex items-center justify-between border-b border-rule px-3 py-2">
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => set({ tab: 'acceptances', sel: undefined })}
              className="rounded-ctl px-2.5 py-1 text-13 font-medium text-ink-2 transition-colors hover:text-ink"
            >
              {t('acceptance.tabAcceptances', { defaultValue: 'Risk Acceptances' })}
            </button>
            <button
              type="button"
              onClick={() => set({ tab: 'held_closes', sel: undefined })}
              className="rounded-ctl px-2.5 py-1 text-13 font-medium text-ink-2 transition-colors hover:text-ink"
            >
              {t('acceptance.tabHeldCloses', { defaultValue: 'Held Closes' })}
            </button>
            <button
              type="button"
              onClick={() => set({ tab: 'groups', sel: undefined })}
              className="rounded-ctl bg-surface px-2.5 py-1 text-13 font-semibold text-ink"
            >
              Finding groups
            </button>
          </div>
          <Button variant="secondary" onClick={() => setCreateOpen(true)}>
            New group
          </Button>
        </div>
        {list}
      </section>
      <div className="min-h-[200px] shrink-0 basis-2/5 border-t border-rule bg-chrome tablet:min-h-0 tablet:w-[360px] tablet:basis-auto tablet:border-s tablet:border-t-0">
        <aside aria-label="Finding group details" className="h-full overflow-y-auto">
          {selected ? (
            <GroupDetail key={selected.id} group={selected} appName={appName(selected.application_id)} onDeleted={() => set({ sel: undefined })} />
          ) : (
            <EmptyState title="Select a group">Its findings and its ticket show here.</EmptyState>
          )}
        </aside>
      </div>
      <CreateGroupDialog open={createOpen} onOpenChange={setCreateOpen} apps={appsQ.data ?? []} />
    </div>
  );
}

/** The ticket column: what a person needs to know in a few words. */
export function ticketShort(t: GroupTicket | undefined): string {
  if (!t) return 'None';
  if (t.status === 'reserved') return 'Being opened';
  if (t.status === 'failed') return 'Could not open';
  return t.external_ref || 'Open';
}

function GroupDetail({
  group,
  appName,
  onDeleted,
}: {
  group: FindingGroup;
  appName: string;
  onDeleted: () => void;
}) {
  const toast = useToast();
  const qc = useQueryClient();
  const { can, canAnywhere } = useAccess();
  // The server decides; the screen offers only what the role on the group's application allows (D90).
  const isMaintainer = group.application_id ? can(group.application_id, 'maintainer') : canAnywhere('admin');
  const isTriager = group.application_id ? can(group.application_id, 'triager') : canAnywhere('triager');

  const ticketMutation = useMutation({
    mutationFn: () => requestGroupTicket(group.id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.groups.all() });
      toast.info('Ticket requested. It opens on your tracker within a minute.');
    },
  });

  const detailQuery = useQuery({
    queryKey: qk.groups.one(group.id),
    queryFn: ({ signal }) => getFindingGroup(group.id, signal),
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteFindingGroup(group.id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.groups.all() });
      toast.info('Finding group deleted');
      onDeleted();
    },
  });

  const removeMemberMutation = useMutation({
    mutationFn: (findingId: string) => removeGroupMembers(group.id, [findingId]),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.groups.one(group.id) });
      void qc.invalidateQueries({ queryKey: qk.groups.all() });
      toast.info('Finding removed from group');
    },
  });

  const findings = detailQuery.data?.finding_ids ?? [];
  const ticket = detailQuery.data?.group.ticket ?? group.ticket;
  const failed = deleteMutation.isError ? deleteMutation.error : ticketMutation.isError ? ticketMutation.error : null;
  const problem = failed ? toProblem(failed) : null;

  return (
    <article aria-label="Finding group detail" className="px-4 py-3">
      <h2 className="display text-16 leading-snug [overflow-wrap:anywhere]">{group.name}</h2>
      {group.description && <p className="mt-1 text-13 text-ink-2">{group.description}</p>}

      <dl className="m-0 mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-13">
        <dt className="text-ink-2">Application</dt>
        <dd className="m-0">{appName}</dd>
        <dt className="text-ink-2">Owner</dt>
        <dd className="m-0">{group.owner ? group.owner.replace(/^user:/, '') : '—'}</dd>
        <dt className="text-ink-2">Findings</dt>
        <dd className="m-0 font-medium">{findings.length || group.member_count || 0}</dd>
        <dt className="text-ink-2">Created</dt>
        <dd className="m-0">{group.created_at ? absoluteDate(group.created_at) : '—'}</dd>
      </dl>

      <section className="mt-5" aria-labelledby="group-ticket">
        <h3 id="group-ticket" className="m-0 mb-1 text-13 font-semibold">
          Ticket
        </h3>
        <p className="m-0 text-13 text-ink-2">{ticketSentence(ticket)}</p>
        {ticket?.status === 'done' && ticket.url && (
          <a href={ticket.url} target="_blank" rel="noreferrer" className="text-13 text-accent hover:underline">
            Open {ticket.external_ref} in the tracker
          </a>
        )}
        {isMaintainer && (!ticket || ticket.status === 'failed') && findings.length > 0 && (
          <Button className="mt-2" loading={ticketMutation.isPending} onClick={() => ticketMutation.mutate()}>
            {ticket ? 'Try the ticket again' : 'Open one ticket for the group'}
          </Button>
        )}
      </section>

      <section className="mt-5">
        <h3 className="m-0 mb-2 text-13 font-semibold">Findings ({findings.length})</h3>
        {detailQuery.isPending && (
          <div className="flex flex-col gap-1 py-2">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-1/2" />
          </div>
        )}
        {findings.length === 0 && !detailQuery.isPending && (
          <p className="m-0 text-12 text-ink-2">No findings have been added to this group yet.</p>
        )}
        {findings.length > 0 && (
          <ul className="m-0 list-none p-0 text-12">
            {findings.map((fId) => (
              <li
                key={fId}
                className="flex items-center justify-between border-b border-rule py-1.5 font-mono"
              >
                <Link
                  to="/findings"
                  search={{ sel: fId }}
                  className="truncate text-accent hover:underline"
                >
                  {fId}
                </Link>
                {isTriager && (
                  <button
                    type="button"
                    onClick={() => removeMemberMutation.mutate(fId)}
                    disabled={removeMemberMutation.isPending}
                    className="text-12 text-critical hover:underline"
                    aria-label={`Remove finding ${fId} from group`}
                  >
                    Remove
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      {problem && <ProblemMessage className="mt-3" problem={problem} title="Action failed" />}

      {isMaintainer && (
        <div className="mt-6 border-t border-rule pt-4">
          <Button
            className="text-critical hover:bg-critical/10"
            loading={deleteMutation.isPending}
            onClick={() => {
              if (window.confirm(`Delete finding group "${group.name}"?`)) {
                deleteMutation.mutate();
              }
            }}
          >
            Delete group
          </Button>
        </div>
      )}
    </article>
  );
}

function CreateGroupDialog({
  open,
  onOpenChange,
  apps,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  apps: AppSummary[];
}) {
  const { can, canAnywhere } = useAccess();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  // Only applications where the caller is a maintainer; the whole tenant only for an admin (D90).
  const choices = [
    ...apps.filter((a) => can(a.id, 'maintainer')).map((a) => ({ value: a.id, label: a.name })),
    ...(canAnywhere('admin') ? [{ value: 'tenant', label: 'Whole tenant' }] : []),
  ];
  const [appChoice, setAppChoice] = useState('');
  const app = appChoice || choices[0]?.value || '';
  const nameId = useId();
  const descId = useId();
  const toast = useToast();
  const qc = useQueryClient();

  const mutation = useMutation({
    mutationFn: () =>
      createFindingGroup({
        name: name.trim(),
        description: description.trim() || undefined,
        application_id: app && app !== 'tenant' ? app : undefined,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.groups.all() });
      toast.info('Finding group created');
      setName('');
      setDescription('');
      onOpenChange(false);
    },
  });

  const problem = mutation.isError ? toProblem(mutation.error) : null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="New group" description="Findings of one application that are fixed together.">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim()) mutation.mutate();
          }}
          className="flex flex-col gap-4 p-4"
        >
          <div className="flex flex-col gap-1.5">
            <label htmlFor={nameId} className="text-13 font-medium">
              Name
            </label>
            <input
              id={nameId}
              type="text"
              required
              maxLength={255}
              placeholder="Spring4Shell in payments"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="rounded-ctl border border-rule bg-surface px-3 py-1.5 text-13 text-ink focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label htmlFor={descId} className="text-13 font-medium">
              Description
            </label>
            <textarea
              id={descId}
              rows={3}
              placeholder="Why these findings belong together"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="resize-y rounded-ctl border border-rule bg-surface px-3 py-1.5 text-13 text-ink focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <span className="text-13 font-medium">Application</span>
            {choices.length === 0 ? (
              <p className="m-0 text-13 text-ink-2">You are not a maintainer of any application, so you cannot create a group.</p>
            ) : (
              <Select label="Application" value={app} onValueChange={setAppChoice} options={choices} />
            )}
          </div>

          {problem && <ProblemMessage problem={problem} title="The group was not created" />}

          <div className="flex justify-end gap-2 pt-2">
            <Button
              type="button"
              onClick={() => {
                setName('');
                setDescription('');
                onOpenChange(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={mutation.isPending} disabled={!name.trim() || !app}>
              Create group
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** The ticket, in a sentence for the detail pane. */
export function ticketSentence(t: GroupTicket | undefined): string {
  if (!t) return 'No ticket. One ticket can track every finding of the group.';
  if (t.status === 'reserved') return 'Requested; the server opens it on your tracker within a minute.';
  if (t.status === 'failed') return `It could not be opened${t.error ? `: ${t.error}` : '.'}`;
  return `Open as ${t.external_ref || 'a ticket'}, linked to every finding of the group.`;
}
