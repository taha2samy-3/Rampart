import { useId, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import {
  createFindingGroup,
  deleteFindingGroup,
  getFindingGroup,
  listFindingGroups,
  removeGroupMembers,
  qk,
  toProblem,
} from '@/api';
import type { FindingGroup } from '@/api/types';
import {
  Button,
  Dialog,
  DialogContent,
  EmptyState,
  ProblemMessage,
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
            Create Finding Group
          </Button>
        }
      >
        Group findings across scans to manage remediation initiatives, track root causes together, or dispatch correlation tickets.
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
            <col className="w-[100px]" />
          </colgroup>
          <THead className="sticky top-0 z-10">
            <tr role="row">
              <Th>Group</Th>
              <Th>Owner</Th>
              <Th>Findings</Th>
              <Th align="end">Created</Th>
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
                <Td className="truncate text-12 text-ink-2">
                  {r.owner ? r.owner.replace(/^user:/, '') : '—'}
                </Td>
                <Td className="text-ink-2">{r.member_count ?? 0} findings</Td>
                <Td align="end" className="text-ink-2" title={r.created_at ? absoluteDate(r.created_at) : undefined}>
                  {r.created_at ? absoluteDate(r.created_at) : '—'}
                </Td>
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
              className="rounded-ctl bg-surface px-2.5 py-1 text-13 font-semibold text-ink shadow-sm"
            >
              Finding Groups
            </button>
          </div>
          <Button variant="secondary" onClick={() => setCreateOpen(true)}>
            New Group
          </Button>
        </div>
        {list}
      </section>
      <div className="min-h-[200px] shrink-0 basis-2/5 border-t border-rule bg-chrome tablet:min-h-0 tablet:w-[360px] tablet:basis-auto tablet:border-s tablet:border-t-0">
        <aside aria-label="Finding group details" className="h-full overflow-y-auto">
          {selected ? (
            <GroupDetail key={selected.id} group={selected} onDeleted={() => set({ sel: undefined })} />
          ) : (
            <EmptyState title="Select a group">
              Choose a finding group from the list to view its member findings, correlate root causes, or manage membership.
            </EmptyState>
          )}
        </aside>
      </div>
      <CreateGroupDialog open={createOpen} onOpenChange={setCreateOpen} />
    </div>
  );
}

function GroupDetail({
  group,
  onDeleted,
}: {
  group: FindingGroup;
  onDeleted: () => void;
}) {
  const toast = useToast();
  const qc = useQueryClient();
  const { canAnywhere } = useAccess();
  const isMaintainer = canAnywhere('maintainer');

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

  const findings = detailQuery.data?.findings_ids ?? [];
  const problem = deleteMutation.isError ? toProblem(deleteMutation.error) : null;

  return (
    <article aria-label="Finding group detail" className="px-4 py-3">
      <h2 className="display text-16 leading-snug [overflow-wrap:anywhere]">{group.name}</h2>
      {group.description && <p className="mt-1 text-13 text-ink-2">{group.description}</p>}

      <dl className="m-0 mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-13">
        <dt className="text-ink-2">Owner</dt>
        <dd className="m-0">{group.owner ? group.owner.replace(/^user:/, '') : '—'}</dd>
        <dt className="text-ink-2">Findings</dt>
        <dd className="m-0 font-medium">{findings.length || group.member_count || 0}</dd>
        <dt className="text-ink-2">Created</dt>
        <dd className="m-0">{group.created_at ? absoluteDate(group.created_at) : '—'}</dd>
      </dl>

      <section className="mt-5">
        <h3 className="m-0 mb-2 text-13 font-semibold">Group Findings ({findings.length})</h3>
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
                {isMaintainer && (
                  <button
                    type="button"
                    onClick={() => removeMemberMutation.mutate(fId)}
                    disabled={removeMemberMutation.isPending}
                    className="text-11 text-critical hover:underline"
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
            Delete Group
          </Button>
        </div>
      )}
    </article>
  );
}

function CreateGroupDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const nameId = useId();
  const descId = useId();
  const toast = useToast();
  const qc = useQueryClient();

  const mutation = useMutation({
    mutationFn: () => createFindingGroup({ name: name.trim(), description: description.trim() || undefined }),
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
      <DialogContent title="Create Finding Group" description="Group findings across scans to manage them together.">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim()) mutation.mutate();
          }}
          className="flex flex-col gap-4 p-4"
        >
          <div className="flex flex-col gap-1.5">
            <label htmlFor={nameId} className="text-13 font-medium">
              Group Name <span className="text-critical">*</span>
            </label>
            <input
              id={nameId}
              type="text"
              required
              maxLength={255}
              placeholder="e.g. Critical Spring4Shell Remediation"
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
              placeholder="Explain the purpose or remediation context for this group..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="resize-y rounded-ctl border border-rule bg-surface px-3 py-1.5 text-13 text-ink focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </div>

          {problem && <ProblemMessage problem={problem} title="Failed to create group" />}

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
            <Button type="submit" variant="primary" loading={mutation.isPending} disabled={!name.trim()}>
              Create Group
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
