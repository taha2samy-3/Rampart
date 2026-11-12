import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { createBinding, deleteBinding, listApplications, listBindings, qk, toProblem } from '@/api';
import type { Role } from '@/api/types';
import { Button, EmptyState, Input, ProblemMessage, Select, Table, TBody, Td, Th, THead, Tr, useToast } from '@/components';
import { useAccess } from '@/app/useAccess';
import { ROLES_FOR_BINDING } from '@/lib/access';

/** Roles on single applications. An owner manages the applications they own; an administrator, all. */
export function AccessSection() {
  const { t } = useTranslation();
  const toast = useToast();
  const qc = useQueryClient();
  const { can } = useAccess();
  const bindings = useQuery({ queryKey: qk.bindings(), queryFn: ({ signal }) => listBindings(signal), retry: false });
  const apps = useQuery({ queryKey: qk.applications.list(), queryFn: ({ signal }) => listApplications(signal), staleTime: 60_000 });
  const mine = (apps.data ?? []).filter((a) => can(a.id, 'owner'));
  const [subject, setSubject] = useState('');
  const [role, setRole] = useState<Role>('triager');
  const [app, setApp] = useState('');
  const refresh = () => qc.invalidateQueries({ queryKey: qk.bindings() });
  const add = useMutation({
    mutationFn: () => createBinding({ subject: subject.trim(), role, applicationId: app }),
    onSuccess: () => { setSubject(''); toast.info(t('admin.given')); return refresh(); },
    onError: (e) => toast.problem(toProblem(e)),
  });
  const remove = useMutation({
    mutationFn: (id: string) => deleteBinding(id),
    onSuccess: () => { toast.info(t('admin.removed')); return refresh(); },
    onError: (e) => toast.problem(toProblem(e)),
  });
  const rows = bindings.data ?? [];
  return (
    <section className="mt-8" aria-labelledby="access-h">
      <h2 id="access-h" className="text-13 font-semibold">{t('admin.accessTitle')}</h2>
      <p className="m-0 mt-1 text-13 text-ink-2">{t('admin.accessIntro')}</p>
      <form
        className="mt-3 flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (subject.trim() && app) add.mutate();
        }}
      >
        <Input aria-label={t('admin.subject')} placeholder={t('admin.subject')} value={subject} onChange={(e) => setSubject(e.target.value)} className="w-[240px]" />
        <Select label={t('admin.accessRole')} value={role} onValueChange={(v) => setRole(v as Role)} options={ROLES_FOR_BINDING.map((r) => ({ value: r, label: t(`admin.roles.${r}`) }))} />
        <Select label={t('admin.accessApp')} value={app} onValueChange={setApp} options={[{ value: '', label: t('admin.chooseApp') }, ...mine.map((a) => ({ value: a.id, label: a.name }))]} />
        <Button type="submit" loading={add.isPending} disabled={!subject.trim() || !app}>{t('admin.giveAccess')}</Button>
      </form>
      <div className="mt-3">
        {bindings.isError && <ProblemMessage problem={toProblem(bindings.error)} title={t('admin.accessFailed')} onRetry={() => void bindings.refetch()} />}
        {bindings.data && rows.length === 0 && <EmptyState className="p-0 text-left" title={t('admin.accessEmpty')} />}
        {rows.length > 0 && (
          <Table aria-label={t('admin.accessTable')}>
            <colgroup><col /><col className="w-[120px]" /><col className="w-[200px]" /><col className="w-[90px]" /></colgroup>
            <THead>
              <tr>
                <Th>{t('admin.accessWho')}</Th>
                <Th>{t('admin.accessRole')}</Th>
                <Th>{t('admin.accessApp')}</Th>
                <Th align="end"><span className="sr-only">{t('admin.remove')}</span></Th>
              </tr>
            </THead>
            <TBody>
              {rows.map((b) => (
                <Tr key={b.id}>
                  <Td className="truncate" title={`${t('admin.accessBy')}: ${b.created_by.replace(/^user:/, '')}`}>{b.subject}</Td>
                  <Td>{t(`admin.roles.${b.role}`)}</Td>
                  <Td className="truncate">{b.application_name ?? b.application_id}</Td>
                  <Td align="end">
                    <Button
                      variant="ghost"
                      aria-label={t('admin.removeLabel', { role: t(`admin.roles.${b.role}`).toLowerCase(), who: b.subject, app: b.application_name ?? b.application_id })}
                      disabled={b.managed_by !== 'api' || remove.isPending}
                      onClick={() => remove.mutate(b.id)}
                    >
                      {t('admin.remove')}
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
