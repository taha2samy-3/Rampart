import { useId, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { qk, toProblem, triageFinding } from '@/api';
import type { FindingRow, Severity, TriageBody } from '@/api/types';
import { BAND_LABEL, Button, Dialog, DialogClose, DialogContent, Input, ProblemMessage, Select, useToast } from '@/components';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

/** Splits "a, b,,c" into tags; the server trims, removes duplicates and sorts them. */
export const splitTags = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean);

/**
 * "Edit" (docs/13 key a): owner, severity and tags of one finding. A severity different from the scanner's needs
 * a reason, as the server requires (D38); the owner must be a member of the tenant (D59). Only what changed is
 * sent, so the timeline records exactly what the person did.
 */
export function EditDialog({ row, open, onOpenChange }: { row: FindingRow; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation();
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && (
        <DialogContent title={t('edit.title')} description={t('edit.description')} closeLabel={t('common.close')}>
          <EditForm row={row} onDone={() => onOpenChange(false)} />
        </DialogContent>
      )}
    </Dialog>
  );
}

function EditForm({ row, onDone }: { row: FindingRow; onDone: () => void }) {
  const { t } = useTranslation();
  const toast = useToast();
  const qc = useQueryClient();
  const f = row.finding;
  const [owner, setOwner] = useState(f.owner ?? '');
  const [severity, setSeverity] = useState<Severity>(f.severity);
  const [reason, setReason] = useState('');
  const [tags, setTags] = useState((f.tags ?? []).join(', '));
  const ids = { owner: useId(), sev: useId(), reason: useId(), tags: useId() };

  const body: TriageBody = {};
  if (owner.trim() !== (f.owner ?? '')) body.owner = owner.trim();
  if (severity !== f.severity) {
    body.severity = severity;
    body.severityReason = reason.trim();
  }
  const nextTags = splitTags(tags);
  if (nextTags.join('\u0000') !== (f.tags ?? []).join('\u0000')) body.tags = nextTags;
  const changed = Object.keys(body).length > 0;
  const needsReason = body.severity !== undefined && !reason.trim();

  const mutation = useMutation({
    mutationFn: () => triageFinding(f.id, body, f.version),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.findings.all() });
      toast.info(t('edit.done'));
      onDone();
    },
  });
  const problem = mutation.isError ? toProblem(mutation.error) : null;

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (changed && !needsReason) mutation.mutate();
      }}
      className="flex flex-col gap-3 text-13"
    >
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.owner} className="font-medium">{t('edit.owner')}</label>
        <Input id={ids.owner} type="email" autoComplete="off" value={owner} onChange={(e) => setOwner(e.target.value)} />
        <p className="m-0 text-12 text-ink-2">{t('edit.ownerHelp')}</p>
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.sev} className="font-medium">{t('edit.severity')}</label>
        <Select
          label={t('edit.severity')}
          value={severity}
          onValueChange={(v) => setSeverity(v as Severity)}
          options={SEVERITIES.map((s) => ({ value: s, label: BAND_LABEL[s] }))}
        />
      </div>
      {severity !== f.severity && (
        <div className="flex flex-col gap-1">
          <label htmlFor={ids.reason} className="font-medium">{t('edit.severityReason')}</label>
          <Input id={ids.reason} value={reason} onChange={(e) => setReason(e.target.value)} aria-invalid={needsReason || undefined} />
          <p className="m-0 text-12 text-ink-2">{t('edit.severityReasonHelp')}</p>
        </div>
      )}
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.tags} className="font-medium">{t('edit.tags')}</label>
        <Input id={ids.tags} value={tags} onChange={(e) => setTags(e.target.value)} />
        <p className="m-0 text-12 text-ink-2">{t('edit.tagsHelp')}</p>
      </div>

      {problem && (
        <ProblemMessage problem={{ ...problem, detail: problem.detail ?? (problem.status === 400 ? problem.title : undefined) }} title={t('edit.failedTitle')} />
      )}

      <div className="flex justify-end gap-2 pt-1">
        <DialogClose asChild>
          <Button>{t('edit.cancel')}</Button>
        </DialogClose>
        <Button type="submit" variant="primary" loading={mutation.isPending} disabled={!changed || needsReason}>
          {mutation.isPending ? t('edit.submitting') : t('edit.submit')}
        </Button>
      </div>
    </form>
  );
}
