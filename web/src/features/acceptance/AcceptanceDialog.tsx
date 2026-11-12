import { useId, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getSettings, qk, requestAcceptance, toProblem } from '@/api';
import type { FindingRow } from '@/api/types';
import { Button, Dialog, DialogClose, DialogContent, Input, ProblemMessage, Select, useToast } from '@/components';
import { useSession } from '@/app/session';

const DAY = 86_400_000;
const isoDay = (ms: number) => new Date(ms).toISOString().slice(0, 10);

/**
 * "Request risk acceptance" (docs/06 section 6): a reason, an owner and an end date. Without tenant approval the
 * risk is accepted at once; with it the request waits for an admin who is not you. The end date is required and
 * capped by the tenant's maximum, because an acceptance has to end (docs/16 D39).
 */
export function AcceptanceDialog({ row, open, onOpenChange }: { row: FindingRow; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation();
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && (
        <DialogContent title={t('acceptance.title')} description={t('acceptance.description')} closeLabel={t('common.close')}>
          <AcceptanceForm row={row} onDone={() => onOpenChange(false)} />
        </DialogContent>
      )}
    </Dialog>
  );
}

function AcceptanceForm({ row, onDone }: { row: FindingRow; onDone: () => void }) {
  const { t } = useTranslation();
  const toast = useToast();
  const qc = useQueryClient();
  const { session } = useSession();
  const settings = useQuery({ queryKey: qk.settings(), queryFn: ({ signal }) => getSettings(signal) });
  const maxDays = settings.data?.riskAcceptanceMaxDays ?? 180;
  // Fixed for the life of the dialog, so the bounds of the date field do not move while it is open.
  const [now] = useState(() => Date.now());
  const [why, setWhy] = useState('');
  const [impact, setImpact] = useState('');
  const [until, setUntil] = useState(() => isoDay(now + 30 * DAY));
  const [owner, setOwner] = useState('');
  const [onExpiry, setOnExpiry] = useState<'reactivate' | 'notify_only'>('reactivate');
  const ids = { why: useId(), impact: useId(), until: useId(), owner: useId() };

  const mutation = useMutation({
    mutationFn: () =>
      requestAcceptance({
        findingIds: [row.finding.id],
        justification: why.trim(),
        impactStatement: impact.trim() || undefined,
        owner: owner.trim() || undefined,
        // The end of the chosen day, so "until the 12th" includes the 12th.
        expiresAt: new Date(`${until}T23:59:59Z`).toISOString(),
        onExpiry,
      }),
    onSuccess: (out) => {
      void qc.invalidateQueries({ queryKey: qk.findings.all() });
      void qc.invalidateQueries({ queryKey: qk.acceptances.all() });
      toast.info(t(out.acceptance.status === 'approved' ? 'acceptance.sentApproved' : 'acceptance.sentPending'));
      onDone();
    },
  });
  const problem = mutation.isError ? toProblem(mutation.error) : null;
  const canSubmit = why.trim() !== '' && until !== '';

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (canSubmit) mutation.mutate();
      }}
      className="flex flex-col gap-3 text-13"
    >
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.why} className="font-medium">{t('acceptance.justification')}</label>
        <textarea
          id={ids.why}
          rows={3}
          required
          value={why}
          onChange={(e) => setWhy(e.target.value)}
          className="w-full resize-y rounded-ctl border border-rule bg-surface px-2.5 py-1.5 text-13 text-ink"
        />
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.impact} className="font-medium">{t('acceptance.impact')}</label>
        <Input id={ids.impact} value={impact} onChange={(e) => setImpact(e.target.value)} />
        <p className="m-0 text-12 text-ink-2">{t('acceptance.impactHelp')}</p>
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.until} className="font-medium">{t('acceptance.expires')}</label>
        <Input id={ids.until} type="date" required value={until} min={isoDay(now + DAY)} max={isoDay(now + maxDays * DAY)} onChange={(e) => setUntil(e.target.value)} />
        <p className="m-0 text-12 text-ink-2">{t('acceptance.expiresHelp', { days: maxDays })}</p>
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.owner} className="font-medium">{t('acceptance.owner')}</label>
        <Input id={ids.owner} placeholder={session.user.email} value={owner} onChange={(e) => setOwner(e.target.value)} />
        <p className="m-0 text-12 text-ink-2">{t('acceptance.ownerHelp')}</p>
      </div>
      <div className="flex flex-col gap-1">
        <span className="font-medium">{t('acceptance.onExpiry')}</span>
        <Select
          label={t('acceptance.onExpiry')}
          value={onExpiry}
          onValueChange={(v) => setOnExpiry(v as 'reactivate' | 'notify_only')}
          options={[
            { value: 'reactivate', label: t('acceptance.onExpiryReactivate') },
            { value: 'notify_only', label: t('acceptance.onExpiryNotify') },
          ]}
        />
      </div>

      {problem && (
        <ProblemMessage problem={{ ...problem, detail: problem.detail ?? (problem.status === 400 ? problem.title : undefined) }} title={t('acceptance.failedTitle')} />
      )}

      <div className="flex justify-end gap-2 pt-1">
        <DialogClose asChild>
          <Button>{t('triage.cancel')}</Button>
        </DialogClose>
        <Button type="submit" variant="primary" loading={mutation.isPending} disabled={!canSubmit}>
          {mutation.isPending ? t('acceptance.submitting') : t('acceptance.submit')}
        </Button>
      </div>
    </form>
  );
}
