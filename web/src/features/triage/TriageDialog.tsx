import { useId, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { qk, toProblem, triageFinding } from '@/api';
import type { FindingRow, FindingState, TriageBody } from '@/api/types';
import { Button, Dialog, DialogClose, DialogContent, Input, ProblemMessage, Select, useToast } from '@/components';
import { JUSTIFICATIONS, nextStates } from '@/lib/triage';

/**
 * "Change state" (docs/13): the decision, why, and who made it goes on the timeline. A not_affected decision
 * must carry an OpenVEX justification, a duplicate the finding it repeats. The server enforces the same rules;
 * this keeps the analyst from sending a request it would refuse, and shows the server's reason when it does.
 */
export function TriageDialog({ row, open, onOpenChange }: { row: FindingRow; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation();
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && (
        <DialogContent title={t('triage.title')} description={t('triage.description')} closeLabel={t('common.close')}>
          <TriageForm row={row} onDone={() => onOpenChange(false)} />
        </DialogContent>
      )}
    </Dialog>
  );
}

function TriageForm({ row, onDone }: { row: FindingRow; onDone: () => void }) {
  const { t } = useTranslation();
  const toast = useToast();
  const qc = useQueryClient();
  const f = row.finding;
  const options = nextStates(f.state);
  const [state, setState] = useState<FindingState>(options[0] ?? 'open');
  const [justification, setJustification] = useState<string>(JUSTIFICATIONS[0]);
  const [impact, setImpact] = useState('');
  const [duplicateOf, setDuplicateOf] = useState('');
  const [note, setNote] = useState('');
  const ids = { state: useId(), just: useId(), impact: useId(), dup: useId(), note: useId() };

  const mutation = useMutation({
    mutationFn: () => {
      const body: TriageBody = { state, note: note.trim() || undefined };
      if (state === 'not_affected') {
        body.justification = justification;
        body.impactStatement = impact.trim() || undefined;
      }
      if (state === 'duplicate') body.duplicateOf = duplicateOf.trim();
      return triageFinding(f.id, body, f.version);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.findings.all() });
      toast.info(t('triage.done'));
      onDone();
    },
  });
  const problem = mutation.isError ? toProblem(mutation.error) : null;
  const conflict = problem?.status === 409;
  const canSubmit = state !== 'duplicate' || duplicateOf.trim() !== '';

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (canSubmit) mutation.mutate();
      }}
      className="flex flex-col gap-3 text-13"
    >
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.state} className="font-medium">{t('triage.newState')}</label>
        <Select
          label={t('triage.newState')}
          value={state}
          onValueChange={(v) => setState(v as FindingState)}
          options={options.map((s) => ({ value: s, label: t(`state.${s}`, { defaultValue: s }) }))}
        />
      </div>

      {state === 'not_affected' && (
        <>
          <div className="flex flex-col gap-1">
            <label htmlFor={ids.just} className="font-medium">{t('triage.justification')}</label>
            <Select
              label={t('triage.justification')}
              value={justification}
              onValueChange={setJustification}
              options={JUSTIFICATIONS.map((j) => ({ value: j, label: t(`triage.justifications.${j}`) }))}
            />
            <p className="m-0 text-12 text-ink-2">{t('triage.justificationHelp')}</p>
          </div>
          <div className="flex flex-col gap-1">
            <label htmlFor={ids.impact} className="font-medium">{t('triage.impact')}</label>
            <Input id={ids.impact} value={impact} onChange={(e) => setImpact(e.target.value)} />
            <p className="m-0 text-12 text-ink-2">{t('triage.impactHelp')}</p>
          </div>
        </>
      )}

      {state === 'duplicate' && (
        <div className="flex flex-col gap-1">
          <label htmlFor={ids.dup} className="font-medium">{t('triage.duplicateOf')}</label>
          <Input id={ids.dup} mono value={duplicateOf} onChange={(e) => setDuplicateOf(e.target.value)} />
          <p className="m-0 text-12 text-ink-2">{t('triage.duplicateHelp')}</p>
        </div>
      )}

      <div className="flex flex-col gap-1">
        <label htmlFor={ids.note} className="font-medium">{t('triage.note')}</label>
        <textarea
          id={ids.note}
          rows={3}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          className="w-full resize-y rounded-ctl border border-rule bg-surface px-2.5 py-1.5 text-13 text-ink"
        />
        <p className="m-0 text-12 text-ink-2">{t('triage.noteHelp')}</p>
      </div>

      {problem && (
        <ProblemMessage
          problem={{ ...problem, detail: problem.detail ?? (problem.status === 400 ? problem.title : undefined) }}
          title={conflict ? t('triage.conflictTitle') : t('triage.failedTitle')}
          next={conflict ? t('triage.conflictBody') : undefined}
        />
      )}

      <div className="flex justify-end gap-2 pt-1">
        {conflict && (
          <Button onClick={() => { void qc.invalidateQueries({ queryKey: qk.findings.all() }); onDone(); }}>{t('triage.reload')}</Button>
        )}
        <DialogClose asChild>
          <Button>{t('triage.cancel')}</Button>
        </DialogClose>
        <Button type="submit" variant="primary" loading={mutation.isPending} disabled={!canSubmit}>
          {mutation.isPending ? t('triage.submitting') : t('triage.submit')}
        </Button>
      </div>
    </form>
  );
}
