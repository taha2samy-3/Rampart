import { useId, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { bulkTriage, qk, toProblem } from '@/api';
import type { BulkResult, FindingState, TriageBody } from '@/api/types';
import { Button, Dialog, DialogClose, DialogContent, Input, ProblemMessage, Select } from '@/components';
import { splitTags } from '@/features/triage/EditDialog';
import { JUSTIFICATIONS } from '@/lib/triage';

/** States a bulk change may set; each finding still takes only the moves the server allows (D38). */
const BULK_STATES: FindingState[] = ['under_investigation', 'affected', 'not_affected', 'out_of_scope', 'fixed'];

/**
 * The bar under the list while findings are selected (docs/13 section 5: "Bulk bar appears on selection").
 * "Select all N matching" switches from ids to the filter, so a change can reach findings not loaded yet.
 */
export function BulkBar({
  ids,
  all,
  total,
  q,
  onSelectAll,
  onClear,
}: {
  ids: string[];
  all: boolean;
  total: number | undefined;
  q: string;
  onSelectAll: () => void;
  onClear: () => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const count = all ? (total ?? ids.length) : ids.length;
  return (
    <div role="region" aria-label={t('bulk.action')} className="flex flex-wrap items-center gap-2 border-t border-rule bg-chrome px-3 py-2 text-13">
      <span aria-live="polite" className="font-medium">
        {all ? t('bulk.allMatching', { count }) : t('bulk.selected', { count })}
      </span>
      {!all && total !== undefined && total > ids.length && (
        <Button onClick={onSelectAll}>{t('bulk.selectAll', { count: total })}</Button>
      )}
      <span className="flex-1" />
      <Button variant="primary" onClick={() => setOpen(true)}>{t('bulk.action')}</Button>
      <Button onClick={onClear}>{t('bulk.clear')}</Button>
      <Dialog open={open} onOpenChange={setOpen}>
        {open && (
          <DialogContent
            title={all ? t('bulk.titleAll') : t('bulk.title', { count })}
            description={t('bulk.description')}
            closeLabel={t('common.close')}
          >
            <BulkForm target={all ? { q } : { ids }} onDone={() => { setOpen(false); onClear(); }} />
          </DialogContent>
        )}
      </Dialog>
    </div>
  );
}

function BulkForm({ target, onDone }: { target: { ids: string[] } | { q: string }; onDone: () => void }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [state, setState] = useState<FindingState | ''>('');
  const [justification, setJustification] = useState<string>(JUSTIFICATIONS[0]);
  const [owner, setOwner] = useState('');
  const [addTags, setAddTags] = useState('');
  const [removeTags, setRemoveTags] = useState('');
  const [note, setNote] = useState('');
  const [result, setResult] = useState<BulkResult | null>(null);
  const ids = { state: useId(), just: useId(), owner: useId(), add: useId(), remove: useId(), note: useId() };

  const patch: TriageBody = {};
  if (state) patch.state = state;
  if (state === 'not_affected') patch.justification = justification;
  const o = owner.trim();
  if (o) patch.owner = o.toLowerCase() === 'nobody' ? '' : o;
  if (splitTags(addTags).length) patch.addTags = splitTags(addTags);
  if (splitTags(removeTags).length) patch.removeTags = splitTags(removeTags);
  if (note.trim()) patch.note = note.trim();
  const changed = Object.keys(patch).some((k) => k !== 'note' && k !== 'justification');

  const mutation = useMutation({
    mutationFn: () => bulkTriage({ ...target, patch }),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: qk.findings.all() });
      setResult(r);
    },
  });
  const problem = mutation.isError ? toProblem(mutation.error) : null;

  if (result) {
    const failed = result.failed ?? [];
    return (
      <div className="flex flex-col gap-3 text-13">
        <p className="m-0" role="status">{t('bulk.result', { updated: result.updated, unchanged: result.unchanged, failed: failed.length })}</p>
        {failed.length > 0 && (
          <section aria-label={t('bulk.failedList')}>
            <h3 className="m-0 mb-1 text-13 font-semibold">{t('bulk.failedList')}</h3>
            <ul className="m-0 list-none p-0">
              {failed.map((x) => (
                <li key={x.id} className="border-b border-rule py-1">
                  <span className="font-mono text-12">{x.id.slice(0, 8)}</span> {x.error}
                </li>
              ))}
            </ul>
          </section>
        )}
        <div className="flex justify-end">
          <Button variant="primary" onClick={onDone}>{t('bulk.close')}</Button>
        </div>
      </div>
    );
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (changed) mutation.mutate();
      }}
      className="flex flex-col gap-3 text-13"
    >
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.state} className="font-medium">{t('bulk.state')}</label>
        <Select
          label={t('bulk.state')}
          value={state}
          onValueChange={(v) => setState(v as FindingState | '')}
          options={[{ value: '', label: t('bulk.stateKeep') }, ...BULK_STATES.map((s) => ({ value: s, label: t(`state.${s}`, { defaultValue: s }) }))]}
        />
      </div>
      {state === 'not_affected' && (
        <div className="flex flex-col gap-1">
          <label htmlFor={ids.just} className="font-medium">{t('triage.justification')}</label>
          <Select
            label={t('triage.justification')}
            value={justification}
            onValueChange={setJustification}
            options={JUSTIFICATIONS.map((j) => ({ value: j, label: t(`triage.justifications.${j}`) }))}
          />
        </div>
      )}
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.owner} className="font-medium">{t('bulk.owner')}</label>
        <Input id={ids.owner} autoComplete="off" value={owner} onChange={(e) => setOwner(e.target.value)} />
        <p className="m-0 text-12 text-ink-2">{t('bulk.ownerHelp')}</p>
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.add} className="font-medium">{t('bulk.addTags')}</label>
        <Input id={ids.add} value={addTags} onChange={(e) => setAddTags(e.target.value)} />
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.remove} className="font-medium">{t('bulk.removeTags')}</label>
        <Input id={ids.remove} value={removeTags} onChange={(e) => setRemoveTags(e.target.value)} />
        <p className="m-0 text-12 text-ink-2">{t('edit.tagsHelp')}</p>
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor={ids.note} className="font-medium">{t('triage.note')}</label>
        <Input id={ids.note} value={note} onChange={(e) => setNote(e.target.value)} />
      </div>
      {problem && (
        <ProblemMessage
          problem={{ ...problem, detail: problem.detail ?? (problem.status === 400 || problem.status === 422 ? problem.title : undefined) }}
          title={problem.status === 422 ? t('bulk.tooMany') : t('edit.failedTitle')}
        />
      )}
      <div className="flex justify-end gap-2 pt-1">
        <DialogClose asChild>
          <Button>{t('edit.cancel')}</Button>
        </DialogClose>
        <Button type="submit" variant="primary" loading={mutation.isPending} disabled={!changed}>
          {t('bulk.submit')}
        </Button>
      </div>
    </form>
  );
}
