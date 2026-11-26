import { useEffect, useId, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { attestControl, getTaxonomyHistory, getTaxonomyStatus, listApplications, listTaxonomies, qk, taxonomyCsvUrl, toProblem } from '@/api';
import type { ControlStatus, Taxonomy } from '@/api/types';
import { BandShape, Button, FrameworkMark, Dialog, DialogContent, EmptyState, ProblemMessage, Select, Skeleton, Table, TBody, Td, Th, THead, Tr, useToast } from '@/components';
import { useAccess } from '@/app/useAccess';
import { openText, worstBand } from '@/lib/apps';
import { absoluteDate } from '@/lib/format';

const ACTIVE = 'state:open,under_investigation,affected';

function frameworkLabel(f: Taxonomy, t: (k: string) => string): string {
  const origin = f.origin && f.origin !== 'builtin' ? ` (${t(`compliance.origin_${f.origin}`)})` : '';
  return `${f.name} ${f.version}${origin}`;
}

/**
 * Frameworks and the reading of each control (D52, D102): what is open against it, whether a scan that could show a
 * problem ran, approved exceptions, and the controls a person attests. Each status carries the sentence that says
 * why, so the table can be read without knowing the rules.
 */
/** `framework` and `application` open the page on one framework read for one application (the application page links here). */
export interface ComplianceSearch { framework?: string; application?: string }

export function ComplianceRoute({ search }: { search?: ComplianceSearch } = {}) {
  const { t } = useTranslation();
  useEffect(() => {
    document.title = `${t('compliance.title')} - Rampart`;
  }, [t]);
  const frameworks = useQuery({ queryKey: qk.taxonomies(), queryFn: ({ signal }) => listTaxonomies(signal), staleTime: 300_000 });
  const apps = useQuery({ queryKey: qk.applications.list(), queryFn: ({ signal }) => listApplications(signal), staleTime: 60_000 });
  const [picked, setPicked] = useState(search?.framework ?? '');
  const [app, setApp] = useState(search?.application ?? '');
  const [day, setDay] = useState('');
  const usable = (frameworks.data ?? []).filter((f) => !f.error);
  const broken = (frameworks.data ?? []).filter((f) => f.error);
  const fw = usable.some((f) => f.id === picked) ? picked : usable[0]?.id || '';
  const fwInfo = usable.find((f) => f.id === fw);
  const at = app ? '' : day; // a kept reading is for the whole tenant
  const history = useQuery({ queryKey: qk.taxonomyHistory(fw), queryFn: ({ signal }) => getTaxonomyHistory(fw, signal), enabled: !!fw, retry: false });
  const status = useQuery({ queryKey: qk.taxonomyStatus(fw, app, at), queryFn: ({ signal }) => getTaxonomyStatus(fw, app, signal, at), enabled: !!fw, retry: false });
  const st = status.data;
  const [attesting, setAttesting] = useState<ControlStatus | null>(null);
  const { can } = useAccess();
  const mayAttest = !at && can(app || undefined, 'maintainer');

  return (
    <div className="mx-auto max-w-[1080px] px-6 py-5">
      <h1 className="display text-28">{t('compliance.title')}</h1>
      {frameworks.data?.length === 0 && <EmptyState className="p-0 text-left" title={t('compliance.emptyTitle')} />}
      {fw && (
        <>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Select label={t('compliance.framework')} value={fw} onValueChange={(v) => { setPicked(v); setDay(''); }} options={usable.map((f) => ({ value: f.id, label: frameworkLabel(f, t) }))} />
            <Select label={t('compliance.application')} value={app} onValueChange={setApp} options={[{ value: '', label: t('compliance.allApps') }, ...(apps.data ?? []).map((a) => ({ value: a.id, label: a.name }))]} />
            {!app && (history.data?.length ?? 0) > 0 && (
              <Select label={t('compliance.asOf')} value={day} onValueChange={setDay} options={[{ value: '', label: t('compliance.today') }, ...(history.data ?? []).map((d) => ({ value: d, label: d }))]} />
            )}
            <a className="ms-auto text-13" href={taxonomyCsvUrl(fw, app || undefined, at || undefined)} download>{t('compliance.export')}</a>
          </div>
          {fwInfo && (
            <div className="mt-4 flex items-center gap-3">
              <FrameworkMark id={fwInfo.id} name={fwInfo.name} origin={fwInfo.origin} logo={fwInfo.logo} size={36} />
              <h2 className="display m-0 text-16">{fwInfo.name} <span className="font-normal text-ink-2">{fwInfo.version}</span></h2>
            </div>
          )}
          {st && (
            <div className="mt-2 max-w-[80ch] text-12 text-ink-2">
              {st.note && <p className="m-0">{st.note}</p>}
              {st.scope && <p className="m-0 mt-1">{t('compliance.scopeNote', { scope: st.scope })}</p>}
              <p className="m-0 mt-1">{t('compliance.meaning')}</p>
              <p className="m-0 mt-1">
                {st.historical ? t('compliance.evaluatedPast', { day: at }) : t('compliance.evaluated', { date: absoluteDate(st.evaluated_at), days: st.window_days })}{' '}
                {st.source && (
                  <>
                    {t('compliance.source')}: <a href={st.source} rel="noreferrer noopener" target="_blank">{st.source}</a>
                  </>
                )}
              </p>
            </div>
          )}
          {broken.length > 0 && (
            <section aria-labelledby="fw-broken" className="mt-3 max-w-[80ch] text-12">
              <h2 id="fw-broken" className="m-0 text-13 font-semibold">{t('compliance.broken')}</h2>
              <p className="m-0 text-ink-2">{t('compliance.brokenHelp')}</p>
              <ul className="m-0 mt-1 ps-5">
                {broken.map((b) => <li key={`${b.origin}-${b.id}`}><span className="font-medium">{b.name}</span>: {b.error}</li>)}
              </ul>
            </section>
          )}
          <div className="mt-3">
            {status.isPending && (
              <div aria-busy="true" aria-label={t('common.loading')}>
                {Array.from({ length: 6 }, (_, i) => <div key={i} className="flex h-[46px] items-center border-b border-rule"><Skeleton className="h-3 flex-1" /></div>)}
              </div>
            )}
            {status.isError && <StatusError problem={toProblem(status.error)} onRetry={() => void status.refetch()} />}
            {st && (
              <Table aria-label={t('compliance.tableLabel')}>
                <colgroup><col className="w-[100px]" /><col /><col className="w-[300px]" /><col className="w-[230px]" /></colgroup>
                <THead>
                  <tr>
                    <Th>{t('compliance.colControl')}</Th>
                    <Th><span className="sr-only">{t('compliance.colControl')}</span></Th>
                    <Th>{t('compliance.colStatus')}</Th>
                    <Th>{t('compliance.colOpen')}</Th>
                  </tr>
                </THead>
                <TBody>
                  {st.status.map((c) => (
                    <ControlRow key={c.id} c={c} onAttest={mayAttest && c.manual ? () => setAttesting(c) : undefined} />
                  ))}
                </TBody>
              </Table>
            )}
          </div>
          {attesting && <AttestDialog framework={fw} control={attesting} application={app} onClose={() => setAttesting(null)} />}
        </>
      )}
    </div>
  );
}

function ControlRow({ c, onAttest }: { c: ControlStatus; onAttest?: () => void }) {
  const { t } = useTranslation();
  const worst = worstBand(c.bands);
  const accepted = c.accepted ?? 0;
  const acceptedQuery = c.query ? c.query.replace(ACTIVE, 'state:risk_accepted') : '';
  return (
    <Tr className="align-top">
      <Td className="py-2 font-mono text-12">{c.id}</Td>
      <Td className="!whitespace-normal py-2">
        {c.name}
        {c.description && <span className="block text-12 text-ink-2">{c.description}</span>}
      </Td>
      <Td className="!whitespace-normal py-2">
        {/* plain words, no pill: colour is for risk (docs/13 §6); "not met" is the one that is bold */}
        <span className={c.status === 'open' ? 'font-semibold' : c.status === 'not_assessed' ? 'text-ink-2' : ''}>{t(`compliance.status.${c.status}`)}</span>
        {c.reason && <span className="block text-12 text-ink-2">{c.reason}</span>}
        {!c.manual && c.evidence && c.evidence.length > 0 && <span className="block text-12 text-ink-2">{t('compliance.evidence', { tools: c.evidence.join(', ') })}</span>}
        {c.attestation?.evidence_url && (
          <a className="block text-12" href={c.attestation.evidence_url} rel="noreferrer noopener" target="_blank">{t('compliance.evidenceLink')}</a>
        )}
        {onAttest && <Button className="mt-1" onClick={onAttest}>{t('compliance.attest')}</Button>}
      </Td>
      <Td className="!whitespace-normal py-2">
        {c.manual ? (
          <span className="text-ink-2">—</span>
        ) : c.open > 0 ? (
          <>
            <span className="inline-flex items-center gap-1.5">
              {worst && <BandShape band={worst} />}
              {c.open}: {openText(c.bands, t)}
            </span>
            {c.query && (
              <Link to="/findings" search={{ q: c.query }} className="block text-12" title={c.query_exact === false ? t('compliance.partialLinkHelp') : undefined}>
                {c.query_exact === false ? t('compliance.partialLink') : t('compliance.seeFindings')}
              </Link>
            )}
          </>
        ) : (
          <span className="text-ink-2">{t('compliance.noneOpen')}</span>
        )}
        {accepted > 0 && (
          acceptedQuery ? (
            <Link to="/findings" search={{ q: acceptedQuery }} className="block text-12">{t('compliance.accepted', { count: accepted })}</Link>
          ) : (
            <span className="block text-12 text-ink-2">{t('compliance.accepted', { count: accepted })}</span>
          )
        )}
      </Td>
    </Tr>
  );
}

/** A day, in UTC, this many days from now: the server reads the chosen day as its last second (UTC), and wants it in the future and within three years. */
function utcDay(daysAhead: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + daysAhead);
  return d.toISOString().slice(0, 10);
}

function inAYear(): string {
  const d = new Date();
  d.setFullYear(d.getFullYear() + 1);
  return d.toISOString().slice(0, 10);
}

export function AttestDialog({ framework, control, application, onClose }: { framework: string; control: ControlStatus; application: string; onClose: () => void }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const toast = useToast();
  const [met, setMet] = useState<'passed' | 'failed'>('passed');
  const [note, setNote] = useState('');
  const [link, setLink] = useState('');
  const [until, setUntil] = useState(inAYear);
  const [owner, setOwner] = useState('');
  const ownerId = useId();
  const noteId = useId();
  const linkId = useId();
  const untilId = useId();
  const untilHelp = useId();
  const mutation = useMutation({
    mutationFn: () =>
      attestControl(framework, control.id, {
        status: met,
        note: note.trim(),
        evidence_url: link.trim() || undefined,
        expires_at: until ? new Date(`${until}T23:59:59Z`).toISOString() : undefined,
        application_id: application || undefined,
        owner: owner.trim() || undefined,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['taxonomies', 'status', framework] });
      void qc.invalidateQueries({ queryKey: ['taxonomies', 'history', framework] });
      if (application) void qc.invalidateQueries({ queryKey: qk.applications.compliance(application) }); // the application's own summary
      toast.info(t('compliance.attestSaved'));
      onClose();
    },
  });
  const field = 'rounded-ctl border border-rule bg-surface px-3 py-1.5 text-13 text-ink focus:outline-none focus:ring-1 focus:ring-accent';
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={t('compliance.attestTitle', { id: control.id })} description={t('compliance.attestDescription')}>
        <form
          className="flex flex-col gap-4 p-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (note.trim()) mutation.mutate();
          }}
        >
          <p className="m-0 text-13">{control.name}</p>
          <fieldset className="m-0 flex gap-4 border-0 p-0">
            <legend className="mb-1.5 text-13 font-medium">{t('compliance.colStatus')}</legend>
            {(['passed', 'failed'] as const).map((v) => (
              <label key={v} className="inline-flex items-center gap-1.5 text-13">
                <input type="radio" name="met" value={v} checked={met === v} onChange={() => setMet(v)} />
                {v === 'passed' ? t('compliance.attestMet') : t('compliance.attestNotMet')}
              </label>
            ))}
          </fieldset>
          <div className="flex flex-col gap-1.5">
            <label htmlFor={noteId} className="text-13 font-medium">{t('compliance.attestNote')}</label>
            <textarea id={noteId} rows={3} required maxLength={4000} value={note} onChange={(e) => setNote(e.target.value)}
              placeholder={t('compliance.attestNotePlaceholder')} className={`resize-y ${field}`} />
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor={linkId} className="text-13 font-medium">{t('compliance.attestEvidence')}</label>
            <input id={linkId} type="url" pattern="https://.*" value={link} onChange={(e) => setLink(e.target.value)} placeholder="https://" className={field} />
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor={ownerId} className="text-13 font-medium">{t('compliance.attestOwner')}</label>
            <input id={ownerId} type="text" maxLength={200} value={owner} onChange={(e) => setOwner(e.target.value)} aria-describedby={`${ownerId}-help`} className={`w-full ${field}`} />
            <span id={`${ownerId}-help`} className="text-12 text-ink-2">{t('compliance.attestOwnerHelp')}</span>
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor={untilId} className="text-13 font-medium">{t('compliance.attestExpires')}</label>
            <input id={untilId} type="date" required min={utcDay(1)} max={utcDay(3 * 365 - 1)} value={until} onChange={(e) => setUntil(e.target.value)} aria-describedby={untilHelp} className={`w-fit ${field}`} />
            <span id={untilHelp} className="text-12 text-ink-2">{t('compliance.attestExpiresHelp')}</span>
          </div>
          {mutation.isError && <ProblemMessage problem={toProblem(mutation.error)} title={t('compliance.attestFailed')} />}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" onClick={onClose}>{t('common.cancel', { defaultValue: 'Cancel' })}</Button>
            <Button type="submit" variant="primary" loading={mutation.isPending} disabled={!note.trim()}>{t('compliance.attestSave')}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Why there is no reading. A 404 with a reason is the server refusing on purpose (the framework does not apply to
 * that application, or no reading was kept for that day): its own sentence is shown, as a fact and with no
 * Try again, since trying again gives the same answer (docs/41). Anything else is a failure.
 */
function StatusError({ problem, onRetry }: { problem: ReturnType<typeof toProblem>; onRetry: () => void }) {
  const { t } = useTranslation();
  if (problem.status === 404 && problem.detail) {
    return (
      <div role="status" data-testid="compliance-refusal" className="border-s-2 border-rule ps-3 text-13">
        <p className="m-0 font-semibold text-ink">{t('compliance.refusedTitle')}</p>
        <p className="m-0 mt-0.5 max-w-[80ch] text-ink-2">{problem.detail}</p>
      </div>
    );
  }
  return <ProblemMessage problem={problem} title={t('compliance.loadFailed')} onRetry={onRetry} />;
}
