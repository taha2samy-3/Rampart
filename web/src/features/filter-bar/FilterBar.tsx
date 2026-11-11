import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { IconButton, IconFilter, IconX, Input } from '@/components';
import { describeTerm, parseQuery, removeTerm } from '@/lib/grammar';

/**
 * The typed filter. The input is the source of truth; chips are a read-out of
 * the parsed grammar (docs/16 D16) with one remove button per term. The `q`
 * string is written to the URL after a short pause.
 */
export function FilterBar({
  q,
  onQueryChange,
  total,
  onOpenFilters,
}: {
  q: string;
  onQueryChange: (q: string) => void;
  total: number | undefined;
  onOpenFilters?: () => void;
}) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState(q);
  const written = useRef(q);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // The URL changed from outside (facet, global search, back button).
  useEffect(() => {
    if (q !== written.current) {
      written.current = q;
      setDraft(q);
    }
  }, [q]);
  useEffect(() => () => clearTimeout(timer.current), []);

  const commit = (value: string) => {
    clearTimeout(timer.current);
    written.current = value;
    onQueryChange(value);
  };
  const onChange = (value: string) => {
    setDraft(value);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => commit(value), 250);
  };

  const parsed = parseQuery(draft);
  return (
    <div className="border-b border-rule">
      <div className="flex min-h-11 items-center gap-2 px-3 py-1.5">
        {onOpenFilters && (
          <IconButton label={t('findings.filters')} variant="secondary" onClick={onOpenFilters}>
            <IconFilter />
          </IconButton>
        )}
        <Input
          mono
          type="text"
          spellCheck={false}
          autoComplete="off"
          aria-label={t('findings.queryLabel')}
          aria-describedby="query-help"
          placeholder={t('findings.queryPlaceholder')}
          value={draft}
          invalid={!!parsed.error}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && commit(draft)}
          className="min-w-0 flex-1"
        />
        <p className="shrink-0 text-13 text-ink-2 tnum" aria-live="polite">
          {total === undefined ? '' : t('findings.count', { count: total })}
        </p>
      </div>
      <p id="query-help" className="sr-only">
        {t('findings.queryHelp')}
      </p>
      {parsed.error && (
        <p role="alert" className="px-3 pb-1.5 text-12 text-critical">
          {t('findings.queryError', { message: parsed.error })}
        </p>
      )}
      {parsed.terms.length > 0 && (
        <ul className="m-0 flex list-none flex-wrap gap-1.5 px-3 pb-2">
          {parsed.terms.map((term, i) => (
            <li key={term.source + i} className="inline-flex h-6 items-center rounded-ctl border border-rule text-12">
              <span className="ps-2 pe-1">{describeTerm(term)}</span>
              <button
                type="button"
                aria-label={t('findings.removeTerm', { term: term.source })}
                className="grid size-6 place-items-center text-ink-2 hover:text-ink"
                onClick={() => commit(removeTerm(draft, i))}
              >
                <IconX width={10} height={10} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
