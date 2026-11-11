import { useTranslation } from 'react-i18next';
import type { Problem } from '@/api/types';
import { cn } from '@/lib/cn';
import { Button } from './Button';
import { IconWarning } from './icons';

/** What to do next, by status. Never an apology. */
export function nextStep(status: number, t: (k: string) => string): string {
  const key = [401, 403, 404, 409, 429, 0].includes(status) ? String(status) : 'default';
  return t(`problem.next.${key}`);
}

/**
 * Shows an RFC 9457 problem: what failed (title), why (detail), what to do
 * next, and the request id to quote to support.
 */
export function ProblemMessage({
  problem,
  onRetry,
  next,
  className,
  title,
}: {
  problem: Problem;
  onRetry?: () => void;
  next?: string;
  className?: string;
  title?: string;
}) {
  const { t } = useTranslation();
  const copy = () => void navigator.clipboard?.writeText(problem.request_id ?? '');
  return (
    <div role="alert" className={cn('border-s-2 border-critical ps-3 text-13', className)}>
      <p className="flex items-center gap-1.5 font-semibold text-ink">
        <IconWarning width={14} height={14} className="text-critical" />
        {title ?? problem.title}
      </p>
      {problem.detail && <p className="mt-0.5 text-ink-2">{problem.detail}</p>}
      {(next ?? nextStep(problem.status, t)).trim() && <p className="mt-0.5 text-ink-2">{next ?? nextStep(problem.status, t)}</p>}
      {problem.errors?.length ? (
        <ul className="mt-1 list-disc ps-4 text-ink-2">
          {problem.errors.map((e) => (
            <li key={e.field + e.message}>
              {e.field}: {e.message}
            </li>
          ))}
        </ul>
      ) : null}
      {problem.request_id && (
        <p className="mt-1 flex items-center gap-2 text-12 text-ink-2">
          <span>{t('common.requestId')}</span>
          <code className="text-ink">{problem.request_id}</code>
          <Button variant="ghost" className="h-6 px-1.5 text-12" onClick={copy}>
            {t('common.copy')}
          </Button>
        </p>
      )}
      {onRetry && (
        <Button className="mt-2" onClick={onRetry}>
          {t('common.retry')}
        </Button>
      )}
    </div>
  );
}
