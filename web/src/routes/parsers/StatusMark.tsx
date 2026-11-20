import { IconCheck, IconWarning } from '@/components/icons';
import { cn } from '@/lib/cn';

/** How a thing is doing: fine, wrong, or nothing to say yet. */
export type Health = 'ok' | 'problem' | 'idle';

/**
 * The icon beside a status. The shape says it, not the colour alone (a check, a warning triangle, a dash), and the words beside it say it again;
 * red is used for what is wrong only (docs/13 section 6: colour is for risk).
 */
export function StatusMark({ health, className }: { health: Health; className?: string }) {
  if (health === 'ok') return <IconCheck className={cn('size-3.5 shrink-0 text-ink-2', className)} />;
  if (health === 'problem') return <IconWarning className={cn('size-3.5 shrink-0 text-critical', className)} />;
  return <span aria-hidden="true" className={cn('inline-block w-3.5 shrink-0 text-center text-ink-2', className)}>–</span>;
}
