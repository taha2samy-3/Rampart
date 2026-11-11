import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/cn';
import { Button } from './Button';
import { IconCheck, IconCopy } from './icons';

/** An empty state says what to do next. Left-aligned, no illustration. */
export function EmptyState({
  title,
  children,
  action,
  className,
}: {
  title: string;
  children?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('max-w-[64ch] p-6', className)}>
      <h2 className="text-16 font-semibold">{title}</h2>
      {children && <div className="mt-1 text-13 text-ink-2">{children}</div>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

/** A command in mono with a copy button. */
export function CommandLine({ command }: { command: string }) {
  const { t } = useTranslation();
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } catch {
      /* clipboard blocked: the text stays selectable */
    }
  };
  return (
    <div className="flex items-stretch border border-rule rounded-ctl bg-chrome">
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap px-3 py-1.5 text-13 text-ink">{command}</code>
      <Button variant="ghost" className="h-auto rounded-s-none border-s border-s-rule" onClick={copy} aria-label={t('common.copy')}>
        {done ? <IconCheck /> : <IconCopy />}
        <span aria-live="polite">{done ? t('common.copied') : t('common.copy')}</span>
      </Button>
    </div>
  );
}
