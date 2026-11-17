import { useEffect } from 'react';
import * as D from '@radix-ui/react-dialog';
import { cn } from '@/lib/cn';
import { IconX } from './icons';
import { IconButton } from './Button';

/**
 * Non-modal in Radix terms: modal mode injects a <style> element for scroll
 * locking, which the CSP blocks. DialogContent makes the app inert and draws
 * its own overlay instead, which gives the same focus containment.
 */
export function Dialog(props: D.DialogProps) {
  return <D.Root modal={false} {...props} />;
}
export const DialogTrigger = D.Trigger;
export const DialogClose = D.Close;

/** Mounted only while the dialog is open: hides the rest of the app from focus and assistive tech. */
function InertApp() {
  useEffect(() => {
    const root = document.getElementById('root');
    if (!root) return;
    root.inert = true;
    return () => {
      root.inert = false;
    };
  }, []);
  return null;
}

/** A centred dialog, or a `sheet` docked to the inline start edge (facets on tablet). */
export function DialogContent({
  title,
  description,
  children,
  sheet,
  closeLabel = 'Close',
  className,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
  sheet?: boolean;
  closeLabel?: string;
  className?: string;
}) {
  return (
    <D.Portal>
      <D.Close asChild>
        <div aria-hidden="true" className="fixed inset-0 z-40 bg-[color-mix(in_srgb,var(--ink)_40%,transparent)]" />
      </D.Close>
      <D.Content
        className={cn(
          'fixed z-50 flex flex-col border border-rule bg-surface text-ink shadow-xl',
          sheet
            ? 'inset-y-0 start-0 w-[280px] max-w-[90vw] border-y-0 border-s-0'
            : 'start-1/2 top-1/2 max-h-[90vh] w-[440px] max-w-[92vw] -translate-x-1/2 -translate-y-1/2 rounded-ctl rtl:translate-x-1/2',
          className,
        )}
      >
        <InertApp />
        <div className="flex h-11 shrink-0 items-center justify-between border-b border-rule ps-4 pe-1.5">
          <D.Title className="text-14 font-semibold">{title}</D.Title>
          <D.Close asChild>
            <IconButton label={closeLabel}><IconX /></IconButton>
          </D.Close>
        </div>
        <div className="flex-1 overflow-y-auto p-4">
          {description ? (
            <D.Description className="mb-3 text-13 text-ink-2">{description}</D.Description>
          ) : (
            <D.Description className="sr-only">{title}</D.Description>
          )}
          {children}
        </div>
      </D.Content>
    </D.Portal>
  );
}
