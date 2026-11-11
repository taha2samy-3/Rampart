import * as T from '@radix-ui/react-tooltip';

export const TooltipProvider = T.Provider;

export function Tooltip({ label, children, side = 'bottom' }: { label: string; children: React.ReactElement; side?: 'top' | 'bottom' | 'left' | 'right' }) {
  return (
    <T.Root delayDuration={400}>
      <T.Trigger asChild>{children}</T.Trigger>
      <T.Portal>
        <T.Content side={side} sideOffset={6} className="z-50 rounded-ctl border border-rule bg-chrome px-2 py-1 text-12 text-ink">
          {label}
        </T.Content>
      </T.Portal>
    </T.Root>
  );
}
