import { forwardRef, type InputHTMLAttributes } from 'react';
import { cn } from '@/lib/cn';
import { IconSearch } from './icons';
import { Kbd } from './Kbd';

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { mono?: boolean; invalid?: boolean }>(
  function Input({ className, mono, invalid, ...rest }, ref) {
    return (
      <input
        ref={ref}
        aria-invalid={invalid || undefined}
        className={cn(
          'h-8 w-full rounded-ctl border bg-surface px-2.5 text-13 text-ink placeholder:text-ink-2',
          invalid ? 'border-critical' : 'border-rule',
          mono && 'font-mono text-13',
          className,
        )}
        {...rest}
      />
    );
  },
);

export const SearchField = forwardRef<
  HTMLInputElement,
  InputHTMLAttributes<HTMLInputElement> & { shortcut?: string }
>(function SearchField({ className, shortcut, ...rest }, ref) {
  return (
    <div className={cn('relative flex items-center', className)}>
      <IconSearch className="pointer-events-none absolute start-2.5 text-ink-2" />
      <input
        ref={ref}
        type="search"
        className="h-8 w-full rounded-ctl border border-rule bg-surface ps-8 pe-8 text-13 placeholder:text-ink-2 [&::-webkit-search-cancel-button]:hidden"
        {...rest}
      />
      {shortcut && (
        <span className="pointer-events-none absolute end-2">
          <Kbd>{shortcut}</Kbd>
        </span>
      )}
    </div>
  );
});
