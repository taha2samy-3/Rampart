import { cn } from '@/lib/cn';
import { IconChevronDown } from './icons';

export interface Option {
  value: string;
  label: string;
}

/**
 * A native select with our styling. Radix Select injects a <style> element for
 * scroll locking, which the CSP (default-src 'self') blocks, and the native
 * control is the most accessible choice for short lists anyway.
 */
export function Select({
  value,
  onValueChange,
  options,
  label,
  className,
}: {
  value: string;
  onValueChange: (v: string) => void;
  options: Option[];
  /** accessible name; required because there is no visible label */
  label: string;
  className?: string;
}) {
  return (
    <span className={cn('relative inline-flex', className)}>
      <select
        aria-label={label}
        value={value}
        onChange={(e) => onValueChange(e.target.value)}
        className="h-8 w-full cursor-pointer appearance-none rounded-ctl border border-rule bg-surface ps-2.5 pe-8 text-13 hover:bg-chrome"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <IconChevronDown width={14} height={14} className="pointer-events-none absolute end-2.5 top-[9px] text-ink-2" />
    </span>
  );
}
