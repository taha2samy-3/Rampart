import { forwardRef, type HTMLAttributes, type TdHTMLAttributes, type ThHTMLAttributes } from 'react';
import { cn } from '@/lib/cn';
import { IconChevronDown } from './icons';

/** Dense, rule-divided, no zebra. Rows are 46 px (two lines) or 32 px (compact). */
export const Table = forwardRef<HTMLTableElement, HTMLAttributes<HTMLTableElement>>(function Table({ className, ...p }, ref) {
  return <table ref={ref} className={cn('w-full table-fixed border-collapse text-13', className)} {...p} />;
});
export const THead = (p: HTMLAttributes<HTMLTableSectionElement>) => <thead {...p} />;
export const TBody = (p: HTMLAttributes<HTMLTableSectionElement>) => <tbody {...p} />;
export const Tr = forwardRef<HTMLTableRowElement, HTMLAttributes<HTMLTableRowElement> & { selected?: boolean }>(function Tr({ className, selected, ...p }, ref) {
  return (
    <tr
      ref={ref}
      aria-selected={selected}
      className={cn('border-b border-rule', selected ? 'bg-chrome' : 'hover:bg-chrome/60', className)}
      {...p}
    />
  );
});

export function Th({
  className,
  align = 'start',
  sort,
  onSort,
  children,
  ...p
}: Omit<ThHTMLAttributes<HTMLTableCellElement>, 'align'> & {
  align?: 'start' | 'end';
  sort?: 'ascending' | 'descending' | 'none';
  onSort?: () => void;
}) {
  return (
    <th
      scope="col"
      aria-sort={sort}
      className={cn('h-8 border-b border-rule bg-surface px-3 text-12 font-medium text-ink-2', align === 'end' ? 'text-end' : 'text-start', className)}
      {...p}
    >
      {onSort ? (
        <button type="button" onClick={onSort} className="inline-flex items-center gap-1 font-medium hover:text-ink">
          {children}
          {sort && sort !== 'none' && <IconChevronDown width={12} height={12} className={sort === 'ascending' ? 'rotate-180' : ''} />}
        </button>
      ) : (
        children
      )}
    </th>
  );
}
export function Td({ className, align = 'start', ...p }: Omit<TdHTMLAttributes<HTMLTableCellElement>, 'align'> & { align?: 'start' | 'end' }) {
  return <td className={cn('overflow-hidden text-ellipsis whitespace-nowrap px-3', align === 'end' ? 'text-end tnum' : 'text-start', className)} {...p} />;
}
