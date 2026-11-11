import * as T from '@radix-ui/react-tabs';
import { cn } from '@/lib/cn';

export const Tabs = T.Root;
export const TabsContent = T.Content;

/** Underline tabs: the active one gets a 2 px bar and weight, not a filled pill. */
export function TabsList({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <T.List aria-label={label} className="flex gap-4 border-b border-rule">
      {children}
    </T.List>
  );
}
export function TabsTrigger({ value, children }: { value: string; children: React.ReactNode }) {
  return (
    <T.Trigger
      value={value}
      className={cn(
        '-mb-px h-9 border-b-2 border-transparent text-13 text-ink-2 hover:text-ink',
        'data-[state=active]:border-accent data-[state=active]:font-semibold data-[state=active]:text-ink',
      )}
    >
      {children}
    </T.Trigger>
  );
}
