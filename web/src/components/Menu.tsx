import * as DM from '@radix-ui/react-dropdown-menu';
import { cn } from '@/lib/cn';
import { IconCheck } from './icons';

/**
 * Non-modal: Radix's modal mode injects a <style> element for scroll locking,
 * which the CSP (default-src 'self') blocks. Menus still close on outside click and Escape.
 */
export function Menu(props: DM.DropdownMenuProps) {
  return <DM.Root modal={false} {...props} />;
}
export const MenuTrigger = DM.Trigger;
export const MenuRadioGroup = DM.RadioGroup;

const panel = 'z-50 min-w-48 rounded-ctl border border-rule bg-surface py-1 text-13 text-ink shadow-none';
const item =
  'flex h-8 cursor-default select-none items-center gap-2 px-3 outline-none data-[highlighted]:bg-chrome data-[disabled]:opacity-50';

export function MenuContent({ children, align = 'end', className }: { children: React.ReactNode; align?: 'start' | 'end'; className?: string }) {
  return (
    <DM.Portal>
      <DM.Content align={align} sideOffset={4} className={cn(panel, className)}>
        {children}
      </DM.Content>
    </DM.Portal>
  );
}
export function MenuItem({ children, ...p }: DM.DropdownMenuItemProps) {
  return <DM.Item className={item} {...p}>{children}</DM.Item>;
}
export function MenuRadioItem({ children, ...p }: DM.DropdownMenuRadioItemProps) {
  return (
    <DM.RadioItem className={cn(item, 'ps-8 relative')} {...p}>
      <DM.ItemIndicator className="absolute start-2.5 inline-flex text-accent">
        <IconCheck width={14} height={14} />
      </DM.ItemIndicator>
      {children}
    </DM.RadioItem>
  );
}
export function MenuLabel({ children }: { children: React.ReactNode }) {
  return <DM.Label className="px-3 py-1 text-12 text-ink-2">{children}</DM.Label>;
}
export function MenuSeparator() {
  return <DM.Separator className="my-1 h-px bg-rule" />;
}
