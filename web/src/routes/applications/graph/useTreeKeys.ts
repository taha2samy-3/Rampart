import { useEffect, useMemo, useState, type KeyboardEvent, type RefObject } from 'react';
import type { TreeItem } from './model';

/**
 * Keyboard walk of a tree (WAI-ARIA tree pattern) shared by the drawing and the outline: arrows move, Right opens or
 * goes to the first child, Left closes or goes to the parent, Enter or Space selects. Only one item is in the tab order.
 */
export function useTreeKeys(
  items: TreeItem[],
  selectedId: string | null,
  rootKey: string | null,
  box: RefObject<HTMLElement | null>,
  onSelect: (id: string) => void,
  onToggle: (id: string) => void,
) {
  const [focusKey, setFocusKey] = useState<string | null>(null);
  const byKey = useMemo(() => new Map(items.map((i) => [i.key, i])), [items]);

  const tabKey =
    focusKey && byKey.has(focusKey) ? focusKey : (items.find((i) => i.id === selectedId)?.key ?? rootKey);

  // Move DOM focus when the keys moved the focus; compare attributes instead of building a selector from an id.
  useEffect(() => {
    if (!focusKey) return;
    const el = Array.from(box.current?.querySelectorAll<HTMLElement>('[data-key]') ?? []).find((e) => e.dataset.key === focusKey);
    if (el && document.activeElement !== el) el.focus();
  }, [focusKey, box]);

  const onKey = (e: KeyboardEvent, item: TreeItem) => {
    const at = items.indexOf(item);
    const go = (to?: TreeItem) => to && setFocusKey(to.key);
    switch (e.key) {
      case 'ArrowDown': go(items[at + 1]); break;
      case 'ArrowUp': go(items[at - 1]); break;
      case 'Home': go(items[0]); break;
      case 'End': go(items[items.length - 1]); break;
      case 'ArrowRight':
        if (item.expandable && !item.expanded) onToggle(item.id);
        else go(item.children[0]);
        break;
      case 'ArrowLeft':
        if (item.expanded) onToggle(item.id);
        else if (item.parentKey) go(byKey.get(item.parentKey));
        break;
      case 'Enter':
      case ' ':
        onSelect(item.id);
        break;
      default:
        return;
    }
    e.preventDefault();
  };

  return { tabKey, onKey, setFocusKey };
}
