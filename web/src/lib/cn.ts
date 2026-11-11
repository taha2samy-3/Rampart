import { extendTailwindMerge } from 'tailwind-merge';

// Lets a caller's utility override a component default (px-0 beats px-3),
// and teaches the merger our type-scale names.
const merge = extendTailwindMerge({
  extend: { classGroups: { 'font-size': [{ text: ['12', '13', '14', '16', '20', '28'] }] } },
});

export function cn(...parts: (string | false | null | undefined)[]): string {
  return merge(parts.filter(Boolean).join(' '));
}
