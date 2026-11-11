export function shortId(id: string | undefined | null): string {
  return id ? id.slice(0, 8) : '';
}

const DAY = 86_400_000;

/** "2 days ago", "in 3 days": relative in the interface, absolute in the title. */
export function relativeDays(iso: string | undefined | null, now = Date.now()): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const days = Math.round((t - now) / DAY);
  if (days === 0) return 'today';
  const n = Math.abs(days);
  const unit = n === 1 ? 'day' : 'days';
  return days > 0 ? `in ${n} ${unit}` : `${n} ${unit} ago`;
}

export function absoluteDate(iso: string | undefined | null, locale?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString(locale, { year: 'numeric', month: 'short', day: 'numeric' });
}

/** Short age for a table cell: 4d, 3w, 5mo. */
export function shortAge(iso: string | undefined | null, now = Date.now()): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const days = Math.max(0, Math.floor((now - t) / DAY));
  if (days < 1) return 'today';
  if (days < 14) return `${days}d`;
  if (days < 60) return `${Math.floor(days / 7)}w`;
  return `${Math.floor(days / 30)}mo`;
}

/** Countdown for a table cell: "in 2d", "today", "3d late". */
export function dueShort(iso: string | undefined | null, now = Date.now()): { text: string; late: boolean } {
  if (!iso) return { text: '', late: false };
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return { text: '', late: false };
  const days = Math.ceil((t - now) / DAY);
  if (days === 0) return { text: 'today', late: false };
  return days > 0 ? { text: `in ${days}d`, late: false } : { text: `${-days}d late`, late: true };
}
