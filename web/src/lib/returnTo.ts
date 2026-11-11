/**
 * return_to must be a same-origin path. Anything that could leave the origin
 * (absolute URLs, protocol-relative //host, backslash tricks, control chars)
 * falls back to the default.
 */
export function safeReturnTo(value: string | null | undefined, fallback = '/findings'): string {
  if (!value) return fallback;
  if (!value.startsWith('/')) return fallback;
  if (value.startsWith('//') || value.startsWith('/\\')) return fallback;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(value)) return fallback;
  try {
    const u = new URL(value, 'https://rampart.invalid');
    if (u.origin !== 'https://rampart.invalid') return fallback;
    if (u.pathname.startsWith('/auth/') || u.pathname === '/login') return fallback;
    return u.pathname + u.search + u.hash;
  } catch {
    return fallback;
  }
}
