import { get, patch, post, ProblemError, setCsrfToken } from './client';
import type { FindingEvent, FindingRow, Page, Permissions, RunRow, Session, TenantRef, TriageBody, UiConfig } from './types';

export const getUiConfig = () => get<UiConfig>('/api/v1/ui-config');

/** 401 means "not signed in": a normal answer, so it resolves to null. */
export async function getSession(): Promise<Session | null> {
  try {
    const s = await get<Session>('/auth/session');
    setCsrfToken(s.csrfToken);
    return s;
  } catch (e) {
    if (e instanceof ProblemError && e.status === 401) {
      setCsrfToken('');
      return null;
    }
    throw e;
  }
}

export const getPermissions = () => get<Permissions>('/api/v1/me/permissions');
export const getTenants = async () => (await get<TenantRef[] | null>('/api/v1/me/tenants')) ?? [];
export const switchTenant = (slug: string) => post<void>('/auth/tenant', { tenant: slug });
export const logout = () => post<void>('/auth/logout');

/**
 * Break-glass local administrator sign-in (docs/16 D3). JSON only; a 204 means the session cookie
 * is set. Failures are problems: 401 wrong credentials, 429 locked or throttled, 403 turned off.
 */
export const localLogin = (body: { tenant?: string; username: string; password: string }) =>
  post<void>('/auth/local/login', body);

/** Browser navigation target for sign-in; never fetched. */
export function loginUrl(tenant: string, returnTo: string, idp?: string): string {
  const sp = new URLSearchParams();
  if (tenant) sp.set('tenant', tenant);
  sp.set('return_to', returnTo);
  if (idp) sp.set('idp', idp);
  return `/auth/login?${sp.toString()}`;
}

interface RawPage {
  items?: FindingRow[] | null;
  nextCursor?: string;
  next_cursor?: string;
  total?: number;
}

/** Default sort is -score (docs/16 D16). The backend sends next_cursor and always total. */
export async function listFindings(args: {
  q: string;
  sort: string;
  cursor?: string;
  limit?: number;
  signal?: AbortSignal;
}): Promise<Page<FindingRow>> {
  const raw = await get<RawPage>('/api/v1/findings', {
    query: { q: args.q, sort: args.sort, cursor: args.cursor, limit: args.limit ?? 100 },
    signal: args.signal,
  });
  return {
    items: raw.items ?? [],
    nextCursor: raw.nextCursor ?? raw.next_cursor ?? '',
    total: raw.total,
  };
}

/** Newest first; the cursor is signed by the server and opaque here (docs/16 D16). */
export async function listRuns(args: { cursor?: string; limit?: number; signal?: AbortSignal }): Promise<Page<RunRow>> {
  const raw = await get<{ items?: RunRow[] | null; next_cursor?: string }>('/api/v1/runs', {
    query: { cursor: args.cursor, limit: args.limit ?? 50 },
    signal: args.signal,
  });
  return { items: raw.items ?? [], nextCursor: raw.next_cursor ?? '' };
}

export const getRun = (id: string, signal?: AbortSignal) => get<RunRow>(`/api/v1/runs/${encodeURIComponent(id)}`, { signal });

/** Change a finding's state. `version` is the one the analyst saw; a stale one is a 409 (docs/16 D38). */
export const triageFinding = (id: string, body: TriageBody, version: number | undefined) =>
  patch<FindingRow>(`/api/v1/findings/${encodeURIComponent(id)}`, body, version === undefined ? undefined : { headers: { 'If-Match': `"${version}"` } });

export async function getFindingEvents(id: string, signal?: AbortSignal): Promise<FindingEvent[]> {
  const raw = await get<{ items?: FindingEvent[] | null }>(`/api/v1/findings/${encodeURIComponent(id)}/events`, { signal });
  return raw.items ?? [];
}
