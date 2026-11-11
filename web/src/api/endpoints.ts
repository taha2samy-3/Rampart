import { get, post, ProblemError, setCsrfToken } from './client';
import type { FindingRow, Page, Permissions, Session, TenantRef, UiConfig } from './types';

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
