import { get, patch, post, ProblemError, setCsrfToken } from './client';
import type { AppSummary, ApplicationPage, AcceptanceBody, AcceptanceOutcome, AcceptanceStatus, AppNotification, AuditEntry, AuditFilter, CorrelatedRef, FindingEvent, FindingSources, NotificationList, FindingRow, Page, Permissions, RunRow, Reporter, RiskAcceptance, Session, TenantRef, TenantSettings, TrendPoint, TriageBody, UiConfig, Overview } from './types';

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

export async function getFindingSources(id: string, signal?: AbortSignal): Promise<FindingSources> {
  const raw = await get<{ reported_by?: Reporter[] | null; also_reported_by?: CorrelatedRef[] | null }>(`/api/v1/findings/${encodeURIComponent(id)}`, { signal });
  return { reported_by: raw.reported_by ?? [], also_reported_by: raw.also_reported_by ?? [] };
}
export async function getFindingEvents(id: string, signal?: AbortSignal): Promise<FindingEvent[]> {
  const raw = await get<{ items?: FindingEvent[] | null }>(`/api/v1/findings/${encodeURIComponent(id)}/events`, { signal });
  return raw.items ?? [];
}

export const requestAcceptance = (body: AcceptanceBody) => post<AcceptanceOutcome>('/api/v1/risk-acceptances', body);
export async function listAcceptances(status: AcceptanceStatus | '', signal?: AbortSignal): Promise<RiskAcceptance[]> {
  const raw = await get<{ items?: RiskAcceptance[] | null }>('/api/v1/risk-acceptances', { query: { status }, signal });
  return raw.items ?? [];
}
export const getAcceptance = (id: string, signal?: AbortSignal) => get<RiskAcceptance>(`/api/v1/risk-acceptances/${encodeURIComponent(id)}`, { signal });
export const decideAcceptance = (id: string, action: 'approve' | 'reject' | 'revoke', note?: string) =>
  post<unknown>(`/api/v1/risk-acceptances/${encodeURIComponent(id)}/${action}`, note ? { note } : {});
export const getSettings = (signal?: AbortSignal) => get<TenantSettings>('/api/v1/settings', { signal });

export async function listApplications(signal?: AbortSignal): Promise<AppSummary[]> {
  const raw = await get<{ items?: AppSummary[] | null }>('/api/v1/applications', { signal });
  return raw.items ?? [];
}
export const getApplication = (id: string, signal?: AbortSignal) => get<ApplicationPage>(`/api/v1/applications/${encodeURIComponent(id)}/summary`, { signal });
export const getOverview = (signal?: AbortSignal) => get<Overview>('/api/v1/dashboards/overview', { signal });
export async function getTrend(metric: 'open' | 'new' | 'closed', days: number, signal?: AbortSignal): Promise<TrendPoint[]> {
  const raw = await get<{ points?: TrendPoint[] | null }>('/api/v1/metrics/trend', { query: { metric, days }, signal });
  return raw.points ?? [];
}

export async function getNotifications(signal?: AbortSignal): Promise<NotificationList> {
  const raw = await get<{ items?: AppNotification[] | null; unread?: number }>('/api/v1/notifications', { signal });
  return { items: raw.items ?? [], unread: raw.unread ?? 0 };
}
export const markNotificationsRead = () => post<null>('/api/v1/notifications/read', undefined);

export async function listAudit(args: AuditFilter & { cursor?: string; signal?: AbortSignal }): Promise<Page<AuditEntry>> {
  const raw = await get<{ items?: AuditEntry[] | null; next_cursor?: string }>('/api/v1/audit', {
    query: { actor: args.actor || undefined, action: args.action || undefined, cursor: args.cursor, limit: 50 },
    signal: args.signal,
  });
  return { items: raw.items ?? [], nextCursor: raw.next_cursor ?? '' };
}
/** The export is a plain link: the browser downloads it with the session cookie. */
export const auditExportUrl = (format: 'csv' | 'ndjson', f: AuditFilter) => {
  const p = new URLSearchParams({ format });
  if (f.actor) p.set('actor', f.actor);
  if (f.action) p.set('action', f.action);
  return `/api/v1/audit?${p.toString()}`;
};
