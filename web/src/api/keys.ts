/** The one query-key factory. SSE invalidation (Phase 3) relies on these prefixes. */
export const qk = {
  uiConfig: () => ['ui-config'] as const,
  session: () => ['session'] as const,
  permissions: () => ['me', 'permissions'] as const,
  tenants: () => ['me', 'tenants'] as const,
  acceptances: {
    all: () => ['acceptances'] as const,
    list: (status: string) => ['acceptances', 'list', status] as const,
    one: (id: string) => ['acceptances', 'one', id] as const,
    proofs: (id: string) => ['acceptances', 'proofs', id] as const,
  },
  settings: () => ['settings'] as const,
  audit: (f: { actor?: string; action?: string }) => ['audit', f.actor ?? '', f.action ?? ''] as const,
  access: () => ['access'] as const,
  bindings: () => ['bindings'] as const,
  taxonomies: () => ['taxonomies'] as const,
  taxonomyStatus: (id: string, app: string) => ['taxonomies', 'status', id, app] as const,
  notifications: () => ['notifications'] as const,
  applications: {
    list: () => ['applications', 'list'] as const,
    one: (id: string) => ['applications', 'one', id] as const,
  },
  overview: () => ['overview'] as const,
  trend: (metric: string, days: number) => ['trend', metric, days] as const,
  runs: {
    all: () => ['runs'] as const,
    list: () => ['runs', 'list'] as const,
    one: (id: string) => ['runs', 'one', id] as const,
  },
  findings: {
    all: () => ['findings'] as const,
    events: (id: string) => ['findings', 'events', id] as const,
    sources: (id: string) => ['findings', 'sources', id] as const,
    list: (q: string, sort: string) => ['findings', 'list', { q, sort }] as const,
  },
};
