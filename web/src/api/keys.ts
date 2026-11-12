/** The one query-key factory. SSE invalidation (Phase 3) relies on these prefixes. */
export const qk = {
  uiConfig: () => ['ui-config'] as const,
  session: () => ['session'] as const,
  permissions: () => ['me', 'permissions'] as const,
  tenants: () => ['me', 'tenants'] as const,
  runs: {
    all: () => ['runs'] as const,
    list: () => ['runs', 'list'] as const,
    one: (id: string) => ['runs', 'one', id] as const,
  },
  findings: {
    all: () => ['findings'] as const,
    events: (id: string) => ['findings', 'events', id] as const,
    list: (q: string, sort: string) => ['findings', 'list', { q, sort }] as const,
  },
};
