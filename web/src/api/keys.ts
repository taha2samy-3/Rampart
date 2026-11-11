/** The one query-key factory. SSE invalidation (Phase 3) relies on these prefixes. */
export const qk = {
  uiConfig: () => ['ui-config'] as const,
  session: () => ['session'] as const,
  permissions: () => ['me', 'permissions'] as const,
  tenants: () => ['me', 'tenants'] as const,
  findings: {
    all: () => ['findings'] as const,
    list: (q: string, sort: string) => ['findings', 'list', { q, sort }] as const,
  },
};
