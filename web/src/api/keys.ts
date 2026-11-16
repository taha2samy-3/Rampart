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
    trend: (id: string, days: number) => ['applications', 'trend', id, days] as const,
  },
  overview: () => ['overview'] as const,
  trend: (metric: string, days: number) => ['trend', metric, days] as const,
  heldCloses: {
    all: () => ['held-closes'] as const,
    list: (decision?: string) => ['held-closes', 'list', decision ?? ''] as const,
  },
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
  views: {
    all: () => ['views'] as const,
    list: () => ['views', 'list'] as const,
  },
  groups: {
    all: () => ['groups'] as const,
    list: () => ['groups', 'list'] as const,
    one: (id: string) => ['groups', 'one', id] as const,
  },
  connectors: {
    all: () => ['connectors'] as const,
    list: () => ['connectors', 'list'] as const,
    packages: () => ['connectors', 'packages'] as const,
  },
  inventory: {
    all: () => ['inventory'] as const,
    list: () => ['inventory', 'list'] as const,
  },
  vulnerabilities: {
    all: () => ['vulnerabilities'] as const,
    list: () => ['vulnerabilities', 'list'] as const,
  },
  dtrack: {
    all: () => ['dtrack'] as const,
    sources: () => ['dtrack', 'sources'] as const,
    unmapped: (source: string) => ['dtrack', 'unmapped', source] as const,
    decisions: (source: string) => ['dtrack', 'decisions', source] as const,
  },
  parsers: {
    all: () => ['parsers'] as const,
    list: () => ['parsers', 'list'] as const,
  },
};
