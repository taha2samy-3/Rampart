import { render } from '@testing-library/react';
import { createMemoryHistory } from '@tanstack/react-router';
import { vi } from 'vitest';
import { App } from '@/app/App';
import type { CorrelatedRef, HeldClose, Reporter, Role } from '@/api/types';

export const SESSION = {
  user: { id: 'u1', email: 'sara@acme.example', name: 'Sara Ahmed' },
  tenant: { id: 't1', slug: 'acme', name: 'Acme' },
  csrfToken: 'csrf-1',
  expiresAt: '2030-01-01T00:00:00Z',
};
export const CONFIG = {
  product: 'Rampart', version: '0.1.0', features: [],
  login: { methods: [{ id: 'default', name: 'Default SSO', type: 'oidc' }] },
  locale: { default: 'en' }, supportUrl: '',
};

export function finding(i: number, band: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'high') {
  const base = { critical: 600, high: 400, medium: 200, low: 80, info: 10 }[band];
  return {
    finding: {
      id: `f-${i}`, application_id: 'b7e1c9a2-0000', title: `Finding ${i}`, severity: band, risk_score: base + 100,
      state: 'open', version: 3, first_seen: '2026-10-01T00:00:00Z', rule_scanner_family: 'semgrep', rule_id: 'r1',
      location: { file_path: 'src/a.go', start_line: i },
    },
    risk: { base_severity: band, base_points: base, factors: [{ name: 'KEV', points: 100, reason: 'Known exploited' }], total_score: base + 100, band },
    sla_due_date: '2026-12-01T00:00:00Z',
  };
}

export interface Scenario {
  loggedIn?: boolean;
  /** Sign-in methods ui-config reports (default: one OIDC provider). */
  methods?: { id: string; name: string; type: string }[];
  /** What POST /auth/local/login answers: 204 on success, or a problem status. */
  local?: 204 | 401 | 403 | 429;
  findings?: ReturnType<typeof finding>[] | 'error';
  /** Pages of runs for GET /api/v1/runs; each call returns the next page. 'error' answers 500. */
  runs?: ReturnType<typeof run>[][] | 'error';
  /** The signed-in role (default triager). */
  role?: Role;
  /** What POST /api/v1/findings/bulk answers (default: one changed, one refused). */
  bulk?: { matched: number; updated: number; unchanged: number; failed: { id: string; error: string }[] | null };
  /** What PATCH /api/v1/findings/{id} answers: 200 (default), or a problem status. */
  patch?: 200 | 400 | 409;
  /** What GET /api/v1/findings/{id} answers for the Reported by section. */
  sources?: { reported_by?: Reporter[]; also_reported_by?: CorrelatedRef[] } | 'error';
  /** Pages of GET /api/v1/audit; each call returns the next page. 'error' answers 500. */
  audit?: { items: Record<string, unknown>[]; next_cursor?: string }[] | 'error';
  /** The frameworks and the status of each control (by framework id). 'error' answers 500 on status. */
  taxonomies?: { id: string; name: string; version: string }[];
  taxonomyStatus?: Record<string, { status: Record<string, unknown>[] }> | 'error';
  /** GET /api/v1/me/access: roles on single applications (default none). */
  access?: Record<string, string>;
  /** The access bindings GET /api/v1/access-bindings returns; POST and DELETE are recorded in the calls. */
  bindings?: Record<string, unknown>[] | 'error';
  /** GET /api/v1/notifications; POSTs to /read are recorded in the calls. */
  notifications?: { items: { id: string; kind: string; title: string; body?: string; link?: string; created_at: string; unread: boolean }[]; unread: number } | 'error';
  /** The timeline GET /api/v1/findings/{id}/events returns. */
  /** GET /api/v1/applications, and the page of each (by id). */
  apps?: ReturnType<typeof app>[] | 'error';
  appPages?: Record<string, ReturnType<typeof appPage>>;
  overview?: ReturnType<typeof overviewData> | 'error';
  trend?: { day: string; value: number }[];
  /** Risk acceptances GET /api/v1/risk-acceptances returns (filtered by ?status=). */
  acceptances?: ReturnType<typeof acceptance>[];
  heldCloses?: HeldClose[];
  /** What POST /api/v1/risk-acceptances answers: approved at once (default), pending, or a 400. */
  accept?: 'approved' | 'pending' | 400;
  /** Proof files GET .../proofs returns; what POST .../proofs answers (201 by default, or 422). */
  proofs?: { id: string; name: string; content_type: string; size_bytes: number; uploaded_by: string; uploaded_at: string }[];
  proofUpload?: 201 | 422;
  /** What POST .../approve|reject|revoke answers: 200 (default) or 400. */
  decide?: 200 | 400;
  events?: { id: string; at: string; actor: string; type: string; from?: unknown; to?: unknown; note?: string }[];
}

export function heldClose(i: number, over: Partial<HeldClose> = {}): HeldClose {
  return {
    id: `hc-${i}`,
    ingest_run_id: `run-${i}-00000000`,
    scope: { tenant_id: 't-1', scan_source_id: 'src-1', scanner_family: 'trivy', asset_id: 'a-1', track: 'main' },
    finding_ids: [`f-${i}-1`, `f-${i}-2`, `f-${i}-3`],
    created_at: '2026-11-13T10:00:00Z',
    ...over,
  };
}

export function app(i: number, over: Record<string, unknown> = {}) {
  return {
    id: `app-${i}`, slug: `app-${i}`, name: `Application ${i}`, business_criticality: 'high', internet_facing: false,
    open: { critical: 2, high: 5, medium: 0, low: 1 }, risk_score: 870, exposure_count: 7, sla_breached: 1, last_scan: '2026-11-11T10:00:00Z', ...over,
  };
}

export function appPage(i: number, over: Record<string, unknown> = {}) {
  return {
    ...app(i), sla: { within: 3, late: 1, breached: 1, adherence: 0.6 }, mttr: [{ band: 'high', days: 6.5, fixed: 4 }],
    coverage: [{ asset_id: 'as-1', asset: 'github.com/acme/shop', scanner: 'semgrep', last_scan: '2026-11-11T10:00:00Z' }],
    top_findings: [{ id: 'f-1', title: 'SQL injection in order search', band: 'critical', risk_score: 870, state: 'open', sla_due_date: '2026-11-20T00:00:00Z' }],
    ...over,
  };
}

export function overviewData(over: Record<string, unknown> = {}) {
  return {
    changes: { since: '2026-11-11T10:00:00Z', new: 12, reopened: 3, fixed: 7 },
    open: { critical: 2, high: 5, medium: 9, low: 4 },
    overdue: [{ id: 'f-9', title: 'Hard-coded JWT signing secret', band: 'critical', due: '2026-11-05T00:00:00Z', app_slug: 'app-1', app_name: 'Application 1' }],
    overdue_total: 14,
    sla: { within: 30, late: 5, breached: 5, adherence: 0.75 },
    top_apps: [app(1), app(2, { risk_score: 400, open: { critical: 0, high: 1, medium: 0, low: 0 } })],
    coverage_gaps: [app(3, { last_scan: undefined })],
    ...over,
  };
}

export function acceptance(i: number, over: Record<string, unknown> = {}) {
  return {
    id: `acc-${i}`, status: 'pending', justification: `The service ${i} is internal and behind the VPN`, owner: 'user:sara@acme.example', requester: 'user:sara@acme.example',
    expires_at: '2027-01-15T23:59:59Z', on_expiry: 'reactivate', created_at: '2026-11-10T10:00:00Z', finding_ids: ['f-1'], ...over,
  };
}

export function run(i: number, over: Record<string, unknown> = {}) {
  return {
    id: `0000000${i}-aaaa-bbbb-cccc-000000000000`, status: 'completed', created_at: '2026-11-10T10:00:00Z', scanner_family: 'sarif', format: 'sarif', track: 'main',
    stats: { parsed: 10, created: 4, updated: 1, untouched: 5, reactivated: 0, closed: 2, record_errors: 0, weak_fingerprints: 0 },
    context: { repository: 'github.com/acme/shop', branch: 'main', commit: 'abcdef1234567' }, scanners: ['semgrep'], ephemeral: false, ...over,
  };
}
export type Calls = { method: string; url: string; headers: Record<string, string>; body?: string }[];

export function mockFetch(sc: Scenario): Calls {
  const calls: Calls = [];
  let auditCalls = 0;
  const json = (body: unknown, status = 200) =>
    new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'Content-Type': status >= 400 ? 'application/problem+json' : 'application/json' } });
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const path = url.split('?')[0]!;
    calls.push({ method: init?.method ?? 'GET', url, headers: (init?.headers ?? {}) as Record<string, string>, body: typeof init?.body === 'string' ? init.body : undefined });
    if (path === '/api/v1/ui-config') return json({ ...CONFIG, login: { methods: sc.methods ?? CONFIG.login.methods } });
    if (path === '/auth/local/login') {
      const st = sc.local ?? 204;
      return st === 204 ? json(null, 204) : json({ type: 'u', title: 'x', status: st, detail: st === 429 ? 'Try again in 15 minutes.' : undefined, request_id: 'req_local' }, st);
    }
    if (path === '/auth/session') return sc.loggedIn ? json(SESSION) : json({ type: 'u', title: 'Authentication required', status: 401 }, 401);
    if (path === '/auth/tenant' || path === '/auth/logout') return json(null, 204);
    if (path === '/api/v1/me/permissions') return json({ role: sc.role ?? 'triager', scopes: ['tenant'] });
    if (path === '/api/v1/me/tenants') return json([{ id: 't1', slug: 'acme', name: 'Acme' }, { id: 't2', slug: 'globex', name: 'Globex' }]);
    if (/^\/api\/v1\/findings\/[^/]+$/.test(path) && (init?.method ?? 'GET') === 'GET') {
      if (sc.sources === 'error') return json({ type: 'u', title: 'boom', status: 500 }, 500);
      return json({ finding: {}, reported_by: sc.sources?.reported_by ?? [], also_reported_by: sc.sources?.also_reported_by ?? [] });
    }
    if (path.startsWith('/api/v1/findings/') && path.endsWith('/events')) return json({ items: sc.events?.length ? sc.events : null });
    if (path === '/api/v1/findings/bulk' && init?.method === 'POST') {
      return json(sc.bulk ?? { matched: 2, updated: 1, unchanged: 0, failed: [{ id: 'f-2-0000-0000', error: 'your role does not allow this on its application' }] });
    }
    if (path.startsWith('/api/v1/findings/') && (init?.method ?? 'GET') === 'PATCH') {
      const st = sc.patch ?? 200;
      if (st === 409) return json({ type: 'https://rampart.aspm.dev/problems/conflict-version', title: 'The finding was changed by someone else.', status: 409, request_id: 'req_409' }, 409);
      if (st === 400) return json({ type: 'https://rampart.aspm.dev/problems/validation', title: 'a duplicate needs the id of the finding it duplicates, and it cannot be itself', status: 400 }, 400);
      return json(finding(1));
    }
    if (path === '/api/v1/taxonomies') {
      const items = (sc.taxonomies ?? [{ id: 'owasp-top10-2021', name: 'OWASP Top 10', version: '2021' }]).map((f) => ({ source: 'https://owasp.org/Top10/', kind: 'cwe', controls: 10, ...f }));
      return json({ items });
    }
    if (path.startsWith('/api/v1/taxonomies/') && path.endsWith('/status')) {
      if (sc.taxonomyStatus === 'error') return json({ type: 'u', title: 'boom', status: 500 }, 500);
      const id = path.split('/')[4] ?? '';
      const body = sc.taxonomyStatus?.[id] ?? { status: [] };
      return json({ id, name: id, version: '1', source: 'https://owasp.org/Top10/', kind: 'cwe', controls: body.status.length, evaluated_at: '2026-11-12T10:00:00Z', window_days: 30, ...body });
    }
    if (path === '/api/v1/me/access') return json({ role: sc.role ?? 'triager', applications: sc.access ?? {} });
    if (path === '/api/v1/access-bindings') {
      if (sc.bindings === 'error') return json({ type: 'u', title: 'boom', status: 500 }, 500);
      if ((init?.method ?? 'GET') === 'POST') return json({ id: 'bn-new' }, 201);
      return json({ items: sc.bindings ?? null });
    }
    if (path.startsWith('/api/v1/access-bindings/')) return json(null, 204);
    if (path === '/api/v1/audit') {
      if (sc.audit === 'error') return json({ type: 'u', title: 'boom', status: 500 }, 500);
      const pages = sc.audit ?? [{ items: [] }];
      const i = Math.min(auditCalls++, pages.length - 1);
      return json(pages[i]);
    }
    if (path === '/api/v1/notifications') {
      if (sc.notifications === 'error') return json({ type: 'u', title: 'boom', status: 500 }, 500);
      return json(sc.notifications ?? { items: null, unread: 0 });
    }
    if (path === '/api/v1/notifications/read') return json(null, 204);
    if (path === '/api/v1/applications') {
      if (sc.apps === 'error') return json({ type: 'https://rampart.aspm.dev/problems/internal', title: 'Failed to list applications', status: 500, request_id: 'req_apps' }, 500);
      return json({ items: sc.apps?.length ? sc.apps : null });
    }
    if (path.startsWith('/api/v1/applications/') && path.endsWith('/summary')) {
      const page = sc.appPages?.[path.split('/')[4] ?? ''];
      return page ? json(page) : json({ type: 'https://rampart.aspm.dev/problems/not-found', title: 'Application not found', status: 404 }, 404);
    }
    if (path === '/api/v1/dashboards/overview') {
      if (sc.overview === 'error') return json({ type: 'https://rampart.aspm.dev/problems/internal', title: 'Failed', status: 500, request_id: 'req_ov' }, 500);
      return json(sc.overview ?? overviewData());
    }
    if (path === '/api/v1/metrics/trend') return json({ metric: 'open', points: sc.trend ?? [] });
    if (path === '/api/v1/settings') return json({ riskAcceptanceApproval: false, riskAcceptanceMaxDays: 90 });
    if (path === '/api/v1/risk-acceptances' && (init?.method ?? 'GET') === 'POST') {
      if (sc.accept === 400) return json({ type: 'https://rampart.aspm.dev/problems/validation', title: 'this tenant allows an acceptance of at most 90 days', status: 400 }, 400);
      return json({ acceptance: acceptance(9, { status: sc.accept === 'pending' ? 'pending' : 'approved' }), applied: sc.accept === 'pending' ? 0 : 1, skipped: [] }, 201);
    }
    if (path === '/api/v1/risk-acceptances') {
      const status = new URL(url, 'http://x').searchParams.get('status');
      const all = sc.acceptances ?? [];
      const items = status ? all.filter((a) => a.status === status) : all;
      return json({ items: items.length ? items : null });
    }
    if (path.startsWith('/api/v1/risk-acceptances/') && path.endsWith('/proofs')) {
      if (init?.method === 'POST') {
        if (sc.proofUpload === 422) return json({ type: 'https://rampart.aspm.dev/problems/validation', title: 'proof refused: .docx files are not accepted; use PDF, PNG, JPEG, plain text, Markdown or a saved e-mail (.eml)', status: 422 }, 422);
        return json({ id: 'p-new', name: 'new.pdf', content_type: 'application/pdf', size_bytes: 10, uploaded_by: 'user:sara@acme.example', uploaded_at: '2026-11-12T10:00:00Z' }, 201);
      }
      return json({ items: sc.proofs ?? [] });
    }
    if (path.startsWith('/api/v1/risk-acceptances/')) {
      const parts = path.split('/');
      if ((init?.method ?? 'GET') === 'POST') {
        if (sc.decide === 400) return json({ type: 'https://rampart.aspm.dev/problems/validation', title: 'the person who asked cannot approve their own risk acceptance', status: 400 }, 400);
        return json({ acceptance: acceptance(1), applied: 1, skipped: [] });
      }
      const found = (sc.acceptances ?? []).find((a) => a.id === parts[4]);
      return found ? json(found) : json({ title: 'Not found', status: 404 }, 404);
    }
    if (path === '/api/v1/held-closes') {
      return json({ items: sc.heldCloses ?? [] });
    }
    if (path.startsWith('/api/v1/held-closes/') && path.endsWith('/confirm')) {
      return json({ id: path.split('/')[4], decision: 'confirmed', closed: 5 });
    }
    if (path.startsWith('/api/v1/held-closes/') && path.endsWith('/discard')) {
      return json({ id: path.split('/')[4], decision: 'discarded' });
    }
    if (path === '/api/v1/runs') {
      if (sc.runs === 'error') return json({ type: 'https://rampart.aspm.dev/problems/internal', title: 'Failed to list runs', status: 500, request_id: 'req_runs' }, 500);
      const pages = sc.runs ?? [];
      const cursor = new URL(url, 'http://x').searchParams.get('cursor');
      const idx = cursor ? Number(cursor) : 0;
      const items = pages[idx] ?? [];
      return json({ items: items.length ? items : null, next_cursor: idx + 1 < pages.length ? String(idx + 1) : '' });
    }
    if (path === '/api/v1/uploads/direct' && init?.method === 'POST') {
      return json({ ingestRunId: '00000001-aaaa-bbbb-cccc-000000000001', status: 'completed' }, 201);
    }
    if (path.startsWith('/api/v1/runs/')) {
      const id = decodeURIComponent(path.split('/').pop() ?? '');
      const found = (Array.isArray(sc.runs) ? sc.runs.flat() : []).find((r) => r.id === id);
      return found ? json(found) : json({ title: 'Run not found', status: 404 }, 404);
    }
    if (path === '/api/v1/findings') {
      if (sc.findings === 'error') return json({ type: 'https://rampart.aspm.dev/problems/internal', title: 'Failed to list findings', status: 500, request_id: 'req_1' }, 500);
      const items = sc.findings ?? [];
      return json({ items: items.length ? items : null, total: items.length, next_cursor: '' });
    }
    return json({ title: 'Not found', status: 404 }, 404);
  }));
  return calls;
}

export function renderApp(path: string) {
  const history = createMemoryHistory({ initialEntries: [path] });
  return { history, ...render(<App history={history} />) };
}
