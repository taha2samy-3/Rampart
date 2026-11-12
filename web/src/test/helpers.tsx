import { render } from '@testing-library/react';
import { createMemoryHistory } from '@tanstack/react-router';
import { vi } from 'vitest';
import { App } from '@/app/App';

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
      state: 'open', first_seen: '2026-10-01T00:00:00Z', rule_scanner_family: 'semgrep', rule_id: 'r1',
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
    if (path === '/api/v1/me/permissions') return json({ role: 'triager', scopes: ['tenant'] });
    if (path === '/api/v1/me/tenants') return json([{ id: 't1', slug: 'acme', name: 'Acme' }, { id: 't2', slug: 'globex', name: 'Globex' }]);
    if (path === '/api/v1/runs') {
      if (sc.runs === 'error') return json({ type: 'https://rampart.aspm.dev/problems/internal', title: 'Failed to list runs', status: 500, request_id: 'req_runs' }, 500);
      const pages = sc.runs ?? [];
      const cursor = new URL(url, 'http://x').searchParams.get('cursor');
      const idx = cursor ? Number(cursor) : 0;
      const items = pages[idx] ?? [];
      return json({ items: items.length ? items : null, next_cursor: idx + 1 < pages.length ? String(idx + 1) : '' });
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
