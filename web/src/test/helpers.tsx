import { render } from '@testing-library/react';
import { createMemoryHistory } from '@tanstack/react-router';
import { vi } from 'vitest';
import { App } from '@/app/App';
import type { CorrelatedRef, DTrackProjectRecord, FindingGroup, HeldClose, ParserDescriptor, Reporter, Role, SourceStatus, UpstreamDecision } from '@/api/types';

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
      vulnerability_id: null as string | null,
      location: { file_path: 'src/a.go', start_line: i },
    },
    risk: { base_severity: band, base_points: base, factors: [{ name: 'KEV', points: 100, reason: 'Known exploited' }], total_score: base + 100, band },
    sla_due_date: '2026-12-01T00:00:00Z',
  };
}

export interface Scenario {
  /** The occurrences GET /findings/{id} returns (the package a scanner named), and the vulnerability record and impact. */
  occurrences?: unknown[];
  /** The compliance controls GET /findings/{id} says the finding counts against. */
  findingControls?: unknown[];
  vuln?: { record?: unknown; impact?: unknown; error?: boolean };
  /** What POST /uploads/direct answers: 201 with these fields added, or 404 application-not-found. */
  upload?: Record<string, unknown> | 404;
  /** GET /integration-packages with null lists, as an old server wrote them. */
  packagesNull?: boolean;
  feeds?: unknown | 'error';
  /** GET /applications/{id}/changes; `error` answers 500. The query (from, to) of each call is in the calls. */
  appChanges?: unknown | 'error';
  /** GET /applications/{id}/compliance. */
  appCompliance?: unknown | 'error';
  /** GET /inventory and /inventory/components. error answers 500 (a missing endpoint is a 404 in production). */
  inventory?: { assets?: unknown[]; components?: unknown[]; total?: number; truncated?: boolean; error?: boolean };
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
  groups?: FindingGroup[] | 'error';
  groupFindings?: Record<string, string[]>;
  /** GET /api/v1/sources (Dependency-Track sources, D92), and per source its unmapped projects and decisions. */
  dtSources?: SourceStatus[];
  dtUnmapped?: Record<string, DTrackProjectRecord[]>;
  /** GET /sources/{id}/projects: the projects in an application, and what put each there. */
  dtMapped?: Record<string, (DTrackProjectRecord & { application_name: string; application_slug: string; by_rule: boolean })[]>;
  dtDecisions?: Record<string, UpstreamDecision[]>;
  /** The frameworks and the status of each control (by framework id). 'error' answers 500 on status. */
  taxonomies?: { id: string; name: string; version: string; origin?: string; error?: string }[];
  taxonomyHistory?: string[];
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
  parsers?: ParserDescriptor[] | 'error';
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

export function findingGroup(i: number, over: Partial<FindingGroup> = {}): FindingGroup {
  return {
    id: `grp-${i}`,
    tenant_id: 't1',
    name: `Remediation Sprint ${i}`,
    description: `Track critical findings for sprint ${i}`,
    owner: 'sara@acme.example',
    member_count: 3,
    created_at: '2026-11-10T10:00:00Z',
    updated_at: '2026-11-10T10:00:00Z',
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
export type Calls = { method: string; url: string; headers: Record<string, string>; body?: string; form?: Record<string, string> }[];

export function mockFetch(sc: Scenario): Calls {
  const calls: Calls = [];
  let auditCalls = 0;
  const json = (body: unknown, status = 200) =>
    new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'Content-Type': status >= 400 ? 'application/problem+json' : 'application/json' } });
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const path = url.split('?')[0]!;
    calls.push({ method: init?.method ?? 'GET', url, headers: (init?.headers ?? {}) as Record<string, string>, body: typeof init?.body === 'string' ? init.body : undefined, form: init?.body instanceof FormData ? Object.fromEntries([...init.body.entries()].filter(([, v]) => typeof v === 'string') as [string, string][]) : undefined });
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
      return json({ finding: {}, controls: sc.findingControls ?? [], occurrences: sc.occurrences ?? [], reported_by: sc.sources?.reported_by ?? [], also_reported_by: sc.sources?.also_reported_by ?? [] });
    }
    if (path === '/api/v1/inventory' || path === '/api/v1/inventory/components') {
      if (sc.inventory?.error) return json({ type: 'u', title: 'boom', status: 500 }, 500);
      if (path.endsWith('/components')) return json({ components: sc.inventory?.components ?? [], total: sc.inventory?.total ?? (sc.inventory?.components ?? []).length, truncated: sc.inventory?.truncated ?? false });
      return json({ assets: sc.inventory?.assets ?? [] });
    }
    if (path === '/api/v1/inventory/components/scan' && (init?.method ?? 'GET') === 'POST') {
      const body = typeof init?.body === 'string' ? JSON.parse(init.body) : {};
      const purl = body.purl || 'pkg:npm/lodash@4.17.20';
      return json({
        status: 'started',
        purl,
        message: `On-demand vulnerability scan initiated for ${purl}`,
        scanned_at: new Date().toISOString(),
      }, 202);
    }
    if (/^\/api\/v1\/applications\/[^/]+\/components$/.test(path)) {
      return json({
        components: sc.inventory?.components ?? [
          {
            name: 'log4j-core',
            version: '2.14.1',
            purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            type: 'maven',
            track: 'main',
            license: 'Apache-2.0',
            direct: true,
            asset_id: 'asset-2',
            asset_name: 'flare-reminders',
            application_name: 'Rampart Demo App',
            vulnerabilities: 2,
          },
        ],
        total: 1,
      });
    }
    if (path.startsWith('/api/v1/vulnerabilities/')) {
      if (sc.vuln?.error) return json({ type: 'u', title: 'boom', status: 500 }, 500);
      const id = decodeURIComponent(path.split('/')[4] ?? '');
      if (path.endsWith('/impact')) return json(sc.vuln?.impact ?? { id, findings: 0, open: 0, applications: [] });
      const record = sc.vuln?.record;
      return json(record ? { id, known: true, record, links: (record as { links?: string[] }).links ?? [] } : { id, known: false, links: [`https://nvd.nist.gov/vuln/detail/${id}`] });
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
    if (path.startsWith('/api/v1/taxonomies/') && path.endsWith('/history')) {
      return json({ days: sc.taxonomyHistory ?? [] });
    }
    if (path.startsWith('/api/v1/taxonomies/') && path.endsWith('/attestations') && init?.method === 'POST') {
      return json({ id: 'at-1', status: 'passed', note: 'x', attested_by: 'user:sara@acme.example', attested_at: '2026-11-16T10:00:00Z', expires_at: '2027-11-16T10:00:00Z' }, 201);
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
    if (path.startsWith('/api/v1/applications/') && path.endsWith('/changes')) {
      if (sc.appChanges === 'error') return json({ type: 'u', title: 'boom', status: 500 }, 500);
      return json(sc.appChanges ?? { application: 'x', from: '2026-10-19', to: '2026-11-17', days: 30, summary: { new: 0, closed: 0, reopened: 0, open_at_start: 0, open_at_end: 0, previous: { from: '', to: '', new: 0, closed: 0 } }, daily: [], new: [], closed: [], reopened: [], open: [], truncated: [] });
    }
    if (path.startsWith('/api/v1/applications/') && path.endsWith('/compliance')) {
      if (sc.appCompliance === 'error') return json({ type: 'u', title: 'boom', status: 500 }, 500);
      return json(sc.appCompliance ?? { application: 'x', evaluated_at: '2026-11-17T00:00:00Z', frameworks: [], not_in_scope: [] });
    }
    if (path.startsWith('/api/v1/applications/') && path.endsWith('/trend')) {
      const points = Array.from({ length: 14 }, (_, i) => ({ day: `2026-11-${String(i + 1).padStart(2, '0')}`, critical: i % 3, high: 4 + (i % 2), medium: 6, low: 2, new: i % 4, fixed: 1 + (i % 3) }));
      return json({ days: 14, points, aging: { under_30: 5, d30_90: 3, d90_180: 1, over_180: 1 } });
    }
    if (path.startsWith('/api/v1/applications/') && path.endsWith('/summary')) {
      const page = sc.appPages?.[path.split('/')[4] ?? ''];
      return page ? json(page) : json({ type: 'https://rampart.aspm.dev/problems/not-found', title: 'Application not found', status: 404 }, 404);
    }
    if (path === '/api/v1/dashboards/overview') {
      if (sc.overview === 'error') return json({ type: 'https://rampart.aspm.dev/problems/internal', title: 'Failed', status: 500, request_id: 'req_ov' }, 500);
      return json(sc.overview ?? overviewData());
    }
    if (path === '/api/v1/views') return json({ views: [] });
    if (path === '/api/v1/sources') return json({ sources: sc.dtSources ?? [] });
    if (path.startsWith('/api/v1/sources/')) {
      const [, , , , sid = '', what] = path.split('/');
      if (what === 'projects') return json({ projects: sc.dtMapped?.[sid] ?? [], count: sc.dtMapped?.[sid]?.length ?? 0 });
      if (what === 'unmapped') return json({ projects: sc.dtUnmapped?.[sid] ?? [], count: 0 });
      if (what === 'decisions') return json({ decisions: sc.dtDecisions?.[sid] ?? [] });
      if (what === 'map') return json({ status: 'mapped', sync_queued: true });
    }
    if (path === '/api/v1/groups') {
      if (sc.groups === 'error') return json({ type: 'u', title: 'boom', status: 500 }, 500);
      if (init?.method === 'POST') {
        const b = typeof init?.body === 'string' ? JSON.parse(init.body) : {};
        return json(findingGroup(9, { name: b.name, description: b.description, application_id: b.application_id }), 201);
      }
      return json({ groups: sc.groups ?? [] });
    }
    if (path.startsWith('/api/v1/groups/')) {
      const parts = path.split('/');
      const grpId = decodeURIComponent(parts[4] ?? '');
      if (parts.length === 6 && parts[5] === 'members') {
        return json(null, 204);
      }
      if (parts.length === 6 && parts[5] === 'ticket') {
        return json({ group_id: grpId, ticket: { status: 'reserved' } }, 202);
      }
      if (init?.method === 'DELETE') {
        return json(null, 204);
      }
      const grp = (Array.isArray(sc.groups) ? sc.groups : []).find((g) => g.id === grpId) ?? findingGroup(1, { id: grpId });
      const fIds = sc.groupFindings?.[grpId] ?? ['f-1', 'f-2'];
      return json({ group: grp, finding_ids: fIds });
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
    // Connectors are resources (D82): listed, described and validated, never created here.
    if (path === '/api/v1/connectors') {
      return json({ items: [
        { name: 'jira-sec', type: 'jira', direction: 'bidirectional', enabled: true, managed_by: 'resource',
          status: { conditions: [{ type: 'Connected', status: 'True', reason: 'AuthOK', message: 'Connector verified successfully' }] } },
        { name: 'slack-appsec', type: 'slack', direction: 'outbound', enabled: true, managed_by: 'resource',
          status: { conditions: [{ type: 'Connected', status: 'Unknown', reason: 'PendingVerification', message: 'Connector registered, connection not yet tested' }] } },
        { name: 'chat-sec', type: 'plugin', direction: 'outbound', enabled: true, managed_by: 'resource', spec: { plugin: { name: 'google-chat' } },
          status: { conditions: [{ type: 'Connected', status: 'Unknown', reason: 'NotProbed', message: 'A declarative notifier has no check request; the first delivery tests it' }] } },
      ] });
    }
    // D94: tools installed as data.
    if (path === '/api/v1/integration-packages') {
      // What the server answered before the fix: a parser package with null lists (Go nil slices).
      if (sc.packagesNull) return json({ items: [{ name: 'pip-audit', kind: 'parser', runtime: 'mapping', version: '1.0.0', egress: null, secrets: null, config: null, used_by: null, updated_at: '2026-11-16T10:00:00Z' }] });
      return json({ items: [
        { name: 'google-chat', kind: 'notifier', runtime: 'declarative', version: '1.0.0', description: 'Google Chat spaces', egress: ['chat.googleapis.com'],
          secrets: ['webhookUrl'], config: [], used_by: ['chat-sec'], updated_at: '2026-11-16T10:00:00Z' },
        { name: 'acme-wasm', kind: 'parser', runtime: 'wasm', version: '0.1.0', egress: [], secrets: [], config: [], used_by: [],
          error: 'runtime "wasm": code runtimes are tier 2', updated_at: '2026-11-16T10:00:00Z' },
      ] });
    }
    if (path === '/api/v1/connectors/catalogue') {
      return json({ items: [
        { type: 'jira', name: 'Jira Cloud', kind: 'tracker', directions: ['outbound', 'bidirectional'], description: 'Opens Jira Cloud issues.',
          config_key: 'jira', config_schema: { type: 'object' },
          secrets: [{ field: 'credentialsSecretRef', holds: 'email:apiToken', purpose: 'calls the Jira API' }],
          example: 'apiVersion: rampart.aspm.dev/v1alpha1\nkind: Connector\nmetadata: {name: jira-sec}\nspec:\n  type: jira\n' },
        { type: 'slack', name: 'Slack', kind: 'notifier', directions: ['outbound'], description: 'Posts notifications.',
          config_key: 'slack', config_schema: { type: 'object' },
          secrets: [{ field: 'tokenSecretRef', holds: 'a bot token', purpose: 'posts messages' }],
          example: 'kind: Connector\nmetadata: {name: slack-appsec}\nspec:\n  type: slack\n' },
      ] });
    }
    if (path.startsWith('/api/v1/feeds/sync')) {
      const feedParam = new URL(path, 'http://localhost').searchParams.get('feed') || 'all';
      return json({ status: 'started', feed: feedParam, message: 'Feed synchronization initiated successfully', started_at: new Date().toISOString() }, 202);
    }
    if (path.startsWith('/api/v1/feeds/test-connection')) {
      const feedParam = new URL(path, 'http://localhost').searchParams.get('feed');
      const feedsPayload = (sc.feeds && sc.feeds !== 'error' ? (sc.feeds as { mirror?: Record<string, { url?: string }>; items?: Array<{ name: string; url: string }> }) : null);
      const mirror = feedsPayload?.mirror;
      const getUrl = (name: string, def: string) => {
        const item = feedsPayload?.items?.find((i) => i.name === name);
        if (item?.url) return item.url;
        const mirrorEntry = mirror ? (mirror as Record<string, { url?: string }>)[name] : undefined;
        if (mirrorEntry?.url) return mirrorEntry.url;
        return def;
      };

      const allResults = [
        { name: 'cisa_kev', url: getUrl('cisa_kev', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'), reachable: true, status_code: 200, latency_ms: 64, message: 'Upstream reachable (HTTP 200 OK)' },
        { name: 'first_epss', url: getUrl('first_epss', 'https://epss.cyentia.com/epss_scores-current.csv.gz'), reachable: true, status_code: 200, latency_ms: 110, message: 'Upstream reachable (HTTP 200 OK)' },
        { name: 'nvd', url: getUrl('nvd', 'https://services.nvd.nist.gov/rest/json/cves/2.0'), reachable: true, status_code: 200, latency_ms: 180, message: 'Upstream reachable (HTTP 200 OK)' },
        { name: 'osv', url: getUrl('osv', 'https://osv-vulnerabilities.storage.googleapis.com'), reachable: true, status_code: 200, latency_ms: 85, message: 'Upstream reachable (HTTP 200 OK)' },
        { name: 'vulnrichment', url: getUrl('vulnrichment', 'https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.zip'), reachable: true, status_code: 302, latency_ms: 140, message: 'Upstream reachable (HTTP 302 OK)' },
        { name: 'exploitdb', url: getUrl('exploitdb', 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'), reachable: true, status_code: 200, latency_ms: 95, message: 'Upstream reachable (HTTP 200 OK)' },
      ];
      const results = feedParam ? allResults.filter((r) => r.name === feedParam) : allResults;
      return json({ tested_at: new Date().toISOString(), results });
    }
    if (path === '/api/v1/feeds') {
      if (sc.feeds === 'error') return json({ type: 'https://rampart.aspm.dev/problems/internal', title: 'Failed to list feeds', status: 500 }, 500);
      return json(sc.feeds ?? {
        mirror: {
          egress: 'allow',
          storageMode: 'lightweight',
          kev: { url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' },
          epss: { url: 'https://epss.cyentia.com/epss_scores-current.csv.gz' },
          nvd: { url: 'https://services.nvd.nist.gov/rest/json/cves/2.0' },
          osv: { url: 'https://osv-vulnerabilities.storage.googleapis.com' },
        },
        items: [
          {
            name: 'cisa_kev',
            display_name: 'CISA KEV',
            category: 'Threat Intelligence',
            description: 'Known Exploited Vulnerabilities catalog published by CISA tracking actively exploited CVEs.',
            url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            is_mirror: false,
            enabled: true,
            status: 'success',
            records: 1284,
            last_sync: '2026-11-17T03:00:00Z',
            error: null,
          },
          {
            name: 'first_epss',
            display_name: 'FIRST EPSS',
            category: 'Exploit Prediction',
            description: 'Exploit Prediction Scoring System probabilities estimating likelihood of active exploitation.',
            url: 'https://epss.cyentia.com/epss_scores-current.csv.gz',
            is_mirror: false,
            enabled: true,
            status: 'success',
            records: 245100,
            last_sync: '2026-11-17T03:00:00Z',
            error: null,
          },
          {
            name: 'nvd',
            display_name: 'NVD (National Vulnerability Database)',
            category: 'Vulnerability Database',
            description: 'NIST National Vulnerability Database CVE records, CVSS severity metrics, and CWE mappings.',
            url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            is_mirror: false,
            enabled: true,
            status: 'success',
            records: 250412,
            last_sync: '2026-11-17T01:00:00Z',
            error: null,
          },
          {
            name: 'osv',
            display_name: 'OSV (Open Source Vulnerabilities)',
            category: 'Package Advisories',
            description: 'Open Source Vulnerabilities database covering open-source package registries and ecosystems.',
            url: 'https://osv-vulnerabilities.storage.googleapis.com',
            is_mirror: false,
            enabled: true,
            status: 'success',
            records: 48920,
            last_sync: '2026-11-17T01:00:00Z',
            error: null,
          },
        ],
      });
    }
    if (path === '/api/v1/connectors/validate' && init?.method === 'POST') {
      const resource = (JSON.parse(String(init.body ?? '{}')) as { resource?: string }).resource ?? '';
      return json(resource.includes('defaultProject')
        ? { valid: true }
        : { valid: false, reason: 'InvalidSpec', error: 'connector: invalid specification: jira defaultProject is required' });
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
      if (sc.upload === 404) return json({ type: 'https://rampart.aspm.dev/problems/application-not-found', title: 'No such application', status: 404, detail: 'There is no application "x" in this tenant.' }, 404);
      return json({ ingestRunId: '00000001-aaaa-bbbb-cccc-000000000001', status: 'completed', ...(typeof sc.upload === 'object' ? sc.upload : {}) }, 201);
    }
    if (path.startsWith('/api/v1/runs/')) {
      const id = decodeURIComponent(path.split('/').pop() ?? '');
      const found = (Array.isArray(sc.runs) ? sc.runs.flat() : []).find((r) => r.id === id);
      return found ? json(found) : json({ title: 'Run not found', status: 404 }, 404);
    }
    if (path === '/api/v1/parsers') {
      if (sc.parsers === 'error') return json({ type: 'https://rampart.aspm.dev/problems/internal', title: 'Failed to list parsers', status: 500, request_id: 'req_parsers' }, 500);
      return json({ parsers: sc.parsers ?? DEFAULT_PARSERS });
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

/** What the server lists by default: some built-ins and one parser package the tenant installed (D98). */
const DEFAULT_PARSERS: ParserDescriptor[] = [
  { id: 'builtin:sarif', name: 'SARIF 2.1.0 Parser', kind: 'parser', version: '2.1.0', support_level: 'builtin', description: 'OASIS SARIF 2.1.0' },
  { id: 'builtin:cyclonedx', name: 'CycloneDX Parser (JSON/XML)', kind: 'parser', version: '1.6.0', support_level: 'builtin', description: 'CycloneDX SBOM, VDR and VEX' },
  { id: 'builtin:trivy', name: 'Trivy Parser (JSON)', kind: 'parser', version: '2', support_level: 'builtin', description: 'Trivy JSON' },
  { id: 'builtin:semgrep', name: 'Semgrep Parser (JSON)', kind: 'parser', version: '1', support_level: 'builtin', description: 'Semgrep JSON' },
  { id: 'mapping:pip-audit', name: 'pip-audit (Declarative)', kind: 'parser', version: '1.0.0', support_level: 'community', description: 'Declarative mapping parser for pip-audit (sca)' },
];
