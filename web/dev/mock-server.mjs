// Dev mock of the Rampart HTTP contract. No dependencies.
//   node dev/mock-server.mjs            (port 8099)
// Scenarios: loggedout | empty | populated | error
//   MOCK_SCENARIO=empty node dev/mock-server.mjs
//   curl 'http://127.0.0.1:8099/__mock/scenario?set=populated'   (also via the Vite proxy)
import http from 'node:http';

const PORT = Number(process.env.MOCK_PORT ?? 8099);
let scenario = process.env.MOCK_SCENARIO ?? 'populated';
let dataMode = scenario === 'loggedout' ? 'populated' : scenario;
let tenantSlug = 'acme';
const SCENARIOS = ['loggedout', 'empty', 'populated', 'error'];
const TENANTS = [
  { id: '0a1b2c3d-0000-4000-8000-000000000001', slug: 'acme', name: 'Acme' },
  { id: '0a1b2c3d-0000-4000-8000-000000000002', slug: 'globex', name: 'Globex' },
];
const LOGIN_METHODS = JSON.parse(process.env.MOCK_METHODS ?? '[{"id":"default","name":"Default SSO","type":"oidc"}]');

// Ingest runs (internal/query/runs.go RunView), newest first.
const RUN_STATS = (parsed, created, updated, untouched, reactivated, closed, record_errors = 0) => ({ parsed, created, updated, untouched, reactivated, closed, record_errors, weak_fingerprints: 0 });
const RUNS = [
  { id: '01a1ceb5-a47c-7484-8fee-7915eba6176d', status: 'merging', created_at: new Date(Date.now() - 40_000).toISOString(), scanner_family: 'sarif', format: 'sarif', track: 'main', stats: RUN_STATS(0, 0, 0, 0, 0, 0), context: { repository: 'github.com/acme/shop', branch: 'main', commit: '9f2c1a8d3e', build_id: '4821' }, scanners: ['semgrep'], ephemeral: false },
  { id: '01a1ceb4-1c02-7a11-9d3b-2a8e5f0c7e44', status: 'completed', created_at: new Date(Date.now() - 3_600_000).toISOString(), scanner_family: 'sarif', format: 'sarif', track: 'pr/412', stats: RUN_STATS(31, 2, 0, 29, 0, 0), context: { repository: 'github.com/acme/shop', branch: 'refs/pull/412/merge', commit: '5be07c1a99' }, scanners: ['trivy'], ephemeral: true },
  { id: '01a1ceb3-77aa-7b90-8e41-0c3d9a6b2f10', status: 'failed', error: 'sha256_mismatch', created_at: new Date(Date.now() - 7_200_000).toISOString(), scanner_family: 'sarif', format: 'sarif', track: 'main', stats: RUN_STATS(0, 0, 0, 0, 0, 0), context: { repository: 'github.com/acme/billing', branch: 'main', commit: 'c0ffee1234' }, scanners: ['gitleaks'], ephemeral: false },
  { id: '01a1ceb2-0d19-7c55-a2f6-6b14e7d3a001', status: 'completed_with_errors', created_at: new Date(Date.now() - 86_400_000).toISOString(), scanner_family: 'cyclonedx', format: 'cyclonedx', track: 'main', stats: RUN_STATS(214, 9, 3, 198, 1, 4, 2), context: { image_ref: 'registry.acme.example/shop/api:2.14.0', environment: 'production' }, scanners: ['syft'], ephemeral: false, error: 'record_errors', has_report: true, record_error_list: [{ where: 'Vulnerabilities 41', message: 'the record does not have the shape this tool writes (json: cannot unmarshal string into Go struct field vuln.CVSS of type object)' }, { where: 'Vulnerabilities 97', message: 'the record does not have the shape this tool writes (json: cannot unmarshal number into Go struct field vuln.Severity of type string)' }] },
  { id: '01a1ceb1-5e3b-7d02-b7c8-91f0a2e48c33', status: 'completed', created_at: new Date(Date.now() - 3 * 86_400_000).toISOString(), scanner_family: 'sarif', format: 'sarif', track: 'main', stats: RUN_STATS(48, 4, 1, 43, 0, 2), context: { repository: 'github.com/acme/shop', branch: 'main', commit: '3a77d90b12' }, scanners: ['semgrep'], ephemeral: false },
];

// Applications and the overview (internal/query/overview.go).
const bands = (critical, high, medium, low) => ({ critical, high, medium, low });
const day = (n) => new Date(Date.now() - n * 86_400_000).toISOString();
const APP_ROWS = [
  { id: 'a0000001-0000-4000-8000-000000000001', slug: 'checkout', name: 'Checkout', business_criticality: 'critical', internet_facing: true, open: bands(3, 6, 4, 2), risk_score: 1000, exposure_count: 9, sla_breached: 4, last_scan: day(0.1) },
  { id: 'a0000001-0000-4000-8000-000000000002', slug: 'billing', name: 'Billing', business_criticality: 'high', internet_facing: false, open: bands(0, 3, 5, 1), risk_score: 650, exposure_count: 3, sla_breached: 1, last_scan: day(2) },
  { id: 'a0000001-0000-4000-8000-000000000003', slug: 'search', name: 'Search', business_criticality: 'medium', internet_facing: true, open: bands(0, 1, 2, 4), risk_score: 420, exposure_count: 1, sla_breached: 0, last_scan: day(21) },
  { id: 'a0000001-0000-4000-8000-000000000004', slug: 'ledger', name: 'Ledger', business_criticality: 'high', internet_facing: false, open: bands(0, 0, 0, 0), risk_score: 0, exposure_count: 0, sla_breached: 0 },
];
const TREND = Array.from({ length: 30 }, (_, i) => ({ day: new Date(Date.now() - (29 - i) * 86_400_000).toISOString().slice(0, 10), value: Math.round(70 + Math.sin(i / 4) * 8 + i * 0.6) }));
const OVERVIEW = () => ({
  changes: { since: day(1), new: 14, reopened: 2, fixed: 9 },
  open: bands(3, 10, 11, 7),
  overdue_total: 5,
  overdue: [
    { id: 'f0000000-0000-4000-8000-000000000001', title: 'Hard-coded JWT signing secret', band: 'critical', due: day(9), app_slug: 'checkout', app_name: 'Checkout' },
    { id: 'f0000000-0000-4000-8000-000000000002', title: 'SQL injection in order search', band: 'critical', due: day(4), app_slug: 'checkout', app_name: 'Checkout' },
    { id: 'f0000000-0000-4000-8000-000000000003', title: 'Server-side request forgery in webhook fetch', band: 'high', due: day(2), app_slug: 'billing', app_name: 'Billing' },
  ],
  sla: { within: 41, late: 7, breached: 5, adherence: 41 / 53 },
  top_apps: APP_ROWS.filter((a) => a.risk_score > 0),
  coverage_gaps: [APP_ROWS[2], APP_ROWS[3]],
});

const BAND_BASE = { critical: 600, high: 400, medium: 200, low: 80, info: 10 };
const F = {
  KEV: [300, 'Vulnerability listed in CISA Known Exploited Vulnerabilities catalog'],
  EPSS_HIGH: [150, 'EPSS exploitation probability is >= 50%'],
  EPSS_MODERATE: [60, 'EPSS exploitation probability is >= 10%'],
  SECRET_VERIFIED: [250, 'Secret credential verified live against upstream provider'],
  INTERNET_FACING: [100, 'Asset or application is internet-facing'],
  SENSITIVE_DATA: [80, 'Handles PCI, PII or PHI'],
  PRODUCTION_ENV: [60, 'Runs in a production environment'],
  FIX_AVAILABLE: [20, 'A fixed version is available'],
  AGING_DEBT: [30, 'Open longer than the age threshold'],
  UNREACHABLE: [-200, 'Vulnerable code is not reachable'],
  COMPENSATING_CONTROL: [-80, 'A compensating control is in place'],
};
const SAMPLES = [
  ['critical', 'AWS access key committed in config/prod.env', 'secrets', 'gitleaks', 'config/prod.env:12', ['SECRET_VERIFIED', 'INTERNET_FACING', 'PRODUCTION_ENV']],
  ['critical', 'CVE-2024-3094 xz-utils backdoor in liblzma', 'sca', 'trivy', 'pkg:deb/debian/xz-utils@5.6.0', ['KEV', 'EPSS_HIGH', 'INTERNET_FACING']],
  ['critical', 'SQL injection in order search handler', 'sast', 'semgrep', 'internal/orders/search.go:88', ['INTERNET_FACING', 'SENSITIVE_DATA']],
  ['critical', 'CVE-2023-44487 HTTP/2 rapid reset', 'sca', 'grype', 'pkg:golang/golang.org/x/net@0.12.0', ['KEV', 'EPSS_HIGH', 'COMPENSATING_CONTROL']],
  ['high', 'Server-side request forgery in webhook fetcher', 'sast', 'semgrep', 'internal/hooks/fetch.go:41', ['INTERNET_FACING', 'PRODUCTION_ENV']],
  ['high', 'CVE-2024-21626 runc container escape', 'container', 'trivy', 'pkg:golang/github.com/opencontainers/runc@1.1.11', ['EPSS_MODERATE', 'PRODUCTION_ENV']],
  ['high', 'Hard-coded JWT signing secret', 'secrets', 'gitleaks', 'src/auth/jwt.ts:9', ['SENSITIVE_DATA']],
  ['high', 'Prototype pollution in lodash.merge', 'sca', 'osv-scanner', 'pkg:npm/lodash@4.17.20', ['FIX_AVAILABLE', 'AGING_DEBT']],
  ['high', 'Container runs as root', 'iac', 'checkov', 'deploy/k8s/payments.yaml:27', ['PRODUCTION_ENV']],
  ['medium', 'Missing Content-Security-Policy header', 'dast', 'zap', 'https://shop.example.com/', ['INTERNET_FACING']],
  ['medium', 'Weak TLS cipher suites enabled', 'dast', 'zap', 'https://api.example.com/', ['INTERNET_FACING', 'COMPENSATING_CONTROL']],
  ['medium', 'Regular expression denial of service in semver', 'sca', 'trivy', 'pkg:npm/semver@7.3.2', ['FIX_AVAILABLE']],
  ['medium', 'Unvalidated redirect after login', 'sast', 'semgrep', 'web/login.py:120', ['INTERNET_FACING']],
  ['medium', 'S3 bucket without access logging', 'iac', 'checkov', 'infra/s3.tf:14', []],
  ['low', 'Verbose error message reveals stack trace', 'sast', 'semgrep', 'internal/api/errors.go:55', ['UNREACHABLE']],
  ['low', 'Cookie without SameSite attribute', 'dast', 'zap', 'https://shop.example.com/cart', []],
  ['low', 'Outdated base image alpine:3.16', 'container', 'trivy', 'pkg:oci/alpine@3.16', ['FIX_AVAILABLE', 'AGING_DEBT']],
  ['low', 'Missing HSTS preload directive', 'dast', 'zap', 'https://shop.example.com/', []],
  ['low', 'Unused dependency with known advisory', 'sca', 'osv-scanner', 'pkg:npm/minimist@1.2.5', ['UNREACHABLE']],
  ['info', 'Server version disclosed in response header', 'dast', 'zap', 'https://api.example.com/', []],
  ['info', 'Dockerfile uses latest tag', 'iac', 'checkov', 'Dockerfile:1', []],
  ['info', 'TODO comment mentions security review', 'sast', 'semgrep', 'src/billing/charge.ts:210', []],
  ['info', 'Debug endpoint reachable internally', 'dast', 'zap', 'http://10.0.4.7/debug', ['UNREACHABLE']],
  ['info', 'Package has no declared licence', 'sca', 'trivy', 'pkg:npm/left-pad@1.3.0', []],
  ['info', 'Commented-out credentials in test fixture', 'secrets', 'gitleaks', 'test/fixtures/db.yml:3', []],
];
const STATES = ['open', 'open', 'open', 'under_investigation', 'open', 'risk_accepted', 'open', 'fixed'];
const APPS = ['b7e1c9a2-4f10-4c1e-9d11-0a0000000001', 'c8f2dab3-5a21-4d2f-8e22-0a0000000002', 'd903ebc4-6b32-4e30-9f33-0a0000000003'];

function makeFindings() {
  const now = Date.now();
  return SAMPLES.map(([band, title, category, family, loc, fs], i) => {
    const factors = fs.map((n) => ({ name: n, points: F[n][0], reason: F[n][1] }));
    let total = BAND_BASE[band] + factors.reduce((s, f) => s + f.points, 0);
    total = Math.max(0, Math.min(1000, total));
    const isFile = !loc.startsWith('pkg:') && !loc.startsWith('http');
    const [path, line] = isFile ? loc.split(':') : [loc];
    return {
      finding: {
        id: `f0000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}`,
        asset_id: `a0000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}`,
        application_id: APPS[i % 3],
        category,
        rule_scanner_family: family,
        rule_id: `${family}.rule.${100 + i}`,
        title,
        vulnerability_id: title.startsWith('CVE-') ? title.split(' ')[0] : null,
        location: loc.startsWith('pkg:') ? { purl: loc } : { file_path: path, start_line: line ? Number(line) : undefined },
        severity: band,
        risk_score: total,
        state: STATES[i % STATES.length],
        detection: 'present',
        first_seen: new Date(now - (i * 3 + 1) * 86_400_000).toISOString(),
        last_seen: new Date(now - 3_600_000).toISOString(),
        occurrence_count: 1,
        version: 1,
      },
      risk: { base_severity: band, base_points: BAND_BASE[band], factors, total_score: total, band, has_kev: fs.includes('KEV'), epss_score: 0 },
      sla_due_date: new Date(now + (6 - i) * 86_400_000).toISOString(),
    };
  }).sort((a, b) => b.risk.total_score - a.risk.total_score);
}
const ALL = makeFindings();

// Triage (docs/16 D38): the same rules as internal/domain/triage.go, enough to click through the dialog.
const JUSTIFICATIONS = ['component_not_present', 'vulnerable_code_not_present', 'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary', 'inline_mitigations_already_exist'];
const EVENTS = new Map(); // finding id -> events, oldest first
const eventsOf = (id) => {
  if (!EVENTS.has(id)) EVENTS.set(id, [{ id: 'e-' + id, at: new Date(Date.now() - 5 * 86_400_000).toISOString(), actor: 'system:parser', type: 'created' }]);
  return EVENTS.get(id);
};
function applyTriage(row, body, version) {
  const f = row.finding;
  if (version !== undefined && version !== f.version) return { status: 409, title: 'The finding was changed by someone else. Reload it and decide again.' };
  const touches = body.state || body.note || body.owner !== undefined || body.severity || body.tags || body.addTags || body.removeTags;
  if (!touches) return { status: 400, title: 'nothing to change: give a state, severity, tags, an owner or a note' };
  if (body.severity && !body.severityReason) return { status: 400, title: 'a severity override needs a reason' };
  if (body.owner && !body.owner.endsWith('@acme.example')) return { status: 400, title: 'the owner must be a member of this tenant: ' + body.owner + ' is not' };
  if (body.state === 'risk_accepted') return { status: 400, title: 'a risk is accepted through a risk acceptance, which needs an owner and an expiry' };
  if (body.state === 'not_affected' && !JUSTIFICATIONS.includes(body.justification)) return { status: 400, title: 'not_affected needs one of the OpenVEX justifications: ' + JUSTIFICATIONS.join(', ') };
  if (body.state === 'duplicate' && !body.duplicateOf) return { status: 400, title: 'a duplicate needs the id of the finding it duplicates, and it cannot be itself' };
  const evs = eventsOf(f.id);
  if (body.state && body.state !== f.state) {
    evs.push({ id: 'e' + Math.random().toString(36).slice(2), at: new Date().toISOString(), actor: 'user:sara.ahmed@acme.example', type: 'state_changed', from: f.state, to: body.state, note: body.note });
    f.state = body.state;
    f.state_reason = body.note;
    f.justification = body.state === 'not_affected' ? body.justification : undefined;
    f.impact_statement = body.state === 'not_affected' ? body.impactStatement : undefined;
  } else if (body.note) {
    evs.push({ id: 'e' + Math.random().toString(36).slice(2), at: new Date().toISOString(), actor: 'user:sara.ahmed@acme.example', type: 'note_added', note: body.note });
  }
  const now = () => new Date().toISOString();
  const id = () => 'e' + Math.random().toString(36).slice(2);
  if (body.owner !== undefined && body.owner !== (f.owner ?? '')) {
    evs.push({ id: id(), at: now(), actor: 'user:sara.ahmed@acme.example', type: 'owner_changed', from: f.owner ?? '', to: body.owner });
    f.owner = body.owner || undefined;
  }
  if (body.severity && body.severity !== f.severity) {
    evs.push({ id: id(), at: now(), actor: 'user:sara.ahmed@acme.example', type: 'severity_changed', from: f.severity, to: body.severity, note: body.severityReason });
    f.severity = body.severity;
    f.severity_override_reason = body.severityReason;
  }
  let tags = body.tags ?? f.tags ?? [];
  if (body.addTags || body.removeTags) tags = [...new Set([...(f.tags ?? []), ...(body.addTags ?? [])])].filter((t) => !(body.removeTags ?? []).includes(t));
  if (tags.join() !== (f.tags ?? []).join()) {
    evs.push({ id: id(), at: now(), actor: 'user:sara.ahmed@acme.example', type: 'tags_changed' });
    f.tags = [...tags].sort();
  }
  f.version += 1;
  return null;
}

function filter(q) {
  let rows = ALL;
  for (const tok of q.split(/\s+/).filter(Boolean)) {
    const neg = tok.startsWith('-');
    const t = neg ? tok.slice(1) : tok;
    const m = /^([a-z]+):(.+)$/.exec(t);
    let test;
    if (m) {
      const vals = m[2].split(',');
      const field = m[1];
      test = (r) => {
        if (field === 'risk' || field === 'severity') return vals.includes(r.risk.band);
        if (field === 'state') return vals.includes(r.finding.state);
        if (field === 'scanner') return vals.includes(r.finding.rule_scanner_family);
        if (field === 'category') return vals.includes(r.finding.category);
        return true;
      };
    } else test = (r) => r.finding.title.toLowerCase().includes(t.toLowerCase());
    rows = rows.filter((r) => (neg ? !test(r) : test(r)));
  }
  return rows;
}

const problem = (res, status, title, detail, extra = {}) => {
  res.writeHead(status, { 'Content-Type': 'application/problem+json' });
  res.end(JSON.stringify({ type: `https://rampart.aspm.dev/problems/${status === 401 ? 'unauthorized' : status >= 500 ? 'internal' : 'validation'}`, title, status, detail, request_id: 'req_mock_' + Math.random().toString(36).slice(2, 10), ...extra }));
};
const json = (res, body, status = 200) => {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;
  const loggedIn = scenario !== 'loggedout';
  const tenant = TENANTS.find((t) => t.slug === tenantSlug) ?? TENANTS[0];

  if (p === '/__mock/scenario') {
    const set = url.searchParams.get('set');
    if (SCENARIOS.includes(set)) {
      scenario = set;
      tenantSlug = 'acme';
      if (set !== 'loggedout') dataMode = set;
    }
    return json(res, { scenario });
  }
  if (p === '/api/v1/ui-config') {
    return json(res, { product: 'Rampart', version: '0.1.0', features: [], login: { methods: LOGIN_METHODS }, locale: { default: 'en' }, supportUrl: '' });
  }
  if (p === '/auth/session') {
    if (!loggedIn) return problem(res, 401, 'Authentication required', 'No active session.');
    return json(res, {
      user: { id: 'u-1', email: 'sara.ahmed@acme.example', name: 'Sara Ahmed' },
      tenant,
      csrfToken: 'mock-csrf-token',
      expiresAt: new Date(Date.now() + 8 * 3_600_000).toISOString(),
    });
  }
  if (p === '/auth/login') {
    const t = url.searchParams.get('tenant');
    const returnTo = url.searchParams.get('return_to') || '/findings';
    if (t === 'nope') {
      res.writeHead(302, { Location: '/login?error=tenant_not_found' });
      return res.end();
    }
    if (t === 'denied') {
      res.writeHead(302, { Location: '/login?error=no_access&request_id=req_mock_denied' });
      return res.end();
    }
    scenario = dataMode;
    res.writeHead(302, { Location: returnTo });
    return res.end();
  }
  if (p === '/auth/local/login' && req.method === 'POST') {
    if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) return problem(res, 415, 'Send the sign-in as JSON', '');
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      try {
        const { username, password } = JSON.parse(body);
        if (username === 'locked') {
          res.setHeader('Retry-After', '900');
          return problem(res, 429, 'This account is locked after too many wrong passwords', 'Try again in 15 minutes, or reset the password with the CLI.');
        }
        if (username === 'admin' && password === 'correct-horse-9') {
          scenario = dataMode;
          res.writeHead(204);
          return res.end();
        }
        return problem(res, 401, 'Wrong username or password', 'Check them and try again.');
      } catch {
        return problem(res, 400, 'A username and a password are required', '');
      }
    });
    return;
  }
  if (p === '/auth/logout' && req.method === 'POST') {
    if (req.headers['x-csrf-token'] !== 'mock-csrf-token') return problem(res, 403, 'Forbidden', 'Missing or wrong CSRF token.');
    scenario = 'loggedout';
    res.writeHead(204);
    return res.end();
  }
  if (p === '/auth/tenant' && req.method === 'POST') {
    if (req.headers['x-csrf-token'] !== 'mock-csrf-token') return problem(res, 403, 'Forbidden', 'Missing or wrong CSRF token.');
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      try {
        const { tenant: slug } = JSON.parse(body);
        if (!TENANTS.some((t) => t.slug === slug)) return problem(res, 404, 'Tenant not found', `No tenant "${slug}".`);
        tenantSlug = slug;
        res.writeHead(204);
        res.end();
      } catch {
        problem(res, 400, 'Invalid body', 'Expected {"tenant":"<slug>"}.');
      }
    });
    return;
  }
  if (p.startsWith('/api/')) {
    if (!loggedIn) return problem(res, 401, 'Authentication required', 'No active session.');
    if (p === '/api/v1/me') return json(res, { user: { id: 'u-1', email: 'sara.ahmed@acme.example', name: 'Sara Ahmed' }, tenant });
    if (p === '/api/v1/me/tenants') return json(res, TENANTS);
    if (p === '/api/v1/me/permissions') return json(res, { role: 'admin', scopes: ['tenant'] });
    if (p === '/api/v1/taxonomies') return json(res, { items: [
      { id: 'owasp-top10-2021', name: 'OWASP Top 10', version: '2021', source: 'https://owasp.org/Top10/', kind: 'cwe', controls: 10 },
      { id: 'pci-dss-4.0.1-req6', name: 'PCI DSS, requirement 6 and 8.6.2', version: '4.0.1', source: 'https://www.pcisecuritystandards.org/document_library/', kind: 'category', note: 'PCI DSS does not list weaknesses by CWE, so each requirement is assessed by the kind of scan that evidences it.', controls: 6 },
    ] });
    if (p.startsWith('/api/v1/taxonomies/') && p.endsWith('/status')) {
      const b = (c, h, m, l) => ({ critical: c, high: h, medium: m, low: l });
      const ctl = (id, name, status, bands, evidence) => ({ id, name, status, open: Object.values(bands).reduce((a, n) => a + n, 0), bands, query: 'cwe:89 state:open', evidence });
      return json(res, { id: p.split('/')[4], name: 'OWASP Top 10', version: '2021', source: 'https://owasp.org/Top10/', kind: 'cwe', controls: 10, evaluated_at: new Date().toISOString(), window_days: 30, status: [
        ctl('A01:2021', 'Broken Access Control', 'open', b(0, 2, 3, 0), ['semgrep']),
        ctl('A02:2021', 'Cryptographic Failures', 'clear', b(0, 0, 0, 0), ['semgrep', 'trivy']),
        ctl('A03:2021', 'Injection', 'open', b(2, 1, 4, 1), ['semgrep']),
        ctl('A04:2021', 'Insecure Design', 'clear', b(0, 0, 0, 0), ['semgrep']),
        ctl('A06:2021', 'Vulnerable and Outdated Components', 'open', b(1, 5, 2, 0), ['trivy', 'grype']),
        ctl('A09:2021', 'Security Logging and Monitoring Failures', 'not_assessed', b(0, 0, 0, 0), []),
      ] });
    }
    if (p === '/api/v1/me/access') return json(res, { role: 'admin', applications: {} });
    if (p === '/api/v1/access-bindings' && req.method === 'GET') {
      const w = (n) => new Date(Date.now() - n * 86400000).toISOString();
      return json(res, { items: dataMode === 'empty' ? [] : [
        { id: 'bn1', subject: 'sara@acme.example', role: 'owner', application_id: APP_ROWS[0].id, application_name: APP_ROWS[0].name, managed_by: 'api', created_by: 'user:boss@acme.example', created_at: w(30) },
        { id: 'bn2', subject: 'omar@acme.example', role: 'triager', application_id: APP_ROWS[0].id, application_name: APP_ROWS[0].name, managed_by: 'api', created_by: 'user:sara@acme.example', created_at: w(9) },
        { id: 'bn3', subject: 'omar@acme.example', role: 'maintainer', application_id: APP_ROWS[1].id, application_name: APP_ROWS[1].name, managed_by: 'api', created_by: 'user:boss@acme.example', created_at: w(2) },
      ] });
    }
    if (p === '/api/v1/access-bindings' && req.method === 'POST') { res.writeHead(201, { 'Content-Type': 'application/json' }); return res.end('{"id":"bn-new"}'); }
    if (p.startsWith('/api/v1/access-bindings/') && req.method === 'DELETE') { res.writeHead(204); return res.end(); }
    if (p === '/api/v1/audit' && req.method === 'GET') {
      const w = (n) => new Date(Date.now() - n * 3600000).toISOString();
      const row = (n, actor, action, rt, rid, status) => ({ id: `au${n}`, at: w(n), actor, action, resource_type: rt, resource_id: rid, detail: { method: action.split(' ')[0], status }, request_id: `req_${n}` });
      return json(res, { items: dataMode === 'empty' ? [] : [
        row(1, 'user:sara@acme.example', 'PATCH /api/v1/findings/{id}', 'findings', 'f-18c2', 200),
        row(2, 'user:omar@acme.example', 'PATCH /api/v1/findings/{id}', 'findings', 'f-77aa', 403),
        row(3, 'user:boss@acme.example', 'POST /api/v1/risk-acceptances/{id}/approve', 'risk-acceptances', 'ra-31', 200),
        row(5, 'user:sara@acme.example', 'POST /api/v1/risk-acceptances', 'risk-acceptances', '', 201),
        row(9, 'ci:github/acme/checkout', 'POST /ingest/v1/uploads', 'uploads', '', 201),
      ], next_cursor: '' });
    }
    if (p === '/api/v1/notifications' && req.method === 'GET') {
      const h = (n) => new Date(Date.now() - n * 3600000).toISOString();
      const items = dataMode === 'empty' ? [] : [
        { id: 'n1', kind: 'sla_breached', title: '3 findings passed their deadline', link: '/findings?q=sla%3Abreached', created_at: h(2), unread: true },
        { id: 'n2', kind: 'sla_due_soon', title: 'A finding is due within a day', body: 'Hard-coded JWT signing secret', link: '/findings?q=sla%3Adue%3A1d', created_at: h(7), unread: true },
        { id: 'n3', kind: 'acceptance_expiring', title: 'A risk acceptance ends in 14 days', body: 'Behind the VPN. Owner: sara@acme.example. 2 findings will return to the queue.', link: '/workflow', created_at: h(60), unread: false },
      ];
      return json(res, { items, unread: items.filter((i) => i.unread).length });
    }
    if (p === '/api/v1/notifications/read' && req.method === 'POST') { res.writeHead(204); return res.end(); }
    if (p === '/api/v1/applications') return json(res, { items: APP_ROWS });
    const am = /^\/api\/v1\/applications\/([^/]+)\/summary$/.exec(p);
    if (am) {
      const a = APP_ROWS.find((x) => x.id === am[1]);
      if (!a) return problem(res, 404, 'Application not found', 'No such application.');
      return json(res, {
        ...a, sla: { within: 14, late: 3, breached: a.sla_breached, adherence: 14 / (17 + a.sla_breached) },
        mttr: [{ band: 'critical', days: 3.2, fixed: 3 }, { band: 'high', days: 11.8, fixed: 9 }],
        coverage: [
          { asset_id: 'as-1', asset: `github.com/acme/${a.slug}`, scanner: 'semgrep', last_scan: day(0.2) },
          { asset_id: 'as-1', asset: `github.com/acme/${a.slug}`, scanner: 'gitleaks', last_scan: day(0.2) },
          { asset_id: 'as-2', asset: `registry.acme.example/${a.slug}`, scanner: 'trivy', last_scan: day(6) },
        ],
        top_findings: ALL.slice(0, 5).map((r) => ({ id: r.finding.id, title: r.finding.title, band: r.risk.band, risk_score: r.risk.total_score, state: r.finding.state, sla_due_date: r.sla_due_date })),
      });
    }
    if (p === '/api/v1/dashboards/overview') return json(res, OVERVIEW());
    if (p === '/api/v1/metrics/trend') return json(res, { metric: 'open', points: TREND });
    if (p === '/api/v1/runs') {
      if (scenario === 'error') return problem(res, 500, 'Failed to list runs', 'The database did not answer within 5 s.');
      return json(res, { items: dataMode === 'empty' ? null : RUNS, next_cursor: '' });
    }
    if (p.startsWith('/api/v1/runs/')) {
      const r = RUNS.find((x) => x.id === p.split('/').pop());
      return r ? json(res, r) : problem(res, 404, 'Run not found', 'No such run.');
    }
    if (p === '/api/v1/findings/bulk' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const b = JSON.parse(body || '{}');
        const rows = b.ids ? ALL.filter((r) => b.ids.includes(r.finding.id)) : filter(b.q ?? '');
        const out = { matched: rows.length, updated: 0, unchanged: 0, failed: [] };
        for (const r of rows) {
          const err = applyTriage(r, b.patch ?? {}, undefined);
          if (err) out.failed.push({ id: r.finding.id, error: err.title });
          else out.updated++;
        }
        json(res, out);
      });
      return;
    }
    const fm = /^\/api\/v1\/findings\/([^/]+)(\/events)?$/.exec(p);
    if (fm) {
      const row = ALL.find((r) => r.finding.id === fm[1]);
      if (!row) return problem(res, 404, 'Finding not found');
      if (fm[2] && req.method === 'GET') return json(res, { items: eventsOf(row.finding.id) });
      if (!fm[2] && req.method === 'GET') {
        const sca = row.finding.category === 'sca';
        const d = (n) => new Date(Date.now() - n * 86400000).toISOString();
        const reported_by = [{ scanner: sca ? 'trivy' : row.finding.rule_scanner_family, name: sca ? 'trivy' : row.finding.rule_scanner_family, version: '0.58.1', first_seen: d(12), last_seen: d(1), reports: 9, present: true, tool_severity: row.finding.severity, latest_run_id: 'r1', locations: 1 }];
        const also_reported_by = sca ? [{ id: ALL.find((r) => r.finding.id !== row.finding.id)?.finding.id ?? row.finding.id, scanner: 'grype', rule_id: row.finding.rule_id, state: 'open' }] : [];
        return json(res, { ...row, reported_by, also_reported_by });
      }
      if (!fm[2] && req.method === 'PATCH') {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          const ifMatch = req.headers['if-match'];
          const err = applyTriage(row, JSON.parse(body || '{}'), ifMatch ? Number(String(ifMatch).replace(/"/g, '')) : undefined);
          if (err) return problem(res, err.status, err.title, undefined);
          json(res, row);
        });
        return;
      }
    }
    if (p === '/api/v1/findings') {
      if (scenario === 'error') return problem(res, 500, 'Failed to list findings', 'The database did not answer within 5 s.');
      if (dataMode === 'empty') return json(res, { items: null, total: 0 });
      const q = url.searchParams.get('q') ?? '';
      const sort = url.searchParams.get('sort') || '-score';
      const limit = Math.min(200, Number(url.searchParams.get('limit')) || 50);
      const offset = Number(url.searchParams.get('cursor') || 0) || 0;
      let rows = filter(q).slice();
      if (sort === 'score') rows.reverse();
      const page = rows.slice(offset, offset + limit);
      return json(res, { items: page, total: rows.length, next_cursor: offset + limit < rows.length ? String(offset + limit) : '' });
    }
  }
  problem(res, 404, 'Not found', `No route for ${req.method} ${p}.`);
});

server.listen(PORT, '127.0.0.1', () => console.log(`rampart mock on http://127.0.0.1:${PORT} scenario=${scenario}`));
