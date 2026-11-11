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
      },
      risk: { base_severity: band, base_points: BAND_BASE[band], factors, total_score: total, band, has_kev: fs.includes('KEV'), epss_score: 0 },
      sla_due_date: new Date(now + (6 - i) * 86_400_000).toISOString(),
    };
  }).sort((a, b) => b.risk.total_score - a.risk.total_score);
}
const ALL = makeFindings();

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
    if (p === '/api/v1/me/permissions') return json(res, { role: 'triager', scopes: ['tenant'] });
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
