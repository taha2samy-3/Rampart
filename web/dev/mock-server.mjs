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
  ['medium', 'CVE-2026-FAIL-SYNC-9042 express-fileupload: Temporary upstream sync throttle', 'sca', 'trivy', 'pkg:npm/express-fileupload@1.4.0', ['FIX_AVAILABLE', 'PRODUCTION_ENV']],
  ['medium', 'CVE-2026-UNSCORED-9041 express-fileupload: Resource Exhaustion during multipart upload', 'sca', 'trivy', 'pkg:npm/express-fileupload@1.4.0', ['FIX_AVAILABLE', 'PRODUCTION_ENV']],
  ['high', 'CVE-2026-2359 multer: Multer vulnerable to Denial of Service', 'sca', 'trivy', 'pkg:npm/multer@1.4.4', ['EPSS_HIGH', 'FIX_AVAILABLE', 'PRODUCTION_ENV']],
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
const ACCEPTANCES = [
  { id: 'ra-31', status: 'approved', justification: 'The payments admin API is only reachable over the VPN', owner: 'user:sara.ahmed@acme.example', requester: 'user:sara.ahmed@acme.example', approver: 'user:boss@acme.example', expires_at: new Date(Date.now() + 40 * 86400000).toISOString(), on_expiry: 'reactivate', created_at: new Date(Date.now() - 5 * 86400000).toISOString(), finding_ids: ['f0000000-0000-4000-8000-000000000001', 'f0000000-0000-4000-8000-000000000002'] },
  { id: 'ra-32', status: 'pending', justification: 'Legacy crypto algorithm in staging environment undergoing migration in Q1', owner: 'user:omar@acme.example', requester: 'user:omar@acme.example', expires_at: new Date(Date.now() + 60 * 86400000).toISOString(), on_expiry: 'close', created_at: new Date(Date.now() - 2 * 86400000).toISOString(), finding_ids: ['f0000000-0000-4000-8000-000000000003'] },
  { id: 'ra-33', status: 'expired', justification: 'Temporary waiver for CVE-2023-44487 during maintenance window', owner: 'user:sara.ahmed@acme.example', requester: 'user:sara.ahmed@acme.example', approver: 'user:boss@acme.example', expires_at: new Date(Date.now() - 10 * 86400000).toISOString(), on_expiry: 'reactivate', created_at: new Date(Date.now() - 70 * 86400000).toISOString(), finding_ids: ['f0000000-0000-4000-8000-000000000004'] },
];

const PARSERS = (() => {
  const ago = (h) => new Date(Date.now() - h * 3_600_000).toISOString();
  const missing = 'its WASM module is not installed on this server (parsers.delivery in the chart)';
  const p = (id, name, family, runtime, extra = {}) => {
    const isSbom = family === 'sbom';
    const isTenant = extra.origin === 'tenant' || id.startsWith('mapping:');
    const resourceKind = isSbom ? 'ClusterSBOMParser' : isTenant ? 'Parser' : 'ClusterParser';
    const resourceName = id.replace(/^(cluster|builtin):sbom-/, '').replace(/^(cluster|builtin):/, '').replace(/^mapping:/, '');
    return {
      id, name, kind: 'parser', version: '1', support_level: isTenant ? 'community' : 'cluster',
      category: isSbom ? 'sca' : 'sast', description: `${name} reads its format into ${isSbom ? 'the inventory' : 'findings'}.`,
      family, runtime, origin: isTenant ? 'tenant' : 'cluster',
      resource_kind: resourceKind, resource_name: resourceName,
      module: runtime === 'wasm' ? resourceName : undefined, status: 'ready', ...extra,
    };
  };
  return [
    p('cluster:bandit', 'bandit Parser', 'report', 'lua', { category: 'sast', last_run: { id: RUNS[3].id, status: 'completed_with_errors', at: ago(26) }, last_success: ago(26) }),
    p('cluster:checkov', 'checkov Parser', 'report', 'wasm', { category: 'iac' }),
    p('cluster:dependencycheck', 'dependencycheck Parser', 'report', 'wasm', { category: 'sca' }),
    p('cluster:genericjson', 'genericjson Parser', 'report', 'lua', { category: 'sast' }),
    p('cluster:gitlab', 'gitlab Parser', 'report', 'wasm', { category: 'sast' }),
    p('cluster:gitleaks', 'gitleaks Parser', 'report', 'wasm', { category: 'secrets' }),
    p('cluster:grype', 'grype Parser', 'report', 'wasm', { category: 'sca' }),
    p('cluster:kubebench', 'kubebench Parser', 'report', 'wasm', { category: 'compliance' }),
    p('cluster:nuclei', 'nuclei Parser', 'report', 'lua', { category: 'dast' }),
    p('cluster:openvex', 'openvex Parser', 'report', 'wasm', { category: 'vex' }),
    p('cluster:prowler', 'prowler Parser', 'report', 'wasm', { category: 'compliance' }),
    p('cluster:sarif', 'sarif Parser', 'report', 'wasm', { category: 'sast', version: '2.1.0', last_run: { id: RUNS[1].id, status: 'completed', at: ago(1) }, last_success: ago(1) }),
    p('cluster:semgrep', 'semgrep Parser', 'report', 'wasm', { category: 'sast', last_run: { id: RUNS[2].id, status: 'failed', error: 'parse_error', at: ago(5) }, last_success: ago(70) }),
    p('cluster:snyk', 'snyk Parser', 'report', 'wasm', { category: 'sca' }),
    p('cluster:trivy', 'trivy Parser', 'report', 'wasm', { category: 'sca' }),
    p('cluster:trufflehog', 'trufflehog Parser', 'report', 'wasm', { category: 'secrets' }),
    p('cluster:zap', 'zap Parser', 'report', 'lua', { category: 'dast' }),
    p('cluster:broken', 'broken Parser', 'report', 'wasm', { category: 'sast', status: 'refused', error: 'spec.detect: no filename or content probe is given, so no upload could be matched to it' }),
    p('mapping:pip-audit', 'pip-audit (Declarative)', 'report', 'mapping', { support_level: 'community', origin: 'tenant', category: 'sca', description: 'Declarative mapping parser for pip-audit.' }),
    p('cluster:sbom-cyclonedx', 'cyclonedx SBOM Parser', 'sbom', 'wasm', { version: '1.6', last_run: { id: RUNS[1].id, status: 'completed', at: ago(2) }, last_success: ago(2) }),
    p('cluster:sbom-spdx', 'spdx SBOM Parser', 'sbom', 'wasm', { status: 'module_missing', unavailable: missing }),
    p('cluster:sbom-syft', 'syft SBOM Parser', 'sbom', 'wasm', { status: 'module_missing', unavailable: missing }),
  ];
})();

const CONNECTORS = [
  {
    name: 'jira-cloud-corp',
    type: 'jira',
    direction: 'bidirectional',
    enabled: true,
    status: {
      conditions: [{ type: 'Connected', status: 'True', message: 'Connected to acme.atlassian.net (Jira Cloud)' }],
      last_check_time: new Date().toISOString(),
    },
  },
  {
    name: 'github-issues-prod',
    type: 'github',
    direction: 'bidirectional',
    enabled: true,
    status: {
      conditions: [{ type: 'Connected', status: 'True', message: 'App token authenticated with issues:write permission' }],
      last_check_time: new Date().toISOString(),
    },
  },
  {
    name: 'dtrack-prod-sync',
    type: 'dependency-track',
    direction: 'inbound',
    enabled: true,
    status: {
      conditions: [{ type: 'Connected', status: 'True', message: 'Dependency-Track v4.14 API key valid, 12 projects synced' }],
      last_check_time: new Date().toISOString(),
    },
  },
  {
    name: 'slack-security-secops',
    type: 'slack',
    direction: 'outbound',
    enabled: true,
    status: {
      conditions: [{ type: 'Connected', status: 'True', message: 'Bot joined #secops-alerts channel' }],
      last_check_time: new Date().toISOString(),
    },
  },
  {
    name: 'teams-incident-response',
    type: 'teams',
    direction: 'outbound',
    enabled: true,
    status: {
      conditions: [{ type: 'Connected', status: 'True', message: 'Incoming webhook endpoint reachable' }],
      last_check_time: new Date().toISOString(),
    },
  },
  {
    name: 'webhook-siem-forwarder',
    type: 'generic-webhook',
    direction: 'outbound',
    enabled: true,
    status: {
      conditions: [{ type: 'Connected', status: 'True', message: 'HMAC signature verification active (200 OK)' }],
      last_check_time: new Date().toISOString(),
    },
  },
  {
    name: 'email-critical-digest',
    type: 'email',
    direction: 'outbound',
    enabled: true,
    status: {
      conditions: [{ type: 'Connected', status: 'True', message: 'SMTP TLS handshake confirmed on port 587' }],
      last_check_time: new Date().toISOString(),
    },
  },
];

const DTRACK_PROJECTS = [
  { project_uuid: 'dtrack-prj-01', name: 'payment-service', version: '2.14.0', last_bom_import: new Date(Date.now() - 3600000).toISOString() },
  { project_uuid: 'dtrack-prj-02', name: 'auth-gateway', version: '1.8.2', last_bom_import: new Date(Date.now() - 14400000).toISOString() },
  { project_uuid: 'dtrack-prj-03', name: 'notification-worker', version: '3.0.1', last_bom_import: new Date(Date.now() - 86400000).toISOString() },
];

const HELD_CLOSES = [
  {
    id: 'hc-001',
    ingest_run_id: RUNS[0].id,
    scope: { tenant_id: 't-1', scan_source_id: 'src-1', scanner_family: 'trivy', asset_id: 'github.com/acme/checkout', track: 'main' },
    finding_ids: ['f0000000-0000-4000-8000-000000000001', 'f0000000-0000-4000-8000-000000000002'],
    created_at: new Date(Date.now() - 7200000).toISOString(),
  },
  {
    id: 'hc-002',
    ingest_run_id: RUNS[3].id,
    scope: { tenant_id: 't-1', scan_source_id: 'src-2', scanner_family: 'semgrep', asset_id: 'github.com/acme/billing', track: 'main' },
    finding_ids: ['f0000000-0000-4000-8000-000000000003'],
    created_at: new Date(Date.now() - 43200000).toISOString(),
  },
];

const GROUPS = [
  {
    id: 'grp-001',
    tenant_id: 't-1',
    name: 'Remediation Sprint 42 (PCI DSS 6.2)',
    description: 'Track critical and high SQLi and auth vulnerabilities required for Q4 audit',
    owner: 'sara.ahmed@acme.example',
    member_count: 5,
    created_at: new Date(Date.now() - 5 * 86400000).toISOString(),
    updated_at: new Date(Date.now() - 86400000).toISOString(),
  },
  {
    id: 'grp-002',
    tenant_id: 't-1',
    name: 'Payment Gateway Hardening',
    description: 'Resolve all open secrets and SSRF flaws in checkout and billing services',
    owner: 'omar@acme.example',
    member_count: 3,
    created_at: new Date(Date.now() - 12 * 86400000).toISOString(),
    updated_at: new Date(Date.now() - 2 * 86400000).toISOString(),
  },
];

const VIEWS = [
  { id: 'v-01', tenant_id: 't-1', owner: 'sara.ahmed@acme.example', name: 'Critical Internet Facing', query: 'severity:critical internet_facing:true state:open', is_shared: true },
  { id: 'v-02', tenant_id: 't-1', owner: 'omar@acme.example', name: 'Open Secrets in Git', query: 'category:secrets state:open', is_shared: true },
];

const INVENTORY = [
  { id: 'inv-1', name: 'github.com/acme/checkout', type: 'repository', criticality: 'critical', environment: 'production', internet_facing: true, owner: 'sara.ahmed@acme.example', last_seen: new Date().toISOString() },
  { id: 'inv-2', name: 'github.com/acme/billing', type: 'repository', criticality: 'high', environment: 'production', internet_facing: false, owner: 'omar@acme.example', last_seen: new Date().toISOString() },
  { id: 'inv-3', name: 'registry.acme.example/checkout:v2.14', type: 'container_image', criticality: 'critical', environment: 'production', internet_facing: true, owner: 'sara.ahmed@acme.example', last_seen: new Date().toISOString() },
];
const PROOFS = {
  'ra-31': [
    { id: 'p1', name: 'CISO approval - payments admin.pdf', content_type: 'application/pdf', size_bytes: 184320, uploaded_by: 'user:sara.ahmed@acme.example', uploaded_at: new Date(Date.now() - 5 * 86400000).toISOString() },
    { id: 'p2', name: 'RE- VPN-only access confirmed.eml', content_type: 'text/plain; charset=utf-8', size_bytes: 6120, uploaded_by: 'user:boss@acme.example', uploaded_at: new Date(Date.now() - 4 * 86400000).toISOString() },
  ],
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
        if (field === 'cve') return r.finding.vulnerability_id && vals.some((v) => r.finding.vulnerability_id.toLowerCase().includes(v.toLowerCase()));
        if (field === 'purl') return r.finding.location?.purl && vals.some((v) => r.finding.location.purl.toLowerCase().includes(v.toLowerCase()));
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
      { id: 'pci-dss-4.0.1-req6', name: 'PCI DSS, requirement 6 and 8.6.2', version: '4.0.1', source: 'https://www.pcisecuritystandards.org/document_library/', kind: 'category', note: 'PCI DSS does not list weaknesses by CWE, so each requirement is assessed by the kind of scan that evidences it.', controls: 6, origin: 'builtin' },
      { id: 'acme-secure-coding', name: 'ACME secure coding policy', version: '2026.1', source: 'https://wiki.acme.example/secpol', kind: 'custom', controls: 5, origin: 'tenant', scope: 'pci', window_days: 30 },
      { id: 'acme-draft', name: 'acme-draft', version: '', kind: 'custom', controls: 0, origin: 'tenant', error: 'compliance framework: control "SC-9": unknown category "sasst" (one of sast, sca, secret, iac, container, dast, cspm, compliance, license, supply_chain)' },
    ] });
    if (p.startsWith('/api/v1/taxonomies/') && p.endsWith('/history')) {
      const d = (n) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);
      return json(res, { days: [d(1), d(2), d(3), d(30), d(90)] });
    }
    if (p.startsWith('/api/v1/taxonomies/') && p.endsWith('/attestations') && req.method === 'POST') {
      res.writeHead(201, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ id: 'at-1', status: 'passed', note: 'ok', attested_by: 'user:sara.ahmed@acme.example', attested_at: new Date().toISOString(), expires_at: new Date(Date.now() + 365 * 86400000).toISOString() }));
    }
    if (p === '/api/v1/taxonomies/acme-secure-coding/status') {
      const z = { critical: 0, high: 0, medium: 0, low: 0 };
      const ago = (n) => new Date(Date.now() - n * 86400000).toISOString();
      return json(res, { id: 'acme-secure-coding', name: 'ACME secure coding policy', version: '2026.1', source: 'https://wiki.acme.example/secpol', kind: 'custom', origin: 'tenant', scope: 'pci',
        controls: 5, evaluated_at: new Date().toISOString(), window_days: 30, status: [
        { id: 'SC-1', name: 'No critical or high injection flaws', status: 'open', open: 3, bands: { ...z, critical: 1, high: 2 }, accepted: 1, query: 'cwe:77,78,79,89 state:open,under_investigation,affected', query_exact: false, evidence: ['semgrep'], assessed_apps: 3, total_apps: 3,
          reason: '3 open findings break it. 1 finding is risk-accepted: approved exceptions, not counted as open.' },
        { id: 'SC-2', name: 'No hard-coded credentials', status: 'clear', open: 0, bands: z, query: 'category:secret state:open,under_investigation,affected', query_exact: true, evidence: ['gitleaks', 'semgrep'], assessed_apps: 3, total_apps: 3,
          reason: 'Nothing that bears on it is open, and a secret scan ran in all 3 applications in the last 30 days.' },
        { id: 'SC-3', name: 'Dependencies with a known exploited vulnerability are patched', status: 'not_assessed', open: 0, bands: z, query: 'category:sca state:open,under_investigation,affected', query_exact: true, evidence: ['trivy'], assessed_apps: 2, total_apps: 3,
          reason: 'Assessed in 2 of 3 applications. The other one had no dependency (SCA) scan in the last 30 days.' },
        { id: 'SC-4', name: 'A threat model is reviewed for each release', description: 'Attested by the application security lead.', status: 'clear', open: 0, bands: z, manual: true,
          attestation: { id: 'at-0', framework_id: 'acme-secure-coding', control_id: 'SC-4', status: 'passed', note: 'Threat model of release 4.2 reviewed', evidence_url: 'https://wiki.acme.example/tm/4.2', attested_by: 'user:omar@acme.example', attested_at: ago(20), expires_at: ago(-345) },
          reason: 'omar@acme.example attested on ' + new Date(Date.now() - 20 * 86400000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) + ' that it is met; in force until next year.' },
        { id: 'SC-5', name: 'Penetration test of internet-facing services each year', status: 'not_assessed', open: 0, bands: z, manual: true,
          reason: 'A person attests this control, and nobody has yet.' },
      ] });
    }
    if (p.startsWith('/api/v1/taxonomies/') && p.endsWith('/status')) {
      const b = (c, h, m, l) => ({ critical: c, high: h, medium: m, low: l });
      const reasonOf = (status, open) => status === 'open' ? `${open} open findings break it.` : status === 'clear' ? 'Nothing that bears on it is open, and a SAST or DAST scan ran in all 3 applications in the last 30 days.' : 'No SAST or DAST scan ran in the last 30 days, so nothing can be said.';
      const ctl = (id, name, status, bands, evidence) => { const open = Object.values(bands).reduce((a, n) => a + n, 0); return { id, name, status, open, bands, query: 'cwe:89 state:open', query_exact: true, evidence, reason: reasonOf(status, open) }; };
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
    // D93: one application over time. Deterministic, so screenshots and tests are stable: a critical spike that is
    // worked down, highs that creep up, a steady medium/low backlog, and new against fixed per day.
    const at = /^\/api\/v1\/applications\/([^/]+)\/trend$/.exec(p);
    if (at) {
      const n = Math.min(180, Math.max(7, Number(url.searchParams.get('days')) || 90));
      const points = Array.from({ length: n }, (_, i) => {
        const t = i / (n - 1);
        const d = new Date(Date.now() - (n - 1 - i) * 86_400_000).toISOString().slice(0, 10);
        const wave = Math.sin(i / 4);
        return {
          day: d,
          critical: Math.max(0, Math.round(1 + 7 * Math.exp(-((t - 0.35) ** 2) / 0.02) + (t > 0.8 ? 1 : 0))),
          high: Math.round(6 + 7 * t + 1.5 * wave),
          medium: Math.round(22 - 6 * t + 2 * Math.sin(i / 7)),
          low: Math.round(14 + 2 * Math.sin(i / 9)),
          new: Math.max(0, Math.round(2 + 2 * Math.sin(i / 3) + (i % 11 === 0 ? 5 : 0))),
          fixed: Math.max(0, Math.round(2 + 1.8 * Math.cos(i / 4) + (i % 13 === 0 ? 4 : 0))),
        };
      });
      return json(res, { days: n, points, aging: { under_30: 18, d30_90: 14, d90_180: 9, over_180: 4 } });
    }
    const am = /^\/api\/v1\/applications\/([^/]+)\/summary$/.exec(p);
    if (am) {
      const a = APP_ROWS.find((x) => x.id === am[1]);
      if (!a) return problem(res, 404, 'Application not found', 'No such application.');
      return json(res, {
        ...a, sla: { within: 14, late: 3, breached: a.sla_breached, adherence: 14 / (17 + a.sla_breached) },
        mttr: [{ band: 'critical', days: 3.2, fixed: 3 }, { band: 'high', days: 11.8, fixed: 9 }, { band: 'medium', days: 27.5, fixed: 14 }, { band: 'low', days: 41.0, fixed: 6 }],
        coverage: [
          { asset_id: 'as-1', asset: `github.com/acme/${a.slug}`, scanner: 'semgrep', last_scan: day(0.2) },
          { asset_id: 'as-1', asset: `github.com/acme/${a.slug}`, scanner: 'gitleaks', last_scan: day(0.2) },
          { asset_id: 'as-2', asset: `registry.acme.example/${a.slug}`, scanner: 'trivy', last_scan: day(6) },
        ],
        top_findings: ALL.slice(0, 5).map((r) => ({ id: r.finding.id, title: r.finding.title, band: r.risk.band, risk_score: r.risk.total_score, state: r.finding.state, sla_due_date: r.sla_due_date })),
        // D101: one row per kind of testing; DAST and cloud never ran, IaC is stale.
        scan_coverage: [
          { category: 'sast', scanners: ['semgrep'], last_scan: day(0.2), open: { critical: 1, high: 3, medium: 2 } },
          { category: 'sca', scanners: ['trivy'], last_scan: day(6), open: { critical: 2, high: 2, medium: 1, low: 1 } },
          { category: 'secret', scanners: ['gitleaks', 'semgrep', 'trivy'], last_scan: day(0.2), open: { high: 1 } },
          { category: 'iac', scanners: ['checkov'], last_scan: day(45), open: { medium: 1, low: 1 } },
          { category: 'container', scanners: ['trivy'], last_scan: day(6), open: {} },
          { category: 'dast', scanners: [], open: {} },
          { category: 'cspm', scanners: [], open: {} },
        ],
      });
    }
    if (p === '/api/v1/dashboards/overview') return json(res, OVERVIEW());
    if (p === '/api/v1/metrics/trend') return json(res, { metric: 'open', points: TREND });
    if (p === '/api/v1/uploads/direct' && req.method === 'POST') {
      return json(res, { ingestRunId: '00000001-aaaa-bbbb-cccc-000000000001', status: 'completed' }, 201);
    }
    if ((p === '/api/v1/openapi.json' || p === '/openapi.json') && req.method === 'GET') {
      return json(res, { openapi: '3.0.3', info: { title: 'Rampart API', version: '1.0.0' } });
    }
    if (p === '/api/v1/runs') {
      if (scenario === 'error') return problem(res, 500, 'Failed to list runs', 'The database did not answer within 5 s.');
      return json(res, { items: dataMode === 'empty' ? null : RUNS, next_cursor: '' });
    }
    if (p.startsWith('/api/v1/runs/')) {
      const r = RUNS.find((x) => x.id === p.split('/').pop());
      return r ? json(res, r) : problem(res, 404, 'Run not found', 'No such run.');
    }
    if (p === '/api/v1/risk-acceptances' && req.method === 'GET') return json(res, { items: ACCEPTANCES });
    const ram = /^\/api\/v1\/risk-acceptances\/([^/]+)(\/proofs)?$/.exec(p);
    if (ram) {
      const ra = ACCEPTANCES.find((x) => x.id === ram[1]);
      if (!ra) return problem(res, 404, 'Risk acceptance not found');
      if (!ram[2]) return json(res, ra);
      if (req.method === 'POST') {
        // The real server checks the file's bytes; the mock only reads the name it was given.
        let size = 0;
        req.on('data', (c) => (size += c.length));
        req.on('end', () => {
          const p2 = { id: 'p' + Math.random().toString(36).slice(2), name: 'attached.pdf', content_type: 'application/pdf', size_bytes: size, uploaded_by: 'user:sara.ahmed@acme.example', uploaded_at: new Date().toISOString() };
          (PROOFS[ra.id] ??= []).push(p2);
          json(res, p2, 201);
        });
        return;
      }
      return json(res, { items: PROOFS[ra.id] ?? [] });
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
        let occurrences = [];
        if (row.finding.location?.purl) {
          const purl = row.finding.location.purl;
          const match = purl.match(/^pkg:([^/]+)\/([^@]+)@(.+)$/);
          const pkgName = match ? match[2] : purl;
          const pkgVer = match ? match[3] : '1.0.0';
          occurrences = [
            {
              location: {
                package: {
                  component_name: pkgName,
                  installed_version: pkgVer,
                  fixed_version: '2.1.0',
                  purl,
                },
              },
            },
          ];
        }
        return json(res, { ...row, reported_by, also_reported_by, occurrences });
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
    // Analyzers (internal/query/analyzers.go): a service, the built-in matcher, one refused resource; Test and Analyze add events.
    if (p.startsWith('/api/v1/analyzers')) {
      const ago = (m) => new Date(Date.now() - m * 60_000).toISOString();
      const key = (a) => [a.kind, a.scope, a.namespace ?? '', a.name].join('/');
      globalThis.__analyzers ??= {
        items: [
          { kind: 'external', scope: 'cluster', name: 'sonatype-oss-index', enabled: true, ready: true, protocol: 'grpc', target: 'sonatype-analyzer.rampart-system.svc.cluster.local:9090', timeout_seconds: 60, secure: false, updated_at: ago(3000) },
          { kind: 'sbom', scope: 'cluster', name: 'native-matcher', enabled: true, ready: true, engine: 'hybrid', min_confidence: 0.8, match_direct_only: false, sources: { osv: true, ghsa: true, nvd: false }, schedule: '0 3 * * *', updated_at: ago(3000) },
          { kind: 'external', scope: 'tenant', namespace: 'acme', name: 'internal-scanner', enabled: true, ready: false, error: 'spec.protocol: "http" is not supported: the server has no HTTP client', updated_at: ago(90) },
        ],
        events: {},
      };
      const st = globalThis.__analyzers;
      const withLast = (a) => ({ ...a, last_event: st.events[key(a)]?.[0] });
      const ev = (a, event, outcome, message, actor, ms) => {
        const e = { id: 'ev-' + Math.random().toString(36).slice(2, 8), event, outcome, message, duration_ms: ms, actor, created_at: new Date().toISOString() };
        (st.events[key(a)] ??= []).unshift(e);
        return e;
      };
      if (p === '/api/v1/analyzers' && req.method === 'GET') return json(res, { analyzers: st.items.map(withLast), total: st.items.length });
      if (p === '/api/v1/analyzers/events' && req.method === 'GET') {
        const a = { kind: url.searchParams.get('kind'), scope: url.searchParams.get('scope'), namespace: url.searchParams.get('namespace') ?? '', name: url.searchParams.get('name') };
        return json(res, { events: st.events[key(a)] ?? [], total: (st.events[key(a)] ?? []).length });
      }
      if ((p === '/api/v1/analyzers/test' || p === '/api/v1/analyzers/analyze') && req.method === 'POST') {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          const a = JSON.parse(body || '{}');
          const found = st.items.find((i) => key(i) === key(a));
          if (!found) return problem(res, 404, 'No such analyzer', undefined);
          if (p.endsWith('/analyze')) {
            if (!found.ready || !found.enabled) return json(res, { queued: 0 }, 202);
            ev(found, 'analysis', 'succeeded', 'Analysed 212 components: 7 findings, 2 new, 1 no longer reported', undefined, 1840);
            return json(res, { queued: 3 }, 202);
          }
          if (!found.ready) {
            const e = ev(found, 'test', 'failed', "The analyzer's spec is refused, so there is nothing to call: " + found.error, 'user:admin', 1);
            return json(res, { ok: false, outcome: 'failed', message: e.message, latency_ms: 1, event: e });
          }
          const ok = found.kind === 'sbom' || Math.random() > 0.35;
          const message = found.kind === 'sbom' ? '1,284,903 affected ranges in 6 ecosystems are loaded for the matcher'
            : ok ? 'Serving: Sonatype OSS Index 0.1.0, 9 package types'
            : 'Could not reach ' + found.target + ': nothing answers there (the Service or the pod is down, the port is wrong, or TLS does not match)';
          const detail = found.kind === 'sbom' ? { affected_ranges: '1284903', ecosystems: '6' } : { target: found.target, enabled: 'true', secure: 'false', ...(ok ? { answered_in_ms: '9', name: 'Sonatype OSS Index', version: '0.1.0', package_types: 'npm,maven,pypi,golang,cargo,nuget,gem,composer,cocoapods' } : {}) };
          const e = ev(found, 'test', ok ? 'succeeded' : 'failed', message, 'user:admin', ok ? 9 : 5003);
          return json(res, { ok, outcome: e.outcome, message, latency_ms: e.duration_ms, detail, event: e });
        });
        return;
      }
    }
    if (p === '/api/v1/parsers') return json(res, { parsers: PARSERS });
    if (p === '/api/v1/feeds/sync') {
      const feedParam = url.searchParams.get('feed') || 'all';
      return json(res, { status: 'started', feed: feedParam, message: 'Feed synchronization initiated successfully', started_at: new Date().toISOString() }, 202);
    }
    if (p === '/api/v1/feeds/test-connection') {
      const feedParam = url.searchParams.get('feed');
      const allResults = [
        { name: 'cisa_kev', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', reachable: true, status_code: 200, latency_ms: 64, message: 'Upstream reachable (HTTP 200 OK)' },
        { name: 'first_epss', url: 'https://epss.cyentia.com/epss_scores-current.csv.gz', reachable: true, status_code: 200, latency_ms: 110, message: 'Upstream reachable (HTTP 200 OK)' },
        { name: 'nvd', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0', reachable: true, status_code: 200, latency_ms: 180, message: 'Upstream reachable (HTTP 200 OK)' },
        { name: 'osv', url: 'https://osv-vulnerabilities.storage.googleapis.com', reachable: true, status_code: 200, latency_ms: 85, message: 'Upstream reachable (HTTP 200 OK)' },
        { name: 'vulnrichment', url: 'https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.zip', reachable: true, status_code: 302, latency_ms: 140, message: 'Upstream reachable (HTTP 302 OK)' },
        { name: 'exploitdb', url: 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv', reachable: true, status_code: 200, latency_ms: 95, message: 'Upstream reachable (HTTP 200 OK)' },
      ];
      const results = feedParam ? allResults.filter((r) => r.name === feedParam) : allResults;
      return json(res, { tested_at: new Date().toISOString(), results });
    }
    if (p === '/api/v1/feeds') return json(res, {
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
          last_sync: new Date(Date.now() - 3600000).toISOString(),
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
          last_sync: new Date(Date.now() - 3600000).toISOString(),
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
          last_sync: new Date(Date.now() - 7200000).toISOString(),
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
          last_sync: new Date(Date.now() - 7200000).toISOString(),
          error: null,
        },
      ],
    });
    if (p === '/api/v1/connectors') return json(res, { items: [...CONNECTORS, { name: 'chat-sec', type: 'plugin', direction: 'outbound', enabled: true, managed_by: 'resource',
      spec: { plugin: { name: 'google-chat' } }, status: { conditions: [{ type: 'Connected', status: 'Unknown', reason: 'NotProbed', message: 'A declarative notifier has no check request; the first delivery tests it' }] } }] });
    // D94: tools installed as data.
    if (p === '/api/v1/integration-packages') return json(res, { items: [
      { name: 'google-chat', kind: 'notifier', runtime: 'declarative', version: '1.0.0', description: 'Posts to a Google Chat space', egress: ['chat.googleapis.com'],
        secrets: ['webhookUrl'], config: [], used_by: ['chat-sec'], updated_at: new Date().toISOString() },
      { name: 'redmine', kind: 'tracker', runtime: 'declarative', version: '0.3.0', egress: [], secrets: [], config: [], used_by: [],
        error: 'kind "tracker": declarative trackers are not built yet; use a built-in tracker (Jira, GitHub)', updated_at: new Date().toISOString() },
    ] });
    // D82: the catalogue and the dry run. The real server builds the catalogue from the Go types and validates with
    // the operator's own rules; the mock answers enough for the page to be exercised.
    if (p === '/api/v1/connectors/catalogue') return json(res, { items: [
      { type: 'jira', name: 'Jira Cloud', kind: 'tracker', directions: ['outbound', 'bidirectional'], description: 'Opens Jira Cloud issues for findings.',
        config_key: 'jira', config_schema: { type: 'object' }, secrets: [{ field: 'credentialsSecretRef', holds: 'email:apiToken', purpose: 'calls the Jira API' }],
        example: 'apiVersion: rampart.aspm.dev/v1alpha1\nkind: Connector\nmetadata: {name: jira-sec, namespace: <tenant-namespace>}\nspec:\n  type: jira\n  jira:\n    url: https://example.atlassian.net\n    credentialsSecretRef: {name: jira-sec-creds, key: token}\n    defaultProject: SEC\n' },
    ] });
    if (p === '/api/v1/connectors/validate' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const resource = JSON.parse(body || '{}').resource ?? '';
        json(res, /kind:\s*Connector/.test(resource) ? { valid: true } : { valid: false, reason: 'InvalidSpec', error: 'the first document must be a Connector' });
      });
      return;
    }
    // Dependency-Track sources (D92): one source, synced 12 minutes ago, one project unmapped, one decision waiting.
    // GET /api/v1/stream (D91): open, with a heartbeat, so the UI does not fall back to polling in the mock.
    if (p === '/api/v1/stream') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
      res.write('retry: 5000\n\n');
      const beat = setInterval(() => res.write(': ping\n\n'), 15_000);
      req.on('close', () => clearInterval(beat));
      return;
    }
    if (p === '/api/v1/sources') return json(res, { sources: [{ id: 'src-dt', name: 'dtrack-portfolio', connector: 'dtrack', schedule_seconds: 1800,
      webhook_enabled: true, trust_upstream_decisions: false, last_portfolio_sync_at: new Date(Date.now() - 12 * 60_000).toISOString(),
      projects: 14, unmapped: DTRACK_PROJECTS.length, pending_decisions: 1 }] });
    if (p === '/api/v1/sources/src-dt/unmapped') return json(res, { projects: DTRACK_PROJECTS, count: DTRACK_PROJECTS.length });
    if (p === '/api/v1/sources/src-dt/decisions') return json(res, { decisions: [{ finding_id: ALL[0]?.finding.id ?? 'f-1', source_id: 'src-dt',
      state: 'not_affected', justification: 'code_not_reachable', applied: false, seen_at: new Date(Date.now() - 3 * 3600_000).toISOString() }] });
    if (p === '/api/v1/sources/src-dt/map' && req.method === 'POST') return json(res, { status: 'mapped', sync_queued: true });
    if (/^\/api\/v1\/groups\/[^/]+\/ticket$/.test(p) && req.method === 'POST') return json(res, { ticket: { status: 'reserved' } }, 202);
    if (p === '/api/v1/held-closes') return json(res, { items: HELD_CLOSES });
    if (p === '/api/v1/groups') return json(res, { groups: GROUPS });
    if (p === '/api/v1/views') return json(res, { views: VIEWS });
    if (p === '/api/v1/settings') return json(res, { riskAcceptanceApproval: true, riskAcceptanceMaxDays: 90 });
    if (p === '/api/v1/inventory') return json(res, { assets: INVENTORY });
    if (p === '/api/v1/inventory/components') {
      return json(res, {
        components: [
          {
            name: 'axios',
            version: '0.21.1',
            purl: 'pkg:npm/axios@0.21.1',
            type: 'npm',
            track: 'main',
            license: 'MIT',
            direct: true,
            asset_id: 'asset-1',
            asset_name: 'github.com/acme/payments',
            application_name: 'Payments Service',
            vulnerabilities: 1,
          },
          {
            name: 'log4j-core',
            version: '2.14.1',
            purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            type: 'maven',
            track: 'main',
            license: 'Apache-2.0',
            direct: true,
            asset_id: 'asset-2',
            asset_name: 'docker.io/acme/auth-service:latest',
            application_name: 'Auth Service',
            vulnerabilities: 2,
          },
          {
            name: 'golang.org/x/crypto',
            version: 'v0.17.0',
            purl: 'pkg:golang/golang.org/x/crypto@v0.17.0',
            type: 'golang',
            track: 'main',
            license: 'BSD-3-Clause',
            direct: false,
            asset_id: 'asset-3',
            asset_name: 'github.com/acme/backend',
            application_name: 'Core API',
            vulnerabilities: 0,
          },
        ],
        total: 3,
        truncated: false,
      });
    }
    if (p === '/api/v1/inventory/components/scan') {
      const purl = req.url.includes('purl=') ? new URL(req.url, 'http://localhost').searchParams.get('purl') : 'pkg:npm/axios@0.21.1';
      return json(res, {
        status: 'started',
        purl: purl,
        message: `On-demand vulnerability scan initiated for ${purl}`,
        scanned_at: new Date().toISOString(),
      }, 202);
    }
    const appFreshMatch = /^\/api\/v1\/applications\/([^/]+)\/freshness$/.exec(p);
    if (appFreshMatch) {
      return json(res, {
        sbom: {
          at: new Date(Date.now() - 2.5 * 86_400_000).toISOString(),
          components: 48,
        },
        rescored_at: new Date(Date.now() - 3_600_000 * 3).toISOString(),
        analyzers: [
          {
            name: 'osv',
            kind: 'sbom',
            scope: 'ecosystems: npm, pypi, go',
            state: 'completed',
            last_analysed_at: new Date(Date.now() - 3_600_000 * 4).toISOString(),
            findings: 5,
            created: 2,
            closed: 1,
          },
          {
            name: 'sonatype-oss-index',
            kind: 'external',
            scope: 'ecosystems: maven, npm',
            state: 'completed',
            last_analysed_at: new Date(Date.now() - 3_600_000 * 5).toISOString(),
            findings: 3,
            created: 1,
            closed: 0,
          },
        ],
        feeds: [
          {
            name: 'nvd',
            display_name: 'National Vulnerability Database (NVD)',
            status: 'success',
            last_sync: new Date(Date.now() - 3_600_000 * 2).toISOString(),
          },
          {
            name: 'epss',
            display_name: 'Exploit Prediction Scoring System (EPSS)',
            status: 'success',
            last_sync: new Date(Date.now() - 3_600_000 * 6).toISOString(),
          },
          {
            name: 'cisa-kev',
            display_name: 'CISA Known Exploited Vulnerabilities (KEV)',
            status: 'success',
            last_sync: new Date(Date.now() - 3_600_000 * 12).toISOString(),
          },
        ],
      });
    }
    const appRefreshMatch = /^\/api\/v1\/applications\/([^/]+)\/refresh-vulnerabilities$/.exec(p);
    if (appRefreshMatch && req.method === 'POST') {
      return json(res, {
        analyzed: 1,
        started_at: new Date(Date.now() - 1000).toISOString(),
        completed_at: new Date().toISOString(),
      });
    }
    const appCompMatch = /^\/api\/v1\/applications\/([^/]+)\/components$/.exec(p);
    if (appCompMatch) {
      return json(res, {
        components: [
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
          {
            name: 'axios',
            version: '0.21.1',
            purl: 'pkg:npm/axios@0.21.1',
            type: 'npm',
            track: 'main',
            license: 'MIT',
            direct: true,
            asset_id: 'asset-1',
            asset_name: 'default-repository',
            application_name: 'Rampart Demo App',
            vulnerabilities: 1,
          },
          {
            name: 'lodash',
            version: '4.17.21',
            purl: 'pkg:npm/lodash@4.17.21',
            type: 'npm',
            track: 'main',
            license: 'MIT',
            direct: true,
            asset_id: 'asset-3',
            asset_name: 'default-repository',
            application_name: 'Rampart Demo App',
            vulnerabilities: 0,
          },
          {
            name: 'readline',
            version: '8.1',
            purl: 'pkg:deb/debian/readline@8.1',
            type: 'deb',
            track: 'main',
            license: 'GPL-3.0-or-later',
            direct: false,
            asset_id: 'asset-1',
            asset_name: 'default-repository',
            application_name: 'Rampart Demo App',
            vulnerabilities: 0,
          },
          {
            name: 'curl',
            version: '7.88.1',
            purl: 'pkg:deb/debian/curl@7.88.1',
            type: 'deb',
            track: 'main',
            license: 'curl',
            direct: true,
            asset_id: 'asset-1',
            asset_name: 'default-repository',
            application_name: 'Rampart Demo App',
            vulnerabilities: 0,
          },
        ],
        total: 5,
      });
    }
    const vm = /^\/api\/v1\/vulnerabilities\/([^/]+)(\/(impact|refresh))?$/.exec(p);
    if (vm) {
      const vid = decodeURIComponent(vm[1]);
      const action = vm[3];
      if (action === 'refresh') {
        if (vid.includes('FAIL') || url.searchParams.get('fail') === 'true') {
          return problem(res, 502, 'Upstream sync failed', 'National Vulnerability Database (NIST NVD) returned HTTP 429 Too Many Requests (rate limit exceeded). Background sweeper will retry with backoff.');
        }
        return json(res, {
          id: vid,
          refreshed: true,
          scoring_status: vid.includes('UNSCORED') ? 'awaiting_analysis' : 'scored',
          updated_at: new Date().toISOString(),
        });
      }
      if (action === 'impact') {
        return json(res, {
          id: vid,
          findings: 1,
          open: 1,
          applications: [
            {
              id: 'app-payments',
              slug: 'payments-service',
              name: 'Payments Service',
              findings: 1,
              open: 1,
              max_severity: 'high',
              max_risk_score: 850,
              asset_ids: ['asset-1'],
            },
          ],
        });
      }
      return json(res, {
        id: vid,
        known: true,
        record: {
          id: vid,
          summary: `Advisory Report for ${vid}`,
          description: `### Impact\n\nA vulnerability in Multer versions < 2.1.0 allows an attacker to trigger a Denial of Service (DoS) by dropping connection during file upload, potentially causing resource exhaustion.\n\n### Patches\n\nUsers should upgrade to \`2.1.0\` immediately.\n\n### Workarounds\n\nNone identified. Apply rate limiting at the reverse proxy layer.\n\n### References\n\n- https://github.com/expressjs/multer/security/advisories/GHSA-v52c-386h-88mc\n- https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vid)}`,
          epss_score: 0.952,
          cvss_score: vid.includes('UNSCORED') || vid.includes('FAIL') ? undefined : 7.5,
          cvss_vector: vid.includes('UNSCORED') || vid.includes('FAIL') ? undefined : 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
          scoring_status: vid.includes('UNSCORED') || vid.includes('FAIL') ? 'awaiting_analysis' : 'scored',
          nvd_status: vid.includes('UNSCORED') || vid.includes('FAIL') ? 'Awaiting Analysis' : 'Analyzed',
          sync_status: vid.includes('FAIL') ? 'failed' : 'success',
          sync_error: vid.includes('FAIL') ? 'National Vulnerability Database (NIST NVD) returned HTTP 429 Too Many Requests (rate limit exceeded)' : undefined,
          cwes: [401, 772],
          aliases: ['GHSA-v52c-386h-88mc'],
          published: '2026-02-27T00:00:00Z',
          modified: '2026-07-15T00:00:00Z',
          updated_at: new Date(Date.now() - 15 * 60000).toISOString(),
          links: [
            `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vid)}`,
            'https://github.com/expressjs/multer/security/advisories/GHSA-v52c-386h-88mc',
            'https://osv.dev/vulnerability/GHSA-v52c-386h-88mc',
          ],
        },
        links: [`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vid)}`],
      });
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
