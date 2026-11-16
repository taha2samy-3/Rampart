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
const ACCEPTANCES = [
  { id: 'ra-31', status: 'approved', justification: 'The payments admin API is only reachable over the VPN', owner: 'user:sara.ahmed@acme.example', requester: 'user:sara.ahmed@acme.example', approver: 'user:boss@acme.example', expires_at: new Date(Date.now() + 40 * 86400000).toISOString(), on_expiry: 'reactivate', created_at: new Date(Date.now() - 5 * 86400000).toISOString(), finding_ids: ['f0000000-0000-4000-8000-000000000001', 'f0000000-0000-4000-8000-000000000002'] },
  { id: 'ra-32', status: 'pending', justification: 'Legacy crypto algorithm in staging environment undergoing migration in Q1', owner: 'user:omar@acme.example', requester: 'user:omar@acme.example', expires_at: new Date(Date.now() + 60 * 86400000).toISOString(), on_expiry: 'close', created_at: new Date(Date.now() - 2 * 86400000).toISOString(), finding_ids: ['f0000000-0000-4000-8000-000000000003'] },
  { id: 'ra-33', status: 'expired', justification: 'Temporary waiver for CVE-2023-44487 during maintenance window', owner: 'user:sara.ahmed@acme.example', requester: 'user:sara.ahmed@acme.example', approver: 'user:boss@acme.example', expires_at: new Date(Date.now() - 10 * 86400000).toISOString(), on_expiry: 'reactivate', created_at: new Date(Date.now() - 70 * 86400000).toISOString(), finding_ids: ['f0000000-0000-4000-8000-000000000004'] },
];

const PARSERS = [
  { id: 'builtin:sarif', name: 'SARIF 2.1.0 Parser', kind: 'parser', version: '2.1.0', support_level: 'builtin', description: 'OASIS SARIF 2.1.0 standard with enrichers for Semgrep, Trivy, Gitleaks, CodeQL' },
  { id: 'builtin:cyclonedx', name: 'CycloneDX Parser (JSON/XML)', kind: 'parser', version: '1.6.0', support_level: 'builtin', description: 'CycloneDX 1.4-1.7 SBOM, VDR, and VEX parser for JSON and XML formats' },
  { id: 'builtin:spdx', name: 'SPDX Parser (JSON/Tag-Value)', kind: 'parser', version: '2.3.0', support_level: 'builtin', description: 'SPDX 2.2 and 2.3 SBOM parser for JSON and Tag-Value formats' },
  { id: 'builtin:openvex', name: 'OpenVEX Parser', kind: 'parser', version: '0.2.0', support_level: 'builtin', description: 'OpenVEX triage statements and exploitability assertions parser' },
  { id: 'builtin:syft', name: 'Syft Parser (JSON)', kind: 'parser', version: '1.0.0', support_level: 'builtin', description: 'Anchore Syft SBOM parser with artifact catalog and dependency relationships' },
  { id: 'builtin:trivy', name: 'Trivy Parser (JSON)', kind: 'parser', version: '2.0.0', support_level: 'builtin', description: 'Trivy JSON (schema 2): package vulnerabilities, secrets, misconfigurations, licenses' },
  { id: 'builtin:grype', name: 'Grype Parser (JSON)', kind: 'parser', version: '1.0.0', support_level: 'builtin', description: 'Grype JSON: vulnerability matches with their related identifiers' },
  { id: 'builtin:semgrep', name: 'Semgrep Parser (JSON)', kind: 'parser', version: '1.0.0', support_level: 'builtin', description: 'Semgrep JSON: code findings with CWE, location and code snippet hash' },
  { id: 'builtin:trufflehog', name: 'TruffleHog Parser (JSON lines)', kind: 'parser', version: '3.0.0', support_level: 'builtin', description: 'TruffleHog JSON lines: secrets, verified against live endpoints' },
  { id: 'builtin:gitleaks', name: 'Gitleaks Parser (JSON)', kind: 'parser', version: '1.0.0', support_level: 'builtin', description: 'Gitleaks JSON: secrets found in git repositories; secret is hashed' },
  { id: 'builtin:dependencytrack', name: 'Dependency-Track Parser (FPF/JSON)', kind: 'parser', version: '1.4.0', support_level: 'builtin', description: 'Dependency-Track FPF export and direct API finding response parser with VEX' },
  { id: 'builtin:checkov', name: 'Checkov Parser (JSON)', kind: 'parser', version: '3.0.0', support_level: 'builtin', description: 'Checkov IaC scanning report for Terraform, CloudFormation, K8s, Dockerfile' },
  { id: 'builtin:bandit', name: 'Bandit Parser (JSON)', kind: 'parser', version: '1.7.0', support_level: 'builtin', description: 'Bandit Python SAST vulnerability and security flaw report' },
  { id: 'builtin:nuclei', name: 'Nuclei Parser (JSONL)', kind: 'parser', version: '3.0.0', support_level: 'builtin', description: 'Nuclei template-based vulnerability scan results' },
  { id: 'builtin:zap', name: 'OWASP ZAP Parser (JSON)', kind: 'parser', version: '2.14.0', support_level: 'builtin', description: 'OWASP ZAP DAST web application security report' },
  { id: 'builtin:dependencycheck', name: 'OWASP Dependency-Check Parser (JSON)', kind: 'parser', version: '8.4.0', support_level: 'builtin', description: 'OWASP Dependency-Check SCA vulnerability report' },
  { id: 'builtin:snyk', name: 'Snyk Parser (JSON)', kind: 'parser', version: '1.0.0', support_level: 'builtin', description: 'Snyk open source and container vulnerability report' },
  { id: 'builtin:kubebench', name: 'kube-bench Parser (JSON)', kind: 'parser', version: '0.6.0', support_level: 'builtin', description: 'Aqua Security kube-bench CIS Kubernetes benchmark report' },
  { id: 'builtin:prowler', name: 'Prowler Parser (JSON)', kind: 'parser', version: '4.0.0', support_level: 'builtin', description: 'Prowler AWS/Azure/GCP cloud security and compliance report' },
  { id: 'builtin:gitlab', name: 'GitLab Security Report Parser (JSON)', kind: 'parser', version: '15', support_level: 'builtin', description: 'GitLab SAST, secret detection, dependency scanning, container scanning and DAST reports (schema v14, v15)' },
  { id: 'builtin:genericjson', name: 'Generic JSON Parser', kind: 'parser', version: '1', support_level: 'builtin', description: 'Rampart generic findings format, a superset of DefectDojo Generic Findings Import' },
  { id: 'crd:custom-sast-mapper', name: 'Custom In-House SAST', kind: 'parser', version: '1.0.0', support_level: 'community', description: 'Declarative CEL mapping parser registered dynamically via IntegrationPackage CRD' },
];

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
    if (p === '/api/v1/parsers') return json(res, { parsers: PARSERS });
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
