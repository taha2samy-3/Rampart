/**
 * Hand-written from the Go structs (internal/query/api.go, internal/domain,
 * internal/risk). Replace with openapi-typescript output once
 * /api/v1/openapi.json exists; the endpoint functions in endpoints.ts are the
 * only callers, so the swap stays inside api/.
 */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail?: string;
  request_id?: string;
  /** field-level errors, when the backend sends them */
  errors?: { field: string; message: string }[];
}

export interface LoginMethod {
  id: string;
  name: string;
  type: string;
}
export interface UiConfig {
  product: string;
  version: string;
  features: string[];
  login: { methods: LoginMethod[] };
  locale: { default: string };
  supportUrl: string;
}

export interface SessionUser {
  id: string;
  email: string;
  name: string;
}
export interface TenantRef {
  id: string;
  slug: string;
  name: string;
}
export interface Session {
  user: SessionUser;
  tenant: TenantRef;
  csrfToken: string;
  expiresAt: string;
}
export type Role = 'viewer' | 'triager' | 'maintainer' | 'owner' | 'admin';
export interface Permissions {
  role: Role;
  scopes: string[];
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
export type FindingState =
  | 'open'
  | 'under_investigation'
  | 'affected'
  | 'not_affected'
  | 'fixed'
  | 'risk_accepted'
  | 'out_of_scope'
  | 'duplicate';

/**
 * Where a finding is, flat, as the screens read it (lib/location.ts makes it from the answer of the server, which nests it
 * by kind). Which fields are set depends on what the scanner knows: a code scanner gives a file and lines, a dependency
 * scanner a package, a web scanner an address, an infrastructure scanner a resource, a container scanner an image.
 */
export interface FindingLocation {
  file_path?: string;
  start_line?: number;
  end_line?: number;
  start_column?: number;
  end_column?: number;
  logical_location?: string;
  snippet?: string;
  purl?: string;
  component_name?: string;
  installed_version?: string;
  fixed_version?: string;
  manifest_path?: string;
  dependency_path?: string[];
  url?: string;
  method?: string;
  param?: string;
  resource_address?: string;
  resource_key?: string;
  resource_type?: string;
  image?: string;
}
export interface Finding {
  id: string;
  asset_id?: string;
  application_id?: string;
  category?: string;
  rule_scanner_family?: string;
  rule_id?: string;
  title: string;
  description?: string;
  vulnerability_id?: string | null;
  cwes?: number[];
  cvss_vector?: string;
  /** As the server sends it (nested by kind) or flat; read it with locationOf. */
  location?: unknown;
  tool_severity?: string;
  secret_verified?: boolean;
  severity: Severity;
  risk_score: number;
  state: FindingState;
  detection?: 'present' | 'absent';
  first_seen: string;
  last_seen?: string;
  occurrence_count?: number;
  /** For If-Match: a decision applies only to the version the analyst saw (docs/16 D38). */
  version?: number;
  state_reason?: string;
  justification?: string;
  impact_statement?: string;
  duplicate_of_id?: string;
  tags?: string[];
  risk_acceptance_id?: string;
  /** The member who works on it (D59). */
  owner?: string;
  severity_override_reason?: string;
}
export interface RiskFactor {
  name: string;
  points: number;
  reason: string;
}
export interface ScoreBreakdown {
  base_severity: Severity;
  base_points: number;
  factors: RiskFactor[] | null;
  total_score: number;
  band: Severity;
  has_kev?: boolean;
  epss_score?: number;
}
export interface FindingRow {
  finding: Finding;
  risk: ScoreBreakdown;
  sla_due_date?: string | null;
}

export interface FindingDetail extends FindingRow {
  reported_by?: Reporter[];
  also_reported_by?: CorrelatedRef[];
  occurrences?: Occurrence[];
}

export interface Occurrence {
  id: string;
  tenant_id: string;
  finding_id: string;
  ingest_run_id: string;
  scan_source_id: string;
  asset_id: string;
  track: string;
  occurrence_key: string;
  scanner_family: string;
  scanner_name: string;
  scanner_version?: string;
  tool_record_id?: string;
  location?: unknown;
  tool_severity?: string;
  normalized?: Record<string, unknown> | null;
  raw?: Record<string, unknown> | string | null;
  present: boolean;
  seen_count: number;
  first_seen: string;
  last_seen: string;
}

/** Normalised list page (doc 11 shape; the backend spelling is accepted too). */
export interface Page<T> {
  items: T[];
  nextCursor: string;
  total?: number;
}

export type RunStatus =
  | 'queued' | 'parsing' | 'merging' | 'enriching' | 'scoring'
  | 'completed' | 'completed_with_errors' | 'failed' | 'stale';

/** One ingest run (internal/query/runs.go RunView, internal/domain IngestRun). */
export interface RunRow {
  id: string;
  status: RunStatus;
  created_at: string;
  finished_at?: string;
  scanner_family: string;
  format: string;
  track: string;
  /** A stable code when the run failed, for example sha256_mismatch. */
  error?: string;
  /** The raw report can be downloaded by a maintainer. */
  has_report?: boolean;
  /** When retention removed the raw report (docs/16 D53). */
  report_purged_at?: string;
  /** The report named at least one secret, so its raw report is kept for a shorter time. */
  holds_secrets?: boolean;
  /** The first records the run could not read, and where they are (the single-run GET only). */
  record_error_list?: { where: string; message: string }[];
  stats: {
    parsed: number; created: number; updated: number; untouched: number;
    reactivated: number; closed: number; record_errors: number; weak_fingerprints: number;
  };
  context: {
    repository?: string; branch?: string; commit?: string; image_ref?: string; image_digest?: string;
    environment?: string; build_id?: string; pipeline_url?: string;
  };
  /** The tools in the report. */
  scanners: string[];
  /** From an untracked ref: it never changed the inventory (docs/16 D10). */
  ephemeral: boolean;
}

/** One entry of a finding's timeline (internal/domain FindingEvent). */
export interface FindingEvent {
  id: string;
  at: string;
  actor: string;
  type: string;
  from?: unknown;
  to?: unknown;
  note?: string;
}

/** The body of PATCH /api/v1/findings/{id} (docs/11). */
export interface TriageBody {
  state?: FindingState;
  justification?: string;
  impactStatement?: string;
  duplicateOf?: string;
  note?: string;
  /** An override; severityReason is then required (docs/16 D38). */
  severity?: Severity;
  severityReason?: string;
  /** Replaces every tag. In bulk use addTags and removeTags, which keep each finding's own (D59). */
  tags?: string[];
  addTags?: string[];
  removeTags?: string[];
  /** The e-mail of a member of the tenant; "" clears it (D59). */
  owner?: string;
}

/** A file that supports a risk acceptance (docs/16 D60). */
export interface Proof {
  id: string;
  name: string;
  content_type: string;
  size_bytes: number;
  uploaded_by: string;
  uploaded_at: string;
}

/** POST /api/v1/findings/bulk: exactly one of ids and q (docs/16 D38). */
export interface BulkBody {
  ids?: string[];
  q?: string;
  patch: TriageBody;
}
export interface BulkResult {
  matched: number;
  updated: number;
  unchanged: number;
  failed: { id: string; error: string }[] | null;
}

export type AcceptanceStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'revoked';

/** internal/domain RiskAcceptance (docs/16 D39). */
export interface RiskAcceptance {
  id: string;
  status: AcceptanceStatus;
  justification: string;
  impact_statement?: string;
  owner: string;
  requester: string;
  approver?: string;
  expires_at: string;
  on_expiry: 'reactivate' | 'notify_only';
  decision_note?: string;
  created_at: string;
  decided_at?: string;
  finding_ids: string[];
}
export interface AcceptanceOutcome {
  acceptance: RiskAcceptance;
  applied: number;
  skipped: { finding_id: string; reason: string }[];
}
export interface TenantSettings {
  riskAcceptanceApproval: boolean;
  riskAcceptanceMaxDays: number;
}
export interface AcceptanceBody {
  findingIds: string[];
  justification: string;
  impactStatement?: string;
  owner?: string;
  expiresAt: string;
  onExpiry?: 'reactivate' | 'notify_only';
}

export type OpenBand = 'critical' | 'high' | 'medium' | 'low';

/** internal/domain AppSummary: an application seen through its active findings. */
export interface AppSummary {
  id: string;
  slug: string;
  name: string;
  version?: string;
  tags?: string[];
  business_criticality: string;
  internet_facing: boolean;
  type?: string;
  repository?: string;
  branch?: string;
  environment?: string;
  open: Record<OpenBand, number>;
  risk_score: number;
  exposure_count: number;
  sla_breached: number;
  last_scan?: string;
}
export interface SlaStanding {
  within: number;
  late: number;
  breached: number;
  adherence?: number;
}
export interface CoverageRow {
  asset_id: string;
  asset: string;
  scanner: string;
  last_scan: string;
}
export interface TopFinding {
  id: string;
  title: string;
  band: string;
  risk_score: number;
  state: string;
  sla_due_date?: string;
  vulnerability_id?: string | null;
  rule_id?: string;
}
/** What the score reads about an application (D136). */
export interface ApplicationContext {
  business_criticality: 'critical' | 'high' | 'medium' | 'low';
  internet_facing: boolean;
  data_classification: string[];
  compensating_controls: string[];
  lifecycle: 'planning' | 'development' | 'production' | 'deprecated';
  /** What the application is: "repo" (one branch of one repository) or empty (repository-wide). */
  type?: 'repo' | '';
  repository?: string;
  branch?: string;
  /** Where it runs; empty when nobody said, and the score then gives it no environment points. */
  environment: '' | 'production' | 'staging' | 'test' | 'development';
  /** "crd": an Application resource owns it and it is read only here; "ui" or "none": it can be changed here. */
  managed_by: 'crd' | 'ui' | 'none' | '';
  /** Dynamic context attributes (e.g. has_vpn, network_tier) evaluated by custom risk policies. */
  attributes?: Record<string, unknown>;
}
export type ApplicationContextUpdate = Partial<Pick<ApplicationContext, 'business_criticality' | 'internet_facing' | 'data_classification' | 'compensating_controls' | 'lifecycle' | 'environment'>>;

/** One factor of the risk policy in force (GET /api/v1/scoring). */
export interface ScoringFactor {
  name: string;
  when: string;
  points: number;
  reason?: string;
  group: 'severity' | 'threat' | 'context' | 'reduction' | (string & {});
}
export interface ScoringResponse {
  product: string;
  version: string;
  customised: boolean;
  risk: { base: Record<string, number>; bands: Record<string, number>; factors: ScoringFactor[] };
  sla: { matrix: Record<string, Record<string, number>>; kevDueDate: boolean; maxDays: number; startFrom: string; restartOnReactivation: boolean; pauseDuringRiskAcceptance: boolean };
  /** What an application can say about itself; the screens build their choices from these. */
  environments: string[];
  application_types: string[];
}

export interface FreshnessFeed {
  name: string;
  display_name: string;
  last_sync?: string;
  status: 'success' | 'syncing' | 'queued' | 'idle' | 'error' | 'disabled';
  error?: string;
}

export interface FreshnessAnalyzer {
  name: string;
  kind: 'external' | 'sbom';
  scope?: string;
  state: 'completed' | 'failed' | 'pending' | 'running' | 'timed_out' | 'cancelled' | 'not_applicable' | 'not_analysed';
  last_analysed_at?: string;
  findings: number;
  created: number;
  closed: number;
  error?: string;
  in_progress_since?: string;
}

export interface FreshnessSBOM {
  at: string;
  components: number;
}

export interface ApplicationFreshness {
  feeds: FreshnessFeed[];
  analyzers: FreshnessAnalyzer[];
  sbom?: FreshnessSBOM;
  rescored_at?: string;
}

export interface ApplicationScanSource {
  id: string;
  name: string;
  type: string;
  scanner_family?: string;
  categories: string[];
  auth_type: string;
  active: boolean;
  tracked_refs?: string[];
  created_at: string;
  disabled_at?: string;
  total_runs: number;
  last_scan_at?: string;
}

export interface ApplicationScanSourcesResponse {
  sources: ApplicationScanSource[];
  total: number;
}

export interface ApplicationPage extends AppSummary {
  context?: ApplicationContext;
  sla: SlaStanding;
  mttr: { band: OpenBand; days: number; fixed: number }[];
  coverage: CoverageRow[];
  top_findings: TopFinding[];
  scan_coverage?: CategoryCoverage[];
}
/** One kind of testing on the application page (D101). */
export interface CategoryCoverage {
  category: string;
  scanners: string[];
  last_scan?: string;
  open: Partial<Record<OpenBand, number>>;
}
export interface OverdueFinding {
  id: string;
  title: string;
  band: string;
  due: string;
  app_slug: string;
  app_name: string;
  vulnerability_id?: string | null;
  rule_id?: string;
}
export interface Overview {
  changes: { since: string; new: number; reopened: number; fixed: number };
  open: Record<OpenBand, number>;
  overdue: OverdueFinding[];
  overdue_total: number;
  sla: SlaStanding;
  top_apps: AppSummary[];
  coverage_gaps: AppSummary[];
}
/** One day of an application (GET /api/v1/applications/{id}/trend). */
export interface AppTrendPoint {
  day: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  new: number;
  fixed: number;
}
export interface AgeBuckets {
  under_30: number;
  d30_90: number;
  d90_180: number;
  over_180: number;
}
export interface TrendPoint {
  day: string;
  value: number;
}

/** One tool's view of a finding (internal/query Reporter). */
export interface Reporter {
  scanner: string;
  name: string;
  version?: string;
  first_seen: string;
  last_seen: string;
  reports: number;
  /** The latest scan of this tool still reports it. */
  present: boolean;
  tool_severity: string;
  latest_run_id: string;
  locations: number;
}
/** The same issue as found by another tool: a separate finding in the same correlation group (D24). */
export interface CorrelatedRef { id: string; scanner: string; rule_id: string; state: string }
export interface FindingSources { reported_by: Reporter[]; also_reported_by: CorrelatedRef[] }

/** The package a scanner named for a finding: on the occurrence, not on the finding (GET /findings/{id}). */
export interface PackageEvidence {
  purl?: string;
  component_name?: string;
  installed_version?: string;
  fixed_version?: string;
  manifest_path?: string;
}

/** What the feeds know of a vulnerability, whatever scanner or parser reported it (docs/11). */
export interface VulnerabilityRecord {
  id: string;
  aliases: string[];
  summary?: string;
  description?: string;
  cwes: number[];
  cvss_score?: number;
  cvss_vector?: string;
  scoring_status?: 'scored' | 'awaiting_analysis' | 'under_analysis' | 'unscored';
  nvd_status?: string;
  sync_status?: 'success' | 'failed' | 'pending';
  sync_error?: string;
  updated_at?: string;
  epss_score?: number;
  epss_percentile?: number;
  kev: boolean;
  kev_date_added?: string;
  kev_due_date?: string;
  kev_ransomware: boolean;
  published?: string;
  modified?: string;
  links: string[];
  exploited_by?: string[];
  /** The best public exploit the databases know: none, poc or weaponized. */
  exploit_maturity?: 'none' | 'poc' | 'weaponized';
}
export interface VulnerabilityDetail { id: string; known: boolean; record?: VulnerabilityRecord; links: string[] }

/** Where this tenant has a vulnerability: one row per application, with its assets. */
export interface ImpactApplication {
  id: string;
  slug: string;
  name: string;
  findings: number;
  open: number;
  max_severity: Severity;
  max_risk_score: number;
  asset_ids: string[];
}
export interface VulnerabilityImpact { id: string; findings: number; open: number; applications: ImpactApplication[]; truncated?: boolean }

/** An in-app message: what a deadline or expiry sweep found (docs/16 D45). */
export interface AppNotification { id: string; kind: string; title: string; body?: string; link?: string; created_at: string; unread: boolean }
export interface NotificationList { items: AppNotification[]; unread: number }

/** One row of the audit log (GET /api/v1/audit, docs/16 D46). */
export interface AuditEntry {
  id: string; at: string; actor: string; action: string; resource_type: string; resource_id?: string;
  detail?: { method?: string; path?: string; status?: number }; ip?: string; request_id?: string;
}
export interface AuditFilter { actor?: string; action?: string }

/** The caller's tenant role and the roles they hold on single applications (docs/16 D48). */
export interface MyAccess { role: Role; applications: Record<string, Role> }
/** A role on one application for one person or token. */
export interface AccessBinding { id: string; subject: string; role: Role; application_id: string; application_name?: string; managed_by: string; created_by: string; created_at: string }

/** A compliance framework (docs/16 D52). */
export interface Taxonomy {
  id: string; name: string; version: string; source: string; kind: 'cwe' | 'category' | 'custom'; note?: string; controls: number;
  /** builtin: shipped with Rampart; cluster: installed by the platform; tenant: installed by this tenant (D102). */
  origin?: 'builtin' | 'cluster' | 'tenant';
  scope?: string;
  /** The mark, served by this server (the address it came from stays on the server); absent: the screen draws one. */
  logo?: string;
  window_days?: number;
  /** A resource that does not validate: listed so its owner sees why, never evaluated. */
  error?: string;
}
export interface Attestation {
  id: string; framework_id: string; control_id: string; application_id?: string; status: 'passed' | 'failed';
  note: string; evidence_url?: string; attested_by: string; owner?: string; attested_at: string; expires_at: string;
  /** The renewal ticket opened for it on the tenant's tracker. failed: it gave up after its tries. */
  ticket?: { status: 'reserved' | 'opened' | 'closed' | 'failed'; ref?: string; url?: string; error?: string };
}
/** open: a finding is past its deadline (out of compliance); at_risk: findings are open, none past its deadline yet. */
export type ControlState = 'open' | 'at_risk' | 'clear' | 'not_assessed';
export interface ControlStatus {
  id: string; name: string; description?: string; status: ControlState; overdue?: number; earliest_due?: string;
  /** The status in one sentence: why it reads so, and what would change it. */
  reason?: string;
  open: number; bands: Record<OpenBand, number>;
  /** Risk-accepted findings: approved exceptions, not counted as open. */
  accepted?: number;
  query?: string;
  /** false: the link lists part of what is counted (a control matched two ways). */
  query_exact?: boolean;
  evidence?: string[]; needs?: string[];
  assessed_apps?: number; total_apps?: number;
  manual?: boolean; attestation?: Attestation;
}
export interface TaxonomyStatus extends Taxonomy { evaluated_at: string; window_days: number; historical?: boolean; status: ControlStatus[] }

/** A mass-close held by the safety guard for confirmation (docs/16 D22, docs/21 Section 3.2). */
export interface HeldCloseScope {
  tenant_id: string;
  scan_source_id: string;
  scanner_family: string;
  asset_id: string;
  track: string;
}

export interface HeldClose {
  id: string;
  ingest_run_id: string;
  scope: HeldCloseScope;
  finding_ids: string[];
  created_at: string;
  decided_by?: string;
  decision?: string;
  decided_at?: string;
}

/** Saved Explorer View (docs/21 §6.2) */
export interface SavedView {
  id: string;
  tenant_id: string;
  owner: string;
  name: string;
  query: string;
  sort?: string;
  scope: 'tenant' | 'user';
  created_at?: string;
}

/** Finding Group (docs/21 §6.1) */
export interface FindingGroup {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  owner?: string;
  /** absent: a tenant-wide group (admin only, D90) */
  application_id?: string;
  member_count?: number;
  ticket?: GroupTicket;
  created_at?: string;
  updated_at?: string;
}

/** A group's one ticket: reserved by the API, opened by the sweeper (D90). */
export interface GroupTicket {
  status: 'reserved' | 'done' | 'failed';
  attempts?: number;
  error?: string;
  requested_by?: string;
  external_ref?: string;
  url?: string;
}

export interface FindingGroupDetail {
  group: FindingGroup;
  finding_ids: string[];
}

/** Ingestion Parser Descriptor (docs/19 §2, docs/13 §9) */
export interface ParserDescriptor {
  id: string;
  name: string;
  kind: string;
  version: string;
  support_level: 'cluster' | 'certified' | 'community';
  description: string;
  category?: string;
  capabilities?: string[];
  /** Why the parser is listed and cannot run (its WASM module is not installed on the server). Absent: it can. */
  unavailable?: string;
  /** A report parser, or an SBOM reader. */
  family?: 'report' | 'sbom';
  runtime?: 'wasm' | 'lua' | 'mapping' | '';
  /** Installed for every tenant (a cluster resource) or by this tenant. */
  origin?: 'cluster' | 'tenant';
  /** The CRD resource kind: ClusterParser, ClusterSBOMParser, or Parser */
  resource_kind?: 'ClusterParser' | 'ClusterSBOMParser' | 'Parser';
  /** The Kubernetes CRD resource name: e.g. bandit, semgrep, cyclonedx */
  resource_name?: string;
  /** The WASM module it runs, by name. */
  module?: string;
  /** Installed correctly (ready), its module missing, or its resource refused (with `error`). */
  status?: 'ready' | 'module_missing' | 'refused';
  error?: string;
  /** The last run that used this parser, and the last time one completed. Absent when it has never been used. */
  last_run?: { id: string; status: string; error?: string; at: string };
  last_success?: string;
}

/**
 * What an analyzer did, as the server recorded it. A "test" is a person pressing Test; an "analysis" is Rampart asking the
 * analyzer about an SBOM. Only a test is written today.
 */
export interface AnalyzerEvent {
  id: string;
  event: 'test' | 'analysis';
  outcome: 'succeeded' | 'failed';
  message: string;
  detail?: Record<string, string>;
  duration_ms: number;
  actor?: string;
  created_at: string;
}

/**
 * One analyzer. `external` is a service Rampart calls over gRPC; `sbom` is the matcher inside the server. Which of the
 * remaining fields are set follows from the kind.
 */
export interface AnalyzerItem {
  kind: 'external' | 'sbom';
  /** `cluster`: set by an administrator for every tenant; `tenant`: set by this tenant. */
  scope: 'cluster' | 'tenant';
  namespace?: string;
  name: string;
  enabled: boolean;
  /** The server accepted the resource as written. When it did not, `error` says why. */
  ready: boolean;
  error?: string;
  protocol?: string;
  target?: string;
  timeout_seconds?: number;
  secure?: boolean;
  engine?: string;
  min_confidence?: number;
  include_pre_release?: boolean;
  match_direct_only?: boolean;
  sources?: Record<string, boolean>;
  schedule?: string;
  updated_at: string;
  last_event?: AnalyzerEvent;
}

export interface AnalyzerTestResult {
  ok: boolean;
  outcome: 'succeeded' | 'failed';
  message: string;
  latency_ms: number;
  detail?: Record<string, string>;
  event?: AnalyzerEvent;
}

/** What asking an analyzer to analyse every SBOM answers: how many analyses were queued. Those already pending or running are not queued again. */
export interface AnalyzeResponse {
  queued: number;
}

/** What identifies one analyzer to the test and events calls. */
export interface AnalyzerRef {
  kind: AnalyzerItem['kind'];
  scope: AnalyzerItem['scope'];
  namespace?: string;
  name: string;
}

/** Connector status condition (docs/04, docs/20) */
export interface ConnectorCondition {
  type: string;
  status: 'True' | 'False' | 'Unknown';
  reason?: string;
  message?: string;
  last_transition_time?: string;
}

/** A connector as GET /api/v1/connectors lists it (docs/20, docs/21). */
export interface ConnectorSummary {
  name: string;
  type: string; // the ConnectorType: jira, github, externalTracker, slack, teams, email, webhook, plugin
  /** The catalogue's kind of the type (docs/50): Ticketing lists trackers, Notifiers lists notifiers. Empty for a type the catalogue does not list. */
  kind: 'tracker' | 'notifier' | 'source' | '';
  direction: 'outbound' | 'inbound' | 'bidirectional';
  enabled: boolean;
  /** the resource's spec as the server stores it; for a plugin connector, the package it uses (D94) */
  spec?: {
    plugin?: { name: string };
    externalTracker?: { trackerRef?: { scope?: string; namespace?: string; name?: string }; defaultProject?: string };
  };
  status: {
    conditions?: ConnectorCondition[];
    last_check_time?: string;
    account_id?: string;
  };
}

/** An installed IntegrationPackage: a tool described as data (GET /api/v1/integration-packages, D94). */
export interface IntegrationPackageItem {
  name: string;
  kind: string;
  runtime: string;
  version: string;
  description?: string;
  egress: string[];
  secrets: string[];
  config: string[];
  error?: string;
  used_by: string[];
  updated_at: string;
}

/** Vulnerability feed item and sync status (docs/16 D86, D88). */
export interface FeedItem {
  name: string;
  display_name: string;
  category: string;
  description: string;
  url: string;
  is_mirror: boolean;
  enabled: boolean;
  /** Why a feed that is not enabled is not run: the ClusterFeed switched it off, egress is denied with no mirror, OSV has no ecosystem, or the server's configuration. */
  disabled_reason?: 'switched_off' | 'egress_denied' | 'no_ecosystem' | 'server_disabled';
  status: 'success' | 'syncing' | 'queued' | 'idle' | 'error' | 'disabled';
  records: number;
  last_sync?: string | null;
  error?: string | null;
}

export interface FeedMirrorSpec {
  egress?: 'allow' | 'deny';
  storageMode?: 'lightweight' | 'full' | 'standalone';
  kev?: { url?: string; enabled?: boolean };
  epss?: { url?: string; enabled?: boolean };
  nvd?: { url?: string; tokenFile?: string; enabled?: boolean };
  osv?: { url?: string; ecosystems?: string[]; enabled?: boolean };
  vulnrichment?: { url?: string; tokenFile?: string; enabled?: boolean };
  exploitdb?: { url?: string; tokenFile?: string; enabled?: boolean };
  metasploit?: { url?: string; tokenFile?: string; enabled?: boolean };
  euvd?: { url?: string; tokenFile?: string; enabled?: boolean };
  vulncheckKev?: { url?: string; tokenFile?: string; enabled?: boolean };
  custom?: Array<{
    name: string;
    url?: string;
    format: string;
    tokenFile?: string;
    pushTokenFile?: string;
    enabled?: boolean;
  }>;
}

export interface FeedTestResult {
  name: string;
  url: string;
  reachable: boolean;
  status_code: number;
  latency_ms: number;
  message: string;
  error?: string | null;
}

export interface FeedTestConnectionResponse {
  tested_at: string;
  results: FeedTestResult[];
}

export interface FeedSyncResponse {
  status: string;
  feed: string;
  message: string;
  started_at: string;
}

export interface FeedsResponse {
  mirror?: FeedMirrorSpec | null;
  items: FeedItem[];
}

export interface AdvisorySourceItem {
  name: string;
  display_name: string;
  provider: string;
  category: 'open' | 'api' | 'commercial' | 'custom';
  description: string;
  url: string;
  enabled: boolean;
  token_required: boolean;
  token_present: boolean;
  token_file?: string;
  records_count?: number;
  last_sync?: string | null;
  status: 'ready' | 'syncing' | 'error' | 'disabled';
  error?: string | null;
}

export interface ClusterAdvisorySourceSpec {
  enabled?: boolean;
  mode?: 'hybrid' | 'live' | 'stored';
  liveFetch?: boolean;
  persistReports?: boolean;
  refreshInterval?: string;
  sources?: {
    osv?: { enabled?: boolean; url?: string; ecosystems?: string[] };
    nvd?: { enabled?: boolean; url?: string; tokenFile?: string };
    sonatype?: { enabled?: boolean; url?: string; username?: string; tokenFile?: string };
    snyk?: { enabled?: boolean; url?: string; orgId?: string; tokenFile?: string };
    vulncheck?: { enabled?: boolean; url?: string; tokenFile?: string };
    depsdev?: { enabled?: boolean; url?: string };
    custom?: Array<{
      name: string;
      enabled?: boolean;
      format: string;
      url: string;
      tokenFile?: string;
    }>;
  };
}

export interface AdvisorySourcesResponse {
  spec?: ClusterAdvisorySourceSpec | null;
  items: AdvisorySourceItem[];
}

/** Inventory asset summary (docs/13, docs/21) */
export interface InventoryAsset {
  id: string;
  name: string;
  kind: string; // repository, container, host, package
  application_name?: string;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  total_findings: number;
  last_seen_at?: string;
}

/** Vulnerability by CVE (docs/13, docs/21) */
export interface VulnerabilityRow {
  cve_id: string;
  title: string;
  severity: string;
  score: number;
  epss?: number;
  kev: boolean;
  affected_assets: number;
  affected_applications: number;
  open_findings: number;
}

/** Where an application stands against one framework (GET /applications/{id}/compliance). */
export interface AppFramework {
  id: string;
  name: string;
  version: string;
  origin?: 'builtin' | 'cluster' | 'tenant';
  logo?: string;
  verdict: 'meets' | 'at_risk' | 'gaps' | 'partial';
  controls: number;
  clear: number;
  open: number;
  at_risk: number;
  not_assessed: number;
  open_findings: number;
  overdue_findings: number;
  earliest_due?: string;
  accepted_findings: number;
  window_days: number;
}
export interface AppCompliance { application: string; evaluated_at: string; frameworks: AppFramework[]; not_in_scope: string[] }

/** A finding in one list of an application's changes (GET /applications/{id}/changes). */
export interface FindingChange {
  id: string;
  vulnerability_id?: string;
  rule_id: string;
  title: string;
  category: string;
  severity: Severity;
  risk_band: Severity;
  risk_score: number;
  state: string;
  resolution?: string;
  asset: string;
  first_seen: string;
  resolved_at?: string | null;
  at: string;
}
export interface ChangeDay { day: string; new: number; closed: number }
export interface ApplicationChanges {
  application: string;
  from: string;
  to: string;
  days: number;
  summary: { new: number; closed: number; reopened: number; open_at_start: number; open_at_end: number; previous: { from: string; to: string; new: number; closed: number } };
  daily: ChangeDay[];
  new: FindingChange[];
  closed: FindingChange[];
  reopened: FindingChange[];
  open: FindingChange[];
  truncated: string[];
}

/** A compliance control an open finding counts against (GET /findings/{id}). */
export interface FindingControl {
  framework_id: string;
  framework: string;
  version: string;
  control_id: string;
  control: string;
  due?: string;
  overdue: boolean;
}

export interface TrackerRefKey {
  scope: string;
  namespace?: string;
  name: string;
}

export interface TrackerEvent {
  id: string;
  event: 'test' | 'check' | string;
  outcome: 'succeeded' | 'failed' | string;
  message: string;
  detail?: Record<string, string>;
  latency_ms: number;
  actor?: string;
  at: string;
}

export interface TrackerContainerItem {
  scope: 'cluster' | 'tenant' | string;
  namespace?: string;
  name: string;
  enabled: boolean;
  state: 'ready' | 'disabled' | 'refused' | string;
  reason?: string;
  protocol: string;
  target?: string;
  tls: 'off' | 'tls' | string;
  timeout_seconds: number;
  bound_connectors: number;
  last_event?: TrackerEvent;
  updated_at?: string;
}

export interface TrackerDeclaredSecret {
  name: string;
  holds?: string;
  purpose?: string;
  required: boolean;
}

export interface TrackerTestResult {
  ok: boolean;
  outcome: string;
  message: string;
  latency_ms: number;
  provider?: string;
  display_name?: string;
  version?: string;
  capabilities?: string[];
  config_schema?: Record<string, unknown>;
  declared_secrets?: TrackerDeclaredSecret[];
  example_yaml?: string;
  detail?: Record<string, string>;
  event?: TrackerEvent;
}

export interface TicketSummary {
  id: string;
  connector: string;
  external_ref: string;
  url?: string;
  state: string;
  finding_count: number;
  created_at: string;
  updated_at: string;
}

export interface TicketOutboxItem {
  finding_id: string;
  finding_title?: string;
  severity?: string;
  status: string;
  attempts: number;
  next_attempt_at: string;
  last_error?: string;
  updated_at: string;
}

export interface TicketQueueResponse {
  tickets: TicketSummary[];
  outbox: TicketOutboxItem[];
  configured: boolean;
}
