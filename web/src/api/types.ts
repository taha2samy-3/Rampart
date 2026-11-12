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
export type Role = 'viewer' | 'triager' | 'admin';
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

export interface FindingLocation {
  file_path?: string;
  start_line?: number;
  purl?: string;
  component_name?: string;
  installed_version?: string;
  fixed_version?: string;
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
  location?: FindingLocation;
  severity: Severity;
  risk_score: number;
  state: FindingState;
  detection?: 'present' | 'absent';
  first_seen: string;
  last_seen?: string;
  occurrence_count?: number;
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
