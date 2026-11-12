-- +goose Up
-- Schema Version 1 (Rampart ASPM Foundation)
-- Normative References: docs/12-database-schema.md, docs/16-implementation-decisions.md (D1, D4, D5, D8, D10, D11, D12, D13, D17, D18, D19, D21, D25, D28)

-- Helper function for Row-Level Security predicate (D4)
-- Nullif ensures an empty or unset tenant yields NULL, matching zero rows securely
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID AS $$
    SELECT NULLIF(current_setting('app.tenant_id', true), '')::UUID;
$$ LANGUAGE SQL STABLE;
-- +goose StatementEnd

-- ============================================================================
-- 1. Database Roles & Grants (D4)
-- ============================================================================
-- Roles are normally provisioned by the platform (CNPG managed roles, Helm, or
-- deploy/compose/initdb) with credentials from a Secret (D4). This only
-- guarantees that they exist; it never sets a password or touches login.
-- +goose StatementBegin
DO $$
BEGIN
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rampart_owner') THEN
            CREATE ROLE rampart_owner NOLOGIN;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rampart_app') THEN
            CREATE ROLE rampart_app NOLOGIN;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rampart_system') THEN
            CREATE ROLE rampart_system NOLOGIN BYPASSRLS;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rampart_ro') THEN
            CREATE ROLE rampart_ro NOLOGIN;
        END IF;
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END $$;
-- +goose StatementEnd

-- ============================================================================
-- 2. Global Intelligence Tables (Shared, Read-Only to tenants, No RLS)
-- ============================================================================

CREATE TABLE vulnerability (
    id TEXT PRIMARY KEY, -- Canonical: CVE-..., else GHSA-..., else OSV id
    aliases TEXT[] NOT NULL DEFAULT '{}',
    summary TEXT,
    description TEXT,
    cwes INT[] NOT NULL DEFAULT '{}',
    cvss JSONB NOT NULL DEFAULT '[]',
    cvss_best_score NUMERIC(3,1),
    cvss_best_vector TEXT,
    epss_score REAL,
    epss_percentile REAL,
    epss_date DATE,
    kev_date_added DATE,
    kev_due_date DATE,
    kev_ransomware BOOLEAN DEFAULT FALSE,
    ssvc JSONB,
    exploit_maturity TEXT,
    published TIMESTAMPTZ,
    modified TIMESTAMPTZ,
    affected JSONB,
    fixed_versions JSONB,
    "references" JSONB,
    source_payloads JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_vulnerability_aliases ON vulnerability USING GIN (aliases);

CREATE TABLE vulnerability_alias (
    alias TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE
);

CREATE TABLE rule (
    scanner_family TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    name TEXT,
    description TEXT,
    help_uri TEXT,
    default_severity TEXT,
    cwes INT[] NOT NULL DEFAULT '{}',
    category TEXT NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (scanner_family, rule_id)
);

-- ============================================================================
-- 3. Tenancy, Identity, Access (D4, D8, D17)
-- ============================================================================

CREATE TABLE tenant (
    id UUID PRIMARY KEY, -- Generated in Go via UUIDv7 (D5)
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    k8s_namespace TEXT,
    settings JSONB NOT NULL DEFAULT '{}',
    quotas JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- D20: a Tenant lists the namespaces it owns; the binding comes only from that list.
-- Control-plane table: one owner per namespace, written by rampart_system only.
CREATE TABLE tenant_namespace (
    namespace TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_tenant_namespace_tenant ON tenant_namespace (tenant_id);

CREATE TABLE app_user (
    id UUID PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (issuer, subject)
);

CREATE TABLE tenant_member (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role TEXT NOT NULL, -- viewer | triager | admin
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);
ALTER TABLE tenant_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_member FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_member
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
-- A person may read their own memberships across tenants (tenant switcher, D8). Read only:
-- writes still require the tenant context.
CREATE POLICY member_reads_own ON tenant_member FOR SELECT
    USING (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

CREATE TABLE api_token (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT 'default',
    prefix TEXT NOT NULL,
    hash BYTEA NOT NULL UNIQUE, -- SHA-256 of token secret (never plaintext, D17)
    role TEXT NOT NULL DEFAULT 'viewer',
    scan_source_id UUID, -- Optional restriction per D17
    scopes TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_api_token_tenant ON api_token (tenant_id, prefix);
CREATE INDEX idx_api_token_hash ON api_token (hash) WHERE revoked_at IS NULL;
ALTER TABLE api_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_token FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON api_token
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE secret_material (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    encrypted_value BYTEA NOT NULL,
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, key)
);
ALTER TABLE secret_material ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_material FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON secret_material
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE session (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,      -- absolute lifetime (doc 14: 24 h)
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- idle timeout (doc 14: 8 h)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_session_token_hash ON session (tenant_id, token_hash);
CREATE INDEX idx_session_tenant_user ON session (tenant_id, user_id);
ALTER TABLE session ENABLE ROW LEVEL SECURITY;
ALTER TABLE session FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON session
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE local_admin (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, username)
);
ALTER TABLE local_admin ENABLE ROW LEVEL SECURITY;
ALTER TABLE local_admin FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON local_admin
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ============================================================================
-- 4. Inventory & Assets (D10)
-- ============================================================================

CREATE TABLE application (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    hierarchy_node_id UUID,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    business_criticality TEXT NOT NULL DEFAULT 'medium',
    internet_facing BOOLEAN NOT NULL DEFAULT FALSE,
    data_classification TEXT[] NOT NULL DEFAULT '{}',
    lifecycle TEXT NOT NULL DEFAULT 'production',
    owners JSONB NOT NULL DEFAULT '[]',
    tags TEXT[] NOT NULL DEFAULT '{}',
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, slug)
);
ALTER TABLE application ENABLE ROW LEVEL SECURITY;
ALTER TABLE application FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON application
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE asset (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    application_id UUID REFERENCES application(id) ON DELETE SET NULL, -- Nullable for shared assets (D10)
    service_id UUID,
    environment_id UUID,
    type TEXT NOT NULL, -- repository | image | workload | url | sbom_project | package | host | cloud_resource
    key TEXT NOT NULL, -- Stable natural key (D10)
    display_name TEXT,
    attributes JSONB NOT NULL DEFAULT '{}',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, type, key)
);
CREATE INDEX idx_asset_tenant_app ON asset (tenant_id, application_id);
ALTER TABLE asset ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON asset
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE asset_version (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    version TEXT NOT NULL, -- Commit SHA or image digest (D10)
    attributes JSONB NOT NULL DEFAULT '{}',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, asset_id, version)
);
ALTER TABLE asset_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_version FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON asset_version
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE asset_edge (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    from_id UUID NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    to_id UUID NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    relation TEXT NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}',
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant_id, from_id, to_id, relation)
);
ALTER TABLE asset_edge ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_edge FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON asset_edge
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ============================================================================
-- 5. Sources and Ingestion (D2, D9, D10, D13)
-- ============================================================================

CREATE TABLE scan_source (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    scanner_family TEXT NOT NULL,
    default_application_id UUID REFERENCES application(id) ON DELETE SET NULL,
    mapping JSONB NOT NULL DEFAULT '{}',
    ingestion_policy JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
ALTER TABLE scan_source ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_source FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scan_source
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE upload (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    scan_source_id UUID REFERENCES scan_source(id) ON DELETE SET NULL,
    idempotency_key TEXT,
    object_ref TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    format_hint TEXT,
    context JSONB NOT NULL DEFAULT '{}',
    options JSONB NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'created',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, idempotency_key)
);
ALTER TABLE upload ENABLE ROW LEVEL SECURITY;
ALTER TABLE upload FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON upload
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE ingest_run (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    upload_id UUID REFERENCES upload(id) ON DELETE SET NULL,
    scan_source_id UUID REFERENCES scan_source(id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    track TEXT NOT NULL DEFAULT 'default',
    scanner_family TEXT NOT NULL,
    scanner_version TEXT,
    format TEXT NOT NULL,
    context JSONB NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'queued',
    stats JSONB NOT NULL DEFAULT '{}',
    error TEXT,
    scan_started TIMESTAMPTZ,
    scan_finished TIMESTAMPTZ,
    crd_uid TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);
CREATE INDEX idx_ingest_run_tenant_status ON ingest_run (tenant_id, status);
CREATE INDEX idx_ingest_run_tenant_asset ON ingest_run (tenant_id, asset_id, scanner_family, finished_at DESC);
ALTER TABLE ingest_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingest_run FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ingest_run
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE ingest_run_scope (
    ingest_run_id UUID NOT NULL REFERENCES ingest_run(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    track TEXT NOT NULL,
    scanner_family TEXT NOT NULL,
    scan_source_id UUID NOT NULL,
    last_applied_scan_finished TIMESTAMPTZ,
    PRIMARY KEY (ingest_run_id, asset_id, track, scanner_family)
);
ALTER TABLE ingest_run_scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingest_run_scope FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ingest_run_scope
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE ingest_run_result (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    ingest_run_id UUID NOT NULL REFERENCES ingest_run(id) ON DELETE CASCADE,
    finding_key TEXT NOT NULL,
    is_new BOOLEAN NOT NULL DEFAULT FALSE,
    is_fixed BOOLEAN NOT NULL DEFAULT FALSE,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    location JSONB NOT NULL DEFAULT '{}',
    raw_payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE ingest_run_result ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingest_run_result FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ingest_run_result
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- Unlogged staging table for fast COPY (D13 - No RLS, deleted per run, never truncated)
CREATE UNLOGGED TABLE ingest_staging (
    ingest_run_id UUID NOT NULL,
    seq INT NOT NULL,
    finding_key TEXT NOT NULL,
    scanner_family TEXT NOT NULL,
    category TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    tool_severity TEXT NOT NULL,
    severity TEXT NOT NULL,
    severity_rank INT NOT NULL,
    location JSONB NOT NULL,
    cwes INT[] NOT NULL DEFAULT '{}',
    vuln_id TEXT,
    cvss_vector TEXT,
    content_hash TEXT NOT NULL,
    initial_state TEXT NOT NULL DEFAULT 'open',
    seen_at TIMESTAMPTZ NOT NULL,
    raw JSONB NOT NULL,
    PRIMARY KEY (ingest_run_id, seq)
);
CREATE INDEX idx_ingest_staging_run_key ON ingest_staging (ingest_run_id, finding_key);

CREATE TABLE action_ledger (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL,
    finding_id UUID NOT NULL,
    action TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, policy_id, finding_id, action)
);
ALTER TABLE action_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_ledger FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON action_ledger
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE tenant_queue_limit (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    queue_name TEXT NOT NULL,
    max_concurrency INT NOT NULL DEFAULT 5,
    current_concurrency INT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, queue_name)
);
ALTER TABLE tenant_queue_limit ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_queue_limit FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_queue_limit
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ============================================================================
-- 6. Findings & Occurrences (D11, D12, D13, D18, D28)
-- ============================================================================

CREATE TABLE finding (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    finding_key TEXT NOT NULL, -- SHA-256 deterministic fingerprint (D11)
    dedup_scope TEXT NOT NULL DEFAULT 'asset',
    asset_id UUID NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    track TEXT NOT NULL DEFAULT 'default',
    category TEXT NOT NULL,
    rule_scanner_family TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    cwes INT[] NOT NULL DEFAULT '{}',
    vulnerability_id TEXT,
    location JSONB NOT NULL,
    purl_base TEXT,
    file_path TEXT,
    tool_severity TEXT NOT NULL,
    severity TEXT NOT NULL,
    severity_override_reason TEXT,
    cvss_vector TEXT,
    risk_score INT NOT NULL DEFAULT 0,
    risk_band TEXT NOT NULL DEFAULT 'low',
    state TEXT NOT NULL DEFAULT 'open', -- OpenVEX disposition (D18)
    previous_state TEXT,
    state_reason TEXT,
    detection TEXT NOT NULL DEFAULT 'present', -- present | absent (D18)
    content_hash TEXT NOT NULL,
    weak_fingerprint BOOLEAN NOT NULL DEFAULT FALSE,
    correlation_key TEXT,
    kev BOOLEAN NOT NULL DEFAULT FALSE,
    epss_bucket TEXT,
    fix_available BOOLEAN NOT NULL DEFAULT FALSE,
    hierarchy_path TEXT,
    environment_kind TEXT,
    tags TEXT[] NOT NULL DEFAULT '{}',
    sla_due_date TIMESTAMPTZ,
    search TSVECTOR,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolution TEXT,
    reopened_count INT NOT NULL DEFAULT 0,
    occurrence_count INT NOT NULL DEFAULT 1,
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, finding_key)
);

CREATE INDEX idx_finding_tenant_app ON finding (tenant_id, application_id);
CREATE INDEX idx_finding_tenant_asset_track ON finding (tenant_id, asset_id, track);
CREATE INDEX idx_finding_tenant_state ON finding (tenant_id, state);
CREATE INDEX idx_finding_tenant_severity ON finding (tenant_id, severity);
CREATE INDEX idx_finding_tenant_risk_score ON finding (tenant_id, risk_score DESC);
CREATE INDEX idx_finding_tenant_purl_base ON finding (tenant_id, purl_base) WHERE purl_base IS NOT NULL;
CREATE INDEX idx_finding_tenant_vuln ON finding (tenant_id, vulnerability_id) WHERE vulnerability_id IS NOT NULL;
CREATE INDEX idx_finding_tenant_tags ON finding USING GIN (tags);
CREATE INDEX idx_finding_tenant_search ON finding USING GIN (search);

ALTER TABLE finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON finding
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE finding_key_alias (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    old_key TEXT NOT NULL,
    new_key TEXT NOT NULL,
    finding_id UUID NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, old_key)
);
ALTER TABLE finding_key_alias ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_key_alias FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON finding_key_alias
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE occurrence (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    ingest_run_id UUID NOT NULL REFERENCES ingest_run(id) ON DELETE CASCADE,
    scan_source_id UUID REFERENCES scan_source(id) ON DELETE SET NULL,
    occurrence_key TEXT NOT NULL,
    asset_id UUID NOT NULL,
    track TEXT NOT NULL DEFAULT 'default',
    scanner_family TEXT NOT NULL,
    scanner_name TEXT NOT NULL,
    scanner_version TEXT,
    tool_record_id TEXT,
    location JSONB NOT NULL,
    tool_severity TEXT NOT NULL,
    normalized JSONB,
    raw JSONB,
    present BOOLEAN NOT NULL DEFAULT TRUE, -- D12
    seen_count INT NOT NULL DEFAULT 1,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE NULLS NOT DISTINCT (tenant_id, finding_id, scan_source_id, occurrence_key)
);
CREATE INDEX idx_occurrence_tenant_finding ON occurrence (tenant_id, finding_id);
CREATE INDEX idx_occurrence_scope_present ON occurrence (tenant_id, scan_source_id, scanner_family, asset_id, track) WHERE present = TRUE;
ALTER TABLE occurrence ENABLE ROW LEVEL SECURITY;
ALTER TABLE occurrence FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON occurrence
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ============================================================================
-- 7. Events & Audit (Partitioned by range per D4)
-- ============================================================================

CREATE TABLE finding_event (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,
    type TEXT NOT NULL,
    "from" JSONB,
    "to" JSONB,
    note TEXT,
    PRIMARY KEY (at, id)
) PARTITION BY RANGE (at);

-- Monthly initial partitions (D4)
CREATE TABLE IF NOT EXISTS finding_event_y2026_m11 PARTITION OF finding_event
    FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS finding_event_y2026_m12 PARTITION OF finding_event
    FOR VALUES FROM ('2026-12-01 00:00:00+00') TO ('2027-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS finding_event_y2027_m01 PARTITION OF finding_event
    FOR VALUES FROM ('2027-01-01 00:00:00+00') TO ('2027-02-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS finding_event_default PARTITION OF finding_event DEFAULT;

CREATE INDEX idx_finding_event_finding ON finding_event (tenant_id, finding_id, at DESC);
ALTER TABLE finding_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_event FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON finding_event
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE audit_event (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor JSONB NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    before JSONB,
    after JSONB,
    ip INET,
    user_agent TEXT,
    request_id TEXT,
    PRIMARY KEY (at, id)
) PARTITION BY RANGE (at);

-- Monthly initial partitions (D4)
CREATE TABLE IF NOT EXISTS audit_event_y2026_m11 PARTITION OF audit_event
    FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS audit_event_y2026_m12 PARTITION OF audit_event
    FOR VALUES FROM ('2026-12-01 00:00:00+00') TO ('2027-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS audit_event_y2027_m01 PARTITION OF audit_event
    FOR VALUES FROM ('2027-01-01 00:00:00+00') TO ('2027-02-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS audit_event_default PARTITION OF audit_event DEFAULT;

ALTER TABLE audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_event FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_event
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ============================================================================
-- 8. Tenant-Local Intelligence Tables (D19)
-- ============================================================================

CREATE TABLE vulnerability_local (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    aliases TEXT[] NOT NULL DEFAULT '{}',
    summary TEXT,
    description TEXT,
    cwes INT[] NOT NULL DEFAULT '{}',
    cvss JSONB NOT NULL DEFAULT '[]',
    severity TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id)
);
ALTER TABLE vulnerability_local ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_local FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON vulnerability_local
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE vulnerability_alias_local (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    alias TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, alias)
);
ALTER TABLE vulnerability_alias_local ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_alias_local FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON vulnerability_alias_local
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE rule_local (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    scanner_family TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    name TEXT,
    description TEXT,
    default_severity TEXT,
    cwes INT[] NOT NULL DEFAULT '{}',
    category TEXT NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, scanner_family, rule_id)
);
ALTER TABLE rule_local ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_local FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rule_local
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ============================================================================
-- 9. Supply Chain & SBOM (docs/12)
-- ============================================================================

CREATE TABLE sbom (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    ingest_run_id UUID REFERENCES ingest_run(id) ON DELETE SET NULL,
    format TEXT NOT NULL,
    spec_version TEXT NOT NULL,
    serial TEXT,
    object_ref TEXT,
    root_component TEXT,
    component_count INT NOT NULL DEFAULT 0,
    dependencies JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_sbom_tenant_asset ON sbom (tenant_id, asset_id);
ALTER TABLE sbom ENABLE ROW LEVEL SECURITY;
ALTER TABLE sbom FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sbom
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE sbom_component (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    sbom_id UUID NOT NULL REFERENCES sbom(id) ON DELETE CASCADE,
    ref TEXT NOT NULL,
    purl TEXT NOT NULL,
    purl_base TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    licenses TEXT[] NOT NULL DEFAULT '{}',
    scope TEXT,
    direct BOOLEAN NOT NULL DEFAULT FALSE,
    hashes JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, sbom_id, ref)
);
CREATE INDEX idx_sbom_comp_tenant_purl ON sbom_component (tenant_id, purl_base);
ALTER TABLE sbom_component ENABLE ROW LEVEL SECURITY;
ALTER TABLE sbom_component FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sbom_component
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ============================================================================
-- 10. Role Grants (D4)
-- ============================================================================

GRANT USAGE ON SCHEMA public TO rampart_app, rampart_ro, rampart_system;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rampart_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rampart_system;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO rampart_ro;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO rampart_owner;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO rampart_owner;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO rampart_app;

-- D4/D19: tenants are written by the operator (rampart_system); global intelligence
-- tables are written only by feed sync jobs. rampart_app reads them.
REVOKE INSERT, UPDATE, DELETE ON tenant, tenant_namespace, vulnerability, vulnerability_alias, rule FROM rampart_app;
REVOKE INSERT, UPDATE, DELETE ON tenant, tenant_namespace, vulnerability, vulnerability_alias, rule FROM rampart_ro;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO rampart_system;

-- +goose Down
DROP TABLE IF EXISTS sbom_component;
DROP TABLE IF EXISTS sbom;
DROP TABLE IF EXISTS rule_local;
DROP TABLE IF EXISTS vulnerability_alias_local;
DROP TABLE IF EXISTS vulnerability_local;
DROP TABLE IF EXISTS audit_event;
DROP TABLE IF EXISTS finding_event;
DROP TABLE IF EXISTS occurrence;
DROP TABLE IF EXISTS finding_key_alias;
DROP TABLE IF EXISTS finding;
DROP TABLE IF EXISTS ingest_staging;
DROP TABLE IF EXISTS ingest_run_result;
DROP TABLE IF EXISTS ingest_run_scope;
DROP TABLE IF EXISTS tenant_queue_limit;
DROP TABLE IF EXISTS action_ledger;
DROP TABLE IF EXISTS local_admin;
DROP TABLE IF EXISTS session;
DROP TABLE IF EXISTS ingest_run;
DROP TABLE IF EXISTS upload;
DROP TABLE IF EXISTS scan_source;
DROP TABLE IF EXISTS asset_edge;
DROP TABLE IF EXISTS asset_version;
DROP TABLE IF EXISTS asset;
DROP TABLE IF EXISTS application;
DROP TABLE IF EXISTS secret_material;
DROP TABLE IF EXISTS api_token;
DROP TABLE IF EXISTS tenant_member;
DROP TABLE IF EXISTS app_user;
DROP TABLE IF EXISTS tenant_namespace;
DROP TABLE IF EXISTS tenant;
DROP TABLE IF EXISTS rule;
DROP TABLE IF EXISTS vulnerability_alias;
DROP TABLE IF EXISTS vulnerability;
DROP FUNCTION IF EXISTS current_tenant_id();
