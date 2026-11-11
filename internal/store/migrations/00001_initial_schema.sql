-- +goose Up
-- Schema Version 1 (Rampart ASPM Foundation)
-- Normative References: docs/12-database-schema.md, docs/16-implementation-decisions.md (D1, D4, D5, D8, D10, D11, D12, D13, D18, D19, D28)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- 1. Global Intelligence Tables (Shared, Read-Only to tenants, No RLS)
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
    references JSONB,
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
-- 2. Tenancy, Identity, Access (D4, D8)
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

-- Helper function for Row-Level Security predicate (D4)
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID AS $$
    SELECT NULLIF(current_setting('app.tenant_id', true), '')::UUID;
$$ LANGUAGE SQL STABLE;

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
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);
ALTER TABLE tenant_member ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_member
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ============================================================================
-- 3. Inventory & Assets (D10)
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
CREATE POLICY tenant_isolation ON application
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE asset (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    application_id UUID REFERENCES application(id) ON DELETE SET NULL, -- Nullable for shared assets (D10)
    service_id UUID,
    environment_id UUID,
    type TEXT NOT NULL,
    key TEXT NOT NULL,
    display_name TEXT,
    attributes JSONB NOT NULL DEFAULT '{}',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, type, key)
);
CREATE INDEX idx_asset_tenant_app ON asset (tenant_id, application_id);
ALTER TABLE asset ENABLE ROW LEVEL SECURITY;
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
CREATE POLICY tenant_isolation ON asset_version
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ============================================================================
-- 4. Sources and Ingestion (D2, D13)
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
CREATE POLICY tenant_isolation ON scan_source
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE ingest_run (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    upload_id UUID,
    scan_source_id UUID NOT NULL REFERENCES scan_source(id) ON DELETE CASCADE,
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
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);
CREATE INDEX idx_ingest_run_tenant_status ON ingest_run (tenant_id, status);
ALTER TABLE ingest_run ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ingest_run
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

-- ============================================================================
-- 5. Findings & Occurrences (D11, D12, D13, D18, D28)
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
    tool_severity TEXT NOT NULL,
    severity TEXT NOT NULL,
    severity_override_reason TEXT,
    cvss_vector TEXT,
    risk_score INT NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'open', -- OpenVEX disposition (D18)
    previous_state TEXT,
    state_reason TEXT,
    detection TEXT NOT NULL DEFAULT 'present', -- present | absent (D18)
    content_hash TEXT NOT NULL,
    weak_fingerprint BOOLEAN NOT NULL DEFAULT FALSE,
    correlation_key TEXT,
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

ALTER TABLE finding ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON finding
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE occurrence (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    ingest_run_id UUID NOT NULL REFERENCES ingest_run(id) ON DELETE CASCADE,
    scan_source_id UUID NOT NULL REFERENCES scan_source(id) ON DELETE CASCADE,
    occurrence_key TEXT NOT NULL,
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
    UNIQUE (tenant_id, finding_id, scan_source_id, occurrence_key)
);
CREATE INDEX idx_occurrence_tenant_finding ON occurrence (tenant_id, finding_id);
ALTER TABLE occurrence ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON occurrence
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TABLE finding_event (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,
    type TEXT NOT NULL,
    "from" JSONB,
    "to" JSONB,
    note TEXT
);
CREATE INDEX idx_finding_event_finding ON finding_event (tenant_id, finding_id, at DESC);
ALTER TABLE finding_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON finding_event
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose Down
DROP TABLE IF EXISTS finding_event;
DROP TABLE IF EXISTS occurrence;
DROP TABLE IF EXISTS finding;
DROP TABLE IF EXISTS ingest_staging;
DROP TABLE IF EXISTS ingest_run;
DROP TABLE IF EXISTS scan_source;
DROP TABLE IF EXISTS asset_version;
DROP TABLE IF EXISTS asset;
DROP TABLE IF EXISTS application;
DROP TABLE IF EXISTS tenant_member;
DROP TABLE IF EXISTS app_user;
DROP TABLE IF EXISTS tenant;
DROP TABLE IF EXISTS rule;
DROP TABLE IF EXISTS vulnerability_alias;
DROP TABLE IF EXISTS vulnerability;
DROP FUNCTION IF EXISTS current_tenant_id();

