-- +goose Up
-- Dependency-Track integration: sync tracking, debounce state, and project mappings (docs/10, docs/21 §4).

CREATE TABLE dtrack_sync (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    project_uuid TEXT NOT NULL,
    source_id UUID NOT NULL REFERENCES scan_source(id) ON DELETE CASCADE,
    state TEXT NOT NULL DEFAULT 'idle',
    dirty BOOLEAN NOT NULL DEFAULT FALSE,
    last_sync_at TIMESTAMPTZ,
    next_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, project_uuid)
);

CREATE INDEX idx_dtrack_sync_state ON dtrack_sync (tenant_id, state);

ALTER TABLE dtrack_sync ENABLE ROW LEVEL SECURITY;
ALTER TABLE dtrack_sync FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON dtrack_sync
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON dtrack_sync TO rampart_app, rampart_system;

CREATE TABLE dtrack_project (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    source_id UUID NOT NULL REFERENCES scan_source(id) ON DELETE CASCADE,
    project_uuid TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    purl TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    last_bom_import TIMESTAMPTZ,
    application_id UUID REFERENCES application(id) ON DELETE SET NULL,
    mapping_rule TEXT,
    unmapped_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, project_uuid)
);

CREATE INDEX idx_dtrack_project_tenant_app ON dtrack_project (tenant_id, application_id);

ALTER TABLE dtrack_project ENABLE ROW LEVEL SECURITY;
ALTER TABLE dtrack_project FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON dtrack_project
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON dtrack_project TO rampart_app, rampart_system;

-- +goose Down
DROP TABLE IF EXISTS dtrack_project;
DROP TABLE IF EXISTS dtrack_sync;

