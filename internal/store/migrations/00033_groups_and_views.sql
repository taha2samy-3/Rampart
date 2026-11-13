-- +goose Up
-- Groups and Saved Views: finding groups, correlation groups, and saved views (docs/21 §6).

CREATE TABLE finding_group (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    owner TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_finding_group_tenant ON finding_group (tenant_id, name);

ALTER TABLE finding_group ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_group FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON finding_group
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON finding_group TO rampart_app, rampart_system;

CREATE TABLE finding_group_member (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES finding_group(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, group_id, finding_id)
);

CREATE INDEX idx_finding_group_member ON finding_group_member (tenant_id, finding_id);

ALTER TABLE finding_group_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_group_member FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON finding_group_member
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON finding_group_member TO rampart_app, rampart_system;

CREATE TABLE saved_view (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    query TEXT NOT NULL,
    sort TEXT,
    scope TEXT NOT NULL DEFAULT 'tenant',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_saved_view_tenant ON saved_view (tenant_id, owner, scope);

ALTER TABLE saved_view ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_view FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON saved_view
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON saved_view TO rampart_app, rampart_system;

-- +goose Down
DROP TABLE IF EXISTS saved_view;
DROP TABLE IF EXISTS finding_group_member;
DROP TABLE IF EXISTS finding_group;
