-- +goose Up
-- Connectors (docs/04 Connector, docs/16 D69, docs/20 Milestone 3.1).
-- Connectors configure outbound trackers (Jira, GitHub), notifiers (Slack, Teams, email, webhook) and upstream sources (Dependency-Track).
CREATE TABLE connector (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    spec JSONB NOT NULL DEFAULT '{}',
    status JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique per tenant for namespaced Connector
CREATE UNIQUE INDEX idx_connector_tenant_name ON connector (tenant_id, name);

-- Lookup by connector type
CREATE INDEX idx_connector_tenant_type ON connector (tenant_id, type);

-- Multi-tenant isolation (ADR 0005, docs/16 D69)
ALTER TABLE connector ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON connector
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- Grants
-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT ON connector TO rampart_app, rampart_ro;
    GRANT SELECT, INSERT, UPDATE, DELETE ON connector TO rampart_system;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP POLICY IF EXISTS tenant_isolation ON connector;
DROP TABLE IF EXISTS connector;

