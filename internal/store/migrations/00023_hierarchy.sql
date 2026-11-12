-- +goose Up
-- Hierarchy (docs/01 B1, docs/03, docs/12): business units, teams and portfolios as an N-level tree.
CREATE TABLE IF NOT EXISTS hierarchy_node (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES hierarchy_node(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    path TEXT NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, path)
);

ALTER TABLE hierarchy_node ENABLE ROW LEVEL SECURITY;
ALTER TABLE hierarchy_node FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON hierarchy_node
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE INDEX IF NOT EXISTS idx_hierarchy_node_tenant_path ON hierarchy_node (tenant_id, path);

ALTER TABLE application ADD COLUMN IF NOT EXISTS hierarchy_path TEXT;

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON hierarchy_node TO rampart_app, rampart_system;
    GRANT SELECT ON hierarchy_node TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
ALTER TABLE application DROP COLUMN IF EXISTS hierarchy_path;
DROP TABLE IF EXISTS hierarchy_node CASCADE;

