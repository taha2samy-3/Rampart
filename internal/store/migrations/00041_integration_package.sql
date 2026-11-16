-- +goose Up
-- Tier-1 integrations installed as data (docs/19 §6, docs/16 D94). A tenant admin applies an IntegrationPackage in a
-- tenant namespace; the operator validates it and stores it here; the router builds notifiers from it.
CREATE TABLE integration_package (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    runtime TEXT NOT NULL,
    version TEXT NOT NULL,
    spec JSONB NOT NULL,
    error TEXT,
    generation BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, name)
);
ALTER TABLE integration_package ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_package FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON integration_package
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON integration_package TO rampart_app, rampart_system;
    GRANT SELECT ON integration_package TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS integration_package;
