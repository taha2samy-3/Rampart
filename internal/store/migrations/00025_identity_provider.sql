-- +goose Up
-- Identity providers (docs/04 IdentityProvider, ClusterIdentityProvider; docs/14, docs/16 D8, D27, D64).
-- Supports both tenant-scoped IdentityProvider and platform-wide ClusterIdentityProvider.
CREATE TABLE identity_provider (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenant(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT 'oidc' CHECK (type IN ('oidc', 'saml')),
    allowed_tenants TEXT[] NOT NULL DEFAULT '{}',
    spec JSONB NOT NULL DEFAULT '{}',
    status JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique per tenant for namespaced IdentityProvider
CREATE UNIQUE INDEX idx_identity_provider_tenant_name ON identity_provider (tenant_id, name) WHERE tenant_id IS NOT NULL;

-- Unique by name for cluster-wide ClusterIdentityProvider
CREATE UNIQUE INDEX idx_cluster_identity_provider_name ON identity_provider (name) WHERE tenant_id IS NULL;

-- Multi-tenant isolation (docs/04, docs/14, docs/16 D8, D27)
ALTER TABLE identity_provider ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_provider FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity_provider
    USING (tenant_id = current_tenant_id() OR tenant_id IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR tenant_id IS NULL);

-- Grants
-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT ON identity_provider TO rampart_app, rampart_ro;
    GRANT SELECT, INSERT, UPDATE, DELETE ON identity_provider TO rampart_system;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP POLICY IF EXISTS tenant_isolation ON identity_provider;
DROP TABLE IF EXISTS identity_provider;

