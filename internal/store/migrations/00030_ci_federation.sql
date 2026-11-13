-- +goose Up
-- CI OIDC federation trust rules and token replay prevention (D22, Milestone 3.3).

CREATE TABLE source_trust (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    scan_source_id UUID NOT NULL REFERENCES scan_source(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    provider TEXT NOT NULL,
    repository_id TEXT,
    repository_owner_id TEXT,
    project_id TEXT,
    namespace_id TEXT,
    repository TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_source_trust_tenant ON source_trust (tenant_id, scan_source_id);
CREATE INDEX idx_source_trust_issuer ON source_trust (tenant_id, issuer);

ALTER TABLE source_trust ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_trust FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON source_trust
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON source_trust TO rampart_app, rampart_system;

CREATE TABLE federation_jti (
    issuer TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (issuer, jti)
);

CREATE INDEX idx_federation_jti_exp ON federation_jti (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON federation_jti TO rampart_app, rampart_system;

-- +goose Down
DROP TABLE IF EXISTS federation_jti;
DROP TABLE IF EXISTS source_trust;
