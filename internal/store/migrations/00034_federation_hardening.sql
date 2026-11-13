-- +goose Up
-- Hardening for CI OIDC federation (D22, Milestone 3.3).

CREATE UNIQUE INDEX IF NOT EXISTS idx_source_trust_unique ON source_trust (tenant_id, scan_source_id, issuer);

-- +goose Down
DROP INDEX IF EXISTS idx_source_trust_unique;
