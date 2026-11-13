-- +goose Up
-- Rate limiting and quota tracking across replicas (Milestone 3.3, Section 3.4).

ALTER TABLE api_token ADD COLUMN IF NOT EXISTS rate_limit INT;
ALTER TABLE api_token ADD COLUMN IF NOT EXISTS quota BIGINT;

CREATE TABLE quota_usage (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    used BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, key, window_start)
);

CREATE INDEX idx_quota_usage_window ON quota_usage (window_start);

ALTER TABLE quota_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE quota_usage FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON quota_usage
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON quota_usage TO rampart_app, rampart_system;

-- +goose Down
DROP TABLE IF EXISTS quota_usage;
ALTER TABLE api_token DROP COLUMN IF EXISTS rate_limit;
ALTER TABLE api_token DROP COLUMN IF EXISTS quota;
