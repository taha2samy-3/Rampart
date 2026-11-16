-- +goose Up
-- Dependency-Track wired into the server (docs/16 D92, docs/23 K5, DT3, DT5, DT6).

-- A ScanSource of type apiPull names its Connector and carries its dependencyTrack block and schedule.
ALTER TABLE scan_source
    ADD COLUMN connector TEXT,
    ADD COLUMN dtrack_spec JSONB,
    ADD COLUMN schedule_seconds INT,
    ADD COLUMN last_portfolio_sync_at TIMESTAMPTZ,
    ADD COLUMN last_portfolio_error TEXT;
-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT ON scan_source TO rampart_system;
    GRANT UPDATE ON scan_source TO rampart_system;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- The DT webhook is addressed by the ScanSource's id and the caller is not signed in, so the request has no tenant.
-- As for connectors (D78), this policy shows exactly one row: the one named in app.webhook_scan_source_id, set only
-- for the lookup transaction. The tenant comes from the row, and the bearer secret is checked with that tenant's
-- secret before anything is acted on.
CREATE POLICY webhook_lookup ON scan_source FOR SELECT
    USING (id = nullif(current_setting('app.webhook_scan_source_id', true), '')::uuid);

-- A sync whose worker died leaves 'syncing'; the enqueue treats a row older than this as idle (see the store).
CREATE INDEX IF NOT EXISTS idx_dtrack_sync_updated ON dtrack_sync (updated_at);

-- DT5: the analysis Dependency-Track carries on a finding. Without trustUpstreamDecisions it is a request a person
-- decides on (applied = false); with it, it is applied as a triage decision and recorded as applied.
CREATE TABLE dtrack_decision (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    source_id UUID NOT NULL REFERENCES scan_source(id) ON DELETE CASCADE,
    state TEXT NOT NULL,
    justification TEXT,
    detail TEXT,
    applied BOOLEAN NOT NULL DEFAULT FALSE,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, finding_id)
);
CREATE INDEX idx_dtrack_decision_pending ON dtrack_decision (tenant_id, source_id) WHERE NOT applied;
ALTER TABLE dtrack_decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE dtrack_decision FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON dtrack_decision
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON dtrack_decision TO rampart_app, rampart_system;
    GRANT SELECT ON dtrack_decision TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS dtrack_decision;
DROP INDEX IF EXISTS idx_dtrack_sync_updated;
DROP POLICY IF EXISTS webhook_lookup ON scan_source;
ALTER TABLE scan_source
    DROP COLUMN IF EXISTS last_portfolio_error,
    DROP COLUMN IF EXISTS last_portfolio_sync_at,
    DROP COLUMN IF EXISTS schedule_seconds,
    DROP COLUMN IF EXISTS dtrack_spec,
    DROP COLUMN IF EXISTS connector;
