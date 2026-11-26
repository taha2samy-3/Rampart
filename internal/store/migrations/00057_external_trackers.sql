-- +goose Up
-- expand-safe: widens the kind CHECKs of cluster_policy and policy_object (the old binary never writes the new kind) and adds a new table.
-- Widens cluster_policy and policy_object kind constraints to allow 'external_tracker' and creates RLS-protected tracker_event.
ALTER TABLE cluster_policy DROP CONSTRAINT IF EXISTS cluster_policy_kind_check;
ALTER TABLE cluster_policy ADD CONSTRAINT cluster_policy_kind_check CHECK (kind IN ('risk', 'sla', 'feeds', 'compliance', 'parser', 'external_analyzer', 'sbom_analyzer', 'external_tracker'));

ALTER TABLE policy_object DROP CONSTRAINT IF EXISTS policy_object_kind_check;
ALTER TABLE policy_object ADD CONSTRAINT policy_object_kind_check CHECK (kind IN ('sla', 'risk', 'compliance', 'parser', 'external_analyzer', 'sbom_analyzer', 'external_tracker'));

-- Health probes and connection check events per tracker container & tenant. Bounded to the newest 200 per tracker.
CREATE TABLE tracker_event (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    tracker_scope TEXT NOT NULL CHECK (tracker_scope IN ('cluster', 'tenant')),
    tracker_namespace TEXT NOT NULL DEFAULT '',
    tracker_name TEXT NOT NULL,
    event TEXT NOT NULL CHECK (event IN ('test', 'check')),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
    message TEXT NOT NULL DEFAULT '',
    detail JSONB NOT NULL DEFAULT '{}',
    duration_ms INT NOT NULL DEFAULT 0,
    actor TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_tracker_event_lookup ON tracker_event (tenant_id, tracker_scope, tracker_namespace, tracker_name, created_at DESC);
ALTER TABLE tracker_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE tracker_event FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tracker_event
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, DELETE ON tracker_event TO rampart_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON tracker_event TO rampart_system;
    GRANT SELECT ON tracker_event TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS tracker_event;
DELETE FROM cluster_policy WHERE kind = 'external_tracker';
ALTER TABLE cluster_policy DROP CONSTRAINT IF EXISTS cluster_policy_kind_check;
ALTER TABLE cluster_policy ADD CONSTRAINT cluster_policy_kind_check CHECK (kind IN ('risk', 'sla', 'feeds', 'compliance', 'parser', 'external_analyzer', 'sbom_analyzer'));

DELETE FROM policy_object WHERE kind = 'external_tracker';
ALTER TABLE policy_object DROP CONSTRAINT IF EXISTS policy_object_kind_check;
ALTER TABLE policy_object ADD CONSTRAINT policy_object_kind_check CHECK (kind IN ('sla', 'risk', 'compliance', 'parser', 'external_analyzer', 'sbom_analyzer'));
