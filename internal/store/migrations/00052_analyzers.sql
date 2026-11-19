-- +goose Up
-- expand-safe: only widens two CHECK constraints to allow the kinds 'external_analyzer' and 'sbom_analyzer' (the old binary never writes them and every
-- value it writes stays valid), and adds a table that nothing older reads.
-- Analyzers (docs/16 D142, D143): a ClusterExternalAnalyzer or ClusterSBOMAnalyzer is kept in cluster_policy, an ExternalAnalyzer or SBOMAnalyzer
-- in policy_object, with the last-valid-spec semantics of every other policy (D41).
ALTER TABLE cluster_policy DROP CONSTRAINT IF EXISTS cluster_policy_kind_check;
ALTER TABLE cluster_policy ADD CONSTRAINT cluster_policy_kind_check CHECK (kind IN ('risk', 'sla', 'feeds', 'compliance', 'parser', 'external_analyzer', 'sbom_analyzer'));

ALTER TABLE policy_object DROP CONSTRAINT IF EXISTS policy_object_kind_check;
ALTER TABLE policy_object ADD CONSTRAINT policy_object_kind_check CHECK (kind IN ('sla', 'risk', 'compliance', 'parser', 'external_analyzer', 'sbom_analyzer'));

-- What happened to an analyzer: a test someone ran, and, when analyses run, each analysis. The answer to "is it working". An event belongs to the
-- tenant that caused it, also for a cluster analyzer, so one tenant never reads another's activity. The table is bounded by the store: only the newest
-- 200 events of an analyzer are kept.
CREATE TABLE analyzer_event (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    analyzer_kind TEXT NOT NULL CHECK (analyzer_kind IN ('external', 'sbom')),
    analyzer_scope TEXT NOT NULL CHECK (analyzer_scope IN ('cluster', 'tenant')),
    analyzer_namespace TEXT NOT NULL DEFAULT '',
    analyzer_name TEXT NOT NULL,
    event TEXT NOT NULL CHECK (event IN ('test', 'analysis')),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
    message TEXT NOT NULL DEFAULT '',
    detail JSONB NOT NULL DEFAULT '{}',
    duration_ms INT NOT NULL DEFAULT 0,
    actor TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_analyzer_event_lookup ON analyzer_event (tenant_id, analyzer_kind, analyzer_scope, analyzer_namespace, analyzer_name, created_at DESC);
ALTER TABLE analyzer_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyzer_event FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON analyzer_event
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, DELETE ON analyzer_event TO rampart_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON analyzer_event TO rampart_system;
    GRANT SELECT ON analyzer_event TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS analyzer_event;
DELETE FROM cluster_policy WHERE kind IN ('external_analyzer', 'sbom_analyzer');
ALTER TABLE cluster_policy DROP CONSTRAINT IF EXISTS cluster_policy_kind_check;
ALTER TABLE cluster_policy ADD CONSTRAINT cluster_policy_kind_check CHECK (kind IN ('risk', 'sla', 'feeds', 'compliance', 'parser'));

DELETE FROM policy_object WHERE kind IN ('external_analyzer', 'sbom_analyzer');
ALTER TABLE policy_object DROP CONSTRAINT IF EXISTS policy_object_kind_check;
ALTER TABLE policy_object ADD CONSTRAINT policy_object_kind_check CHECK (kind IN ('sla', 'risk', 'compliance', 'parser'));
