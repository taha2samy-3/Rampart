-- +goose Up
-- Cluster-wide policies (docs/04 ClusterRiskPolicy, ClusterSLAPolicy; docs/06: resolved namespace first, then the
-- cluster default, then the built-in one; docs/16 D62). Written by the operator and `rampart apply` as
-- rampart_system; read by every tenant, so no row-level security, like the other global tables (D19).
CREATE TABLE cluster_policy (
    kind TEXT NOT NULL CHECK (kind IN ('risk', 'sla')),
    name TEXT NOT NULL,
    spec JSONB NOT NULL DEFAULT '{}',
    applied_spec JSONB,
    compiled_ok BOOLEAN NOT NULL DEFAULT FALSE,
    compile_error TEXT,
    generation BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (kind, name)
);

-- A tenant's RiskPolicy lives next to its SLAPolicy (D62).
ALTER TABLE policy_object DROP CONSTRAINT IF EXISTS policy_object_kind_check;
ALTER TABLE policy_object ADD CONSTRAINT policy_object_kind_check CHECK (kind IN ('sla', 'risk'));

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT ON cluster_policy TO rampart_app, rampart_ro;
    GRANT SELECT, INSERT, UPDATE, DELETE ON cluster_policy TO rampart_system;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS cluster_policy;
DELETE FROM policy_object WHERE kind = 'risk';
ALTER TABLE policy_object DROP CONSTRAINT IF EXISTS policy_object_kind_check;
ALTER TABLE policy_object ADD CONSTRAINT policy_object_kind_check CHECK (kind IN ('sla'));
