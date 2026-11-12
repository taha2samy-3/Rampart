-- +goose Up
-- Policy objects (docs/12, docs/04, docs/16 D41): the SLAPolicy of a tenant, written by the operator from its CRD.
-- Keyed by (tenant, kind, namespace, name) as D21 says. A spec that did not pass validation is kept with the
-- reason, so the status can say why it is not applied.
CREATE TABLE policy_object (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('sla')),
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    spec JSONB NOT NULL DEFAULT '{}',
    -- The last spec that passed validation: the one in force. An edit that fails validation changes `spec` and
    -- `compile_error`, never this, so a typo cannot silently put the tenant back on the built-in policy.
    applied_spec JSONB,
    compiled_ok BOOLEAN NOT NULL DEFAULT TRUE,
    compile_error TEXT,
    generation BIGINT NOT NULL DEFAULT 0,
    -- Set when the spec changed: every finding's due date is recomputed, then it is cleared.
    recompute_needed BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, kind, namespace, name)
);
ALTER TABLE policy_object ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_object FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON policy_object
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose StatementBegin
DO $$
BEGIN
    -- The operator (rampart_system) writes policies; the application reads them, and clears the recompute flag.
    GRANT SELECT, INSERT, UPDATE, DELETE ON policy_object TO rampart_system;
    GRANT SELECT, UPDATE ON policy_object TO rampart_app;
    GRANT SELECT ON policy_object TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS policy_object;
