-- +goose Up
-- Proof files of a risk acceptance (docs/01 C5, docs/03, docs/16 D60). The file is in object storage under a
-- name the server chose; this row is what is shown. Proofs are evidence: the application role may add and read
-- them, never change or remove them.
CREATE TABLE risk_acceptance_proof (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    risk_acceptance_id UUID NOT NULL REFERENCES risk_acceptance(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    sha256 TEXT NOT NULL,
    object_ref TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ra_proof ON risk_acceptance_proof (tenant_id, risk_acceptance_id, uploaded_at);
ALTER TABLE risk_acceptance_proof ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_acceptance_proof FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON risk_acceptance_proof
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT ON risk_acceptance_proof TO rampart_app;
    GRANT SELECT, INSERT, DELETE ON risk_acceptance_proof TO rampart_system; -- tenant purge only
    GRANT SELECT ON risk_acceptance_proof TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS risk_acceptance_proof;
