-- +goose Up
-- Attestations (docs/16 D102, D123): who answers for keeping one current, and a note of which expiry reminders went out.
--
-- owner: the person or team that renews the attestation. Empty means the person who made it.
ALTER TABLE compliance_attestation ADD COLUMN owner TEXT NOT NULL DEFAULT '' CHECK (length(owner) <= 200);

-- One row per attestation that was announced as ending: the smallest threshold sent (14, then 1 day). The
-- attestations themselves stay append-only; this is the marker, as risk_acceptance.expiry_warned_days is for acceptances.
CREATE TABLE compliance_attestation_warning (
    attestation_id UUID PRIMARY KEY REFERENCES compliance_attestation(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    days INT NOT NULL CHECK (days IN (1, 14)),
    warned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE compliance_attestation_warning ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_attestation_warning FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON compliance_attestation_warning
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE ON compliance_attestation_warning TO rampart_app, rampart_system;
    GRANT DELETE ON compliance_attestation_warning TO rampart_system;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS compliance_attestation_warning;
ALTER TABLE compliance_attestation DROP COLUMN IF EXISTS owner;
