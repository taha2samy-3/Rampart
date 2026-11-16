-- +goose Up
-- Compliance evidence that is not a finding (docs/16 D102).
--
-- compliance_attestation: a person's statement about a control no scan can read ("a threat model is reviewed for each
-- release"). It is evidence an auditor reads, so it is kept: the application role may add one, never change or remove
-- it. The newest one in force is the control's reading; an expired one reads "not assessed".
CREATE TABLE compliance_attestation (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    framework_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    application_id UUID REFERENCES application(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('passed', 'failed')),
    note TEXT NOT NULL CHECK (length(note) BETWEEN 1 AND 4000),
    evidence_url TEXT NOT NULL DEFAULT '',
    attested_by TEXT NOT NULL,
    attested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_compliance_attestation_control ON compliance_attestation (tenant_id, framework_id, control_id, attested_at DESC);

-- compliance_snapshot: one reading of a framework for a tenant per day, so "what did control 6.3.3 read on 30 June"
-- has an answer. The whole reading is kept as it was shown.
CREATE TABLE compliance_snapshot (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    framework_id TEXT NOT NULL,
    day DATE NOT NULL,
    reading JSONB NOT NULL,
    taken_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, framework_id, day)
);

ALTER TABLE compliance_attestation ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_attestation FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON compliance_attestation
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE compliance_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_snapshot FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON compliance_snapshot
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT ON compliance_attestation TO rampart_app;
    GRANT SELECT, INSERT, DELETE ON compliance_attestation TO rampart_system;
    GRANT SELECT, INSERT, UPDATE ON compliance_snapshot TO rampart_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_snapshot TO rampart_system;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS compliance_snapshot;
DROP TABLE IF EXISTS compliance_attestation;
