-- +goose Up
-- A renewal ticket for an attestation that is about to end (docs/16 D124): the outbox, as for groups (D90).
-- Expand-only, like every migration from 46 on (D124): a new table, nothing an older binary reads is changed.
CREATE TABLE attestation_ticket (
    attestation_id UUID PRIMARY KEY REFERENCES compliance_attestation(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'reserved' CHECK (status IN ('reserved', 'opened', 'closed', 'failed')),
    connector TEXT NOT NULL DEFAULT '',
    ticket_ref TEXT NOT NULL DEFAULT '',
    ticket_url TEXT NOT NULL DEFAULT '',
    attempts INT NOT NULL DEFAULT 0,
    next_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_attestation_ticket_status ON attestation_ticket (status, next_at);
ALTER TABLE attestation_ticket ENABLE ROW LEVEL SECURITY;
ALTER TABLE attestation_ticket FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON attestation_ticket
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- The ticket sweeper looks first at the attestations that end soon; the table only grows.
CREATE INDEX idx_compliance_attestation_expiry ON compliance_attestation (expires_at) WHERE status = 'passed';

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT ON attestation_ticket TO rampart_app, rampart_ro;
    GRANT SELECT, INSERT, UPDATE, DELETE ON attestation_ticket TO rampart_system;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP INDEX IF EXISTS idx_compliance_attestation_expiry;
DROP TABLE IF EXISTS attestation_ticket;
