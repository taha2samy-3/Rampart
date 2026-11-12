-- +goose Up
-- Risk acceptance (docs/06 section 6, docs/16 D39): a time-boxed decision, with an owner, a requester, an
-- approver when the tenant requires one, and an expiry. A finding accepted through it carries risk_acceptance_id.
CREATE TABLE risk_acceptance (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    decision TEXT NOT NULL DEFAULT 'accept' CHECK (decision IN ('accept')),
    justification TEXT NOT NULL,
    impact_statement TEXT,
    owner TEXT NOT NULL,
    requester TEXT NOT NULL,
    approver TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'revoked')),
    expires_at TIMESTAMPTZ NOT NULL,
    on_expiry TEXT NOT NULL DEFAULT 'reactivate' CHECK (on_expiry IN ('reactivate', 'notify_only')),
    restart_sla_on_expiry BOOLEAN NOT NULL DEFAULT FALSE,
    decision_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ
);
CREATE INDEX idx_risk_acceptance_status ON risk_acceptance (tenant_id, status, expires_at);

CREATE TABLE risk_acceptance_finding (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    risk_acceptance_id UUID NOT NULL REFERENCES risk_acceptance(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL,
    PRIMARY KEY (risk_acceptance_id, finding_id)
);
CREATE INDEX idx_risk_acceptance_finding ON risk_acceptance_finding (tenant_id, finding_id);

ALTER TABLE finding ADD COLUMN IF NOT EXISTS risk_acceptance_id UUID;

ALTER TABLE risk_acceptance ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_acceptance FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON risk_acceptance
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE risk_acceptance_finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_acceptance_finding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON risk_acceptance_finding
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- The application role may not write `tenant` (D4), but a tenant admin sets tenant settings. This function
-- writes the settings column of the caller's own tenant and nothing else.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION set_tenant_settings(new_settings JSONB) RETURNS VOID AS $$
BEGIN
    IF current_tenant_id() IS NULL THEN
        RAISE EXCEPTION 'no tenant context';
    END IF;
    UPDATE tenant SET settings = new_settings WHERE id = current_tenant_id();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON risk_acceptance, risk_acceptance_finding TO rampart_app, rampart_system;
    GRANT SELECT ON risk_acceptance, risk_acceptance_finding TO rampart_ro;
    REVOKE ALL ON FUNCTION set_tenant_settings(JSONB) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION set_tenant_settings(JSONB) TO rampart_app, rampart_system;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS set_tenant_settings(JSONB);
ALTER TABLE finding DROP COLUMN IF EXISTS risk_acceptance_id;
DROP TABLE IF EXISTS risk_acceptance_finding;
DROP TABLE IF EXISTS risk_acceptance;
