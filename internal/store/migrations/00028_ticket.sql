-- +goose Up
-- The ticket table (docs/16 D70 B1, docs/21 Section 1.1).
-- Replaces the action_ledger result column with dedicated ticket and ticket_finding tables
-- supporting multiple trackers per finding, finding groups, state management, and two-way sync.
CREATE TABLE ticket (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    connector TEXT NOT NULL,
    external_ref TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_ticket_tenant_connector_ref ON ticket (tenant_id, connector, external_ref);
CREATE INDEX idx_ticket_tenant_ref ON ticket (tenant_id, external_ref);

CREATE TABLE ticket_finding (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    ticket_id UUID NOT NULL REFERENCES ticket(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    PRIMARY KEY (tenant_id, ticket_id, finding_id)
);

CREATE INDEX idx_ticket_finding_finding ON ticket_finding (tenant_id, finding_id);

-- Shared delivery cache across replicas (D70 B8)
CREATE TABLE webhook_delivery (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    connector TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, connector, delivery_id)
);

CREATE INDEX idx_webhook_delivery_expires ON webhook_delivery (expires_at);

-- Row-level security (ADR 0005, docs/16 D69, D70)
ALTER TABLE ticket ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ticket
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE ticket_finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket_finding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ticket_finding
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE webhook_delivery ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_delivery FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON webhook_delivery
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- Grants
-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON ticket TO rampart_app, rampart_system;
    GRANT SELECT ON ticket TO rampart_ro;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ticket_finding TO rampart_app, rampart_system;
    GRANT SELECT ON ticket_finding TO rampart_ro;
    GRANT SELECT, INSERT, UPDATE, DELETE ON webhook_delivery TO rampart_app, rampart_system;
    GRANT SELECT ON webhook_delivery TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- Backfill from existing action_ledger rows (D70 B1)
INSERT INTO ticket (id, tenant_id, connector, external_ref, url, state, created_at, updated_at)
SELECT
    gen_random_uuid(),
    tenant_id,
    'tracker',
    result->>'ticket_id',
    COALESCE(result->>'url', ''),
    'open',
    updated_at,
    updated_at
FROM (
    SELECT DISTINCT ON (tenant_id, result->>'ticket_id')
        tenant_id, result, updated_at
    FROM action_ledger
    WHERE status = 'done' AND result ? 'ticket_id' AND (result->>'ticket_id') <> ''
    ORDER BY tenant_id, result->>'ticket_id', updated_at ASC
) sub
ON CONFLICT (tenant_id, connector, external_ref) DO NOTHING;

INSERT INTO ticket_finding (tenant_id, ticket_id, finding_id)
SELECT
    al.tenant_id,
    t.id,
    al.finding_id
FROM action_ledger al
JOIN ticket t ON t.tenant_id = al.tenant_id AND t.connector = 'tracker' AND t.external_ref = al.result->>'ticket_id'
WHERE al.status = 'done' AND al.result ? 'ticket_id' AND (al.result->>'ticket_id') <> ''
ON CONFLICT (tenant_id, ticket_id, finding_id) DO NOTHING;

-- +goose Down
DROP POLICY IF EXISTS tenant_isolation ON webhook_delivery;
DROP TABLE IF EXISTS webhook_delivery;
DROP POLICY IF EXISTS tenant_isolation ON ticket_finding;
DROP TABLE IF EXISTS ticket_finding;
DROP POLICY IF EXISTS tenant_isolation ON ticket;
DROP TABLE IF EXISTS ticket;
