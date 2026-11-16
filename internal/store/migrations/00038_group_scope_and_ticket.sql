-- +goose Up
-- Finding groups belong to an application, and a group can be tracked by one outbound ticket (docs/16 D90, docs/23 C8).

-- A group with no application is tenant-wide; only an admin may create one (enforced by the API).
ALTER TABLE finding_group ADD COLUMN application_id UUID REFERENCES application(id) ON DELETE CASCADE;
CREATE INDEX idx_finding_group_app ON finding_group (tenant_id, application_id);

-- The group's ticket reservation: the API reserves it, the ticket sweeper opens it (D70: no tracker call inside a request).
ALTER TABLE finding_group
    ADD COLUMN ticket_status TEXT CHECK (ticket_status IN ('reserved', 'done', 'failed')),
    ADD COLUMN ticket_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN ticket_next_at TIMESTAMPTZ,
    ADD COLUMN ticket_error TEXT,
    ADD COLUMN ticket_requested_by TEXT,
    ADD COLUMN ticket_id UUID REFERENCES ticket(id) ON DELETE SET NULL;
CREATE INDEX idx_finding_group_ticket_due ON finding_group (ticket_next_at) WHERE ticket_status = 'reserved';

-- One ticket per correlation group: the sweeper looks up an open ticket of the same key in the same application.
CREATE INDEX IF NOT EXISTS idx_finding_correlation ON finding (tenant_id, application_id, correlation_key) WHERE correlation_key IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_finding_correlation;
DROP INDEX IF EXISTS idx_finding_group_ticket_due;
ALTER TABLE finding_group
    DROP COLUMN IF EXISTS ticket_id,
    DROP COLUMN IF EXISTS ticket_requested_by,
    DROP COLUMN IF EXISTS ticket_error,
    DROP COLUMN IF EXISTS ticket_next_at,
    DROP COLUMN IF EXISTS ticket_attempts,
    DROP COLUMN IF EXISTS ticket_status;
DROP INDEX IF EXISTS idx_finding_group_app;
ALTER TABLE finding_group DROP COLUMN IF EXISTS application_id;
