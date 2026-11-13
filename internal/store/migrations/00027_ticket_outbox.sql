-- +goose Up
-- The ticket outbox (docs/16 D70). A critical finding reserves its ticket in action_ledger inside the merge
-- transaction, and nothing else: the call to the tracker is made afterwards, by a sweeper, so a slow Jira cannot
-- hold the transaction open and a failed call can be tried again. The row says where the ticket stands, and keeps
-- the ticket that was opened: that record, not a label someone can type on a ticket, is what ties a ticket to a
-- finding when a webhook comes back.
ALTER TABLE action_ledger
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'done' CHECK (status IN ('reserved', 'done', 'failed', 'skipped')),
    ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS result JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS last_error TEXT,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
-- The rows that existed were placeholders: nothing was ever opened for them, and nothing will be.
UPDATE action_ledger SET status = 'skipped', last_error = 'reserved before the outbox existed' WHERE status = 'done' AND result = '{}'::jsonb;
CREATE INDEX IF NOT EXISTS idx_action_ledger_pending ON action_ledger (next_attempt_at) WHERE status = 'reserved';
CREATE INDEX IF NOT EXISTS idx_action_ledger_ticket ON action_ledger (tenant_id, finding_id) WHERE status = 'done';

-- +goose Down
DROP INDEX IF EXISTS idx_action_ledger_ticket;
DROP INDEX IF EXISTS idx_action_ledger_pending;
ALTER TABLE action_ledger
    DROP COLUMN IF EXISTS updated_at, DROP COLUMN IF EXISTS last_error, DROP COLUMN IF EXISTS result,
    DROP COLUMN IF EXISTS next_attempt_at, DROP COLUMN IF EXISTS attempts, DROP COLUMN IF EXISTS status;
