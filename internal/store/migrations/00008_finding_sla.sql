-- +goose Up
-- SLA and stored risk (docs/06 sections 2 and 4, docs/16 D28, D40). risk_score, risk_band, kev, epss_bucket and
-- sla_due_date already exist; the SLA clock needs its start, the moment it was breached and the moment it was paused.
ALTER TABLE finding ADD COLUMN IF NOT EXISTS sla_start TIMESTAMPTZ;
ALTER TABLE finding ADD COLUMN IF NOT EXISTS sla_breached_at TIMESTAMPTZ;
ALTER TABLE finding ADD COLUMN IF NOT EXISTS sla_paused_at TIMESTAMPTZ;
-- The breach sweep looks for active, unpaused findings past their due date (docs/12).
CREATE INDEX IF NOT EXISTS idx_finding_sla_due ON finding (tenant_id, sla_due_date)
    WHERE sla_due_date IS NOT NULL AND sla_breached_at IS NULL AND sla_paused_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_finding_sla_due;
ALTER TABLE finding DROP COLUMN IF EXISTS sla_paused_at;
ALTER TABLE finding DROP COLUMN IF EXISTS sla_breached_at;
ALTER TABLE finding DROP COLUMN IF EXISTS sla_start;
