-- +goose Up
-- Retention (docs/01 H7, docs/04 RetentionPolicy, docs/16 D53).
--
-- A run remembers whether its report held secrets, so its raw report can be removed sooner (docs/07: secret
-- scanner reports default to 7 days), and when retention removed the report, so the run page can say so.
ALTER TABLE ingest_run ADD COLUMN IF NOT EXISTS holds_secrets BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ingest_run ADD COLUMN IF NOT EXISTS report_purged_at TIMESTAMPTZ;

-- The sweeps look for old rows of one tenant; each has an index that starts with the tenant.
CREATE INDEX IF NOT EXISTS idx_occurrence_absent ON occurrence (tenant_id, last_seen) WHERE NOT present;
CREATE INDEX IF NOT EXISTS idx_finding_resolved ON finding (tenant_id, resolved_at) WHERE state = 'fixed';
CREATE INDEX IF NOT EXISTS idx_upload_retention ON upload (tenant_id, created_at) WHERE status <> 'purged';
CREATE INDEX IF NOT EXISTS idx_ingest_run_result_created ON ingest_run_result (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ingest_run_upload ON ingest_run (tenant_id, upload_id);

-- +goose Down
DROP INDEX IF EXISTS idx_ingest_run_upload;
DROP INDEX IF EXISTS idx_ingest_run_result_created;
DROP INDEX IF EXISTS idx_upload_retention;
DROP INDEX IF EXISTS idx_finding_resolved;
DROP INDEX IF EXISTS idx_occurrence_absent;
ALTER TABLE ingest_run DROP COLUMN IF EXISTS report_purged_at;
ALTER TABLE ingest_run DROP COLUMN IF EXISTS holds_secrets;
