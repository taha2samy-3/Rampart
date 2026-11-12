-- +goose Up
-- The same issue on other tracks of an asset (docs/16 D57): the finding key with the track left out, so a
-- not_affected or out_of_scope decision made on main reaches a finding created on release/1.x.
ALTER TABLE finding ADD COLUMN IF NOT EXISTS lineage_key TEXT;
CREATE INDEX IF NOT EXISTS idx_finding_lineage ON finding (tenant_id, asset_id, lineage_key) WHERE lineage_key IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_finding_lineage;
ALTER TABLE finding DROP COLUMN IF EXISTS lineage_key;
