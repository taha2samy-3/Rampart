-- +goose Up
-- An SBOM belongs to a track of an asset, not to the asset alone (docs/16 D114). The same repository built from main,
-- staging and production has three SBOMs; with one slot per asset the last upload replaced the others, and the
-- inventory showed whichever branch ran last. Existing rows keep the track "default".
ALTER TABLE sbom ADD COLUMN track TEXT NOT NULL DEFAULT 'default';
CREATE INDEX idx_sbom_asset_track ON sbom (tenant_id, asset_id, track, created_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_sbom_asset_track;
ALTER TABLE sbom DROP COLUMN IF EXISTS track;
