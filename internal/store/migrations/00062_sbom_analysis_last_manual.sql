-- +goose Up
-- docs/51 step 2.2, docs/39 D.2, AGENTS.md section 4: the 5-minute cooldown between manual analyses read the row's trigger, which
-- the next claim (an upload, the daily sweep) overwrote, so a manual check could follow another at once. The time of the last
-- manual claim is kept apart. Nullable: the old binary's INSERT still works.
ALTER TABLE sbom_analysis ADD COLUMN IF NOT EXISTS last_manual_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE sbom_analysis DROP COLUMN IF EXISTS last_manual_at;
