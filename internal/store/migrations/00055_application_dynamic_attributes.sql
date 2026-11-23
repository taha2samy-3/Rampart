-- +goose Up
-- expand-safe: adds an attributes JSONB column with default '{}'::jsonb; existing queries and binaries ignore it and all rows remain valid
ALTER TABLE application
    ADD COLUMN IF NOT EXISTS attributes JSONB NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS idx_application_attributes ON application USING GIN (attributes);

-- +goose Down
DROP INDEX IF EXISTS idx_application_attributes;
ALTER TABLE application
    DROP COLUMN IF EXISTS attributes;
