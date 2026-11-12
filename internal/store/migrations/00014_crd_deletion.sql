-- +goose Up
-- Deleting a custom resource (docs/16 D21, D49). An application made from a resource says so, and keeps its rows
-- when the resource goes (managed_by = none: editable in the UI). A scan source whose resource is gone is
-- disabled, not deleted: its history stays, its tokens and secret material go.
ALTER TABLE application ADD COLUMN IF NOT EXISTS managed_by TEXT NOT NULL DEFAULT 'ui' CHECK (managed_by IN ('ui', 'crd', 'none'));
ALTER TABLE scan_source ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE scan_source DROP COLUMN IF EXISTS disabled_at;
ALTER TABLE application DROP COLUMN IF EXISTS managed_by;
