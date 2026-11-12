-- +goose Up
-- Compensating controls on an application (docs/03, docs/06 section 2, docs/16 D55). data_classification and
-- owners existed but were never written; D55 writes them.
ALTER TABLE application ADD COLUMN IF NOT EXISTS compensating_controls TEXT[] NOT NULL DEFAULT '{}';

-- Nothing in the UI or the API creates an application yet; every row marked 'ui' was made by ingest (the
-- Unassigned application, or one named by the upload context). Such a row is unmanaged ('none'), so a resource of
-- the same name adopts it (D49) instead of being ignored. New rows from ingest are 'none' as well.
UPDATE application SET managed_by = 'none' WHERE managed_by = 'ui';
ALTER TABLE application ALTER COLUMN managed_by SET DEFAULT 'none';

-- +goose Down
ALTER TABLE application ALTER COLUMN managed_by SET DEFAULT 'ui';
ALTER TABLE application DROP COLUMN IF EXISTS compensating_controls;
