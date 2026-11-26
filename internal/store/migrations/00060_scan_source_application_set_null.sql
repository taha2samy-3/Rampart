-- +goose Up
-- expand-safe: replaces the foreign key added by 00056 with the same columns and ON DELETE SET NULL; no binary depends on the cascade.
-- docs/51 step 2.10, D21, D49: 00056 made scan_source.application_id ON DELETE CASCADE. Chained with
-- ingest_run.scan_source_id ON DELETE CASCADE (00001), deleting an application erased its sources and their ingest history,
-- which D21 keeps. A source whose application is gone falls back to its default application, as the reads already do
-- (COALESCE(application_id, default_application_id)).
ALTER TABLE scan_source DROP CONSTRAINT IF EXISTS scan_source_application_id_fkey;
ALTER TABLE scan_source ADD CONSTRAINT scan_source_application_id_fkey
    FOREIGN KEY (application_id) REFERENCES application(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE scan_source DROP CONSTRAINT IF EXISTS scan_source_application_id_fkey;
ALTER TABLE scan_source ADD CONSTRAINT scan_source_application_id_fkey
    FOREIGN KEY (application_id) REFERENCES application(id) ON DELETE CASCADE;
