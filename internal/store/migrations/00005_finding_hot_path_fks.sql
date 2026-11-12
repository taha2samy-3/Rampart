-- +goose Up
-- docs/16 D36: the hot path of ingestion. Every row of `finding` paid three foreign-key checks, and the two
-- on asset and application (tables with forced row-level security) cost about half of the insert time in
-- PostgreSQL 16. Both ids are produced by the same transaction that writes the finding (asset and application
-- are resolved or created first), and nothing deletes assets or applications yet, so the application upholds
-- the invariant instead; the integrity test in internal/store checks it. The tenant key stays: it carries the
-- cascade that removes a tenant's data.
ALTER TABLE finding DROP CONSTRAINT IF EXISTS finding_asset_id_fkey;
ALTER TABLE finding DROP CONSTRAINT IF EXISTS finding_application_id_fkey;

-- +goose Down
ALTER TABLE finding ADD CONSTRAINT finding_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE CASCADE;
ALTER TABLE finding ADD CONSTRAINT finding_application_id_fkey FOREIGN KEY (application_id) REFERENCES application(id) ON DELETE CASCADE;
