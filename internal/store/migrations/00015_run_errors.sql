-- +goose Up
-- The records of a report that could not be read (docs/13: errors with line references; docs/16 D13, D51). A
-- run keeps the first hundred: where the record is in the report and why it was refused, never its content.
CREATE TABLE ingest_run_error (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    ingest_run_id UUID NOT NULL REFERENCES ingest_run(id) ON DELETE CASCADE,
    n INT NOT NULL,
    location TEXT NOT NULL,
    message TEXT NOT NULL,
    PRIMARY KEY (ingest_run_id, n)
);
ALTER TABLE ingest_run_error ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingest_run_error FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ingest_run_error
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON ingest_run_error TO rampart_app, rampart_system;
    GRANT SELECT ON ingest_run_error TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS ingest_run_error;
