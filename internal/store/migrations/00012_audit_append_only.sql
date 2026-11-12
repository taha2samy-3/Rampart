-- +goose Up
-- The audit log is append-only (docs/07, docs/16 D46): the application and system roles may add rows and read them,
-- never change or remove one. Old months leave by dropping a whole partition, as the owner (the retention job).
-- +goose StatementBegin
DO $$
DECLARE
    part TEXT;
BEGIN
    REVOKE UPDATE, DELETE, TRUNCATE ON audit_event FROM rampart_app, rampart_system, rampart_ro;
    FOR part IN SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
                WHERE i.inhparent = 'audit_event'::regclass LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM rampart_app, rampart_system, rampart_ro', part);
    END LOOP;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    GRANT UPDATE, DELETE ON audit_event TO rampart_app, rampart_system;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd
