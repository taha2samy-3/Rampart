-- +goose Up
-- Live updates (docs/16 D91, docs/23 S1). Writers never call the stream: statement-level triggers record which
-- application changed on which topic, and every query-api replica polls this table once for all its streams.
-- LISTEN/NOTIFY is not used: it needs a direct connection (D4) and does not pass through PgBouncer.

CREATE TABLE live_event (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    topic TEXT NOT NULL CHECK (topic IN ('ingests', 'findings', 'operations')),
    application_id UUID,
    at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    xact xid8 NOT NULL DEFAULT pg_current_xact_id()
);
CREATE INDEX idx_live_event_tenant ON live_event (tenant_id, id);
CREATE INDEX idx_live_event_xact ON live_event (xact);
CREATE INDEX idx_live_event_at ON live_event (at);

-- Not FORCE: a later migration run by the owner that updates findings fires the trigger with no tenant set, and
-- must not fail on this table's policy. The application and system roles are bound as everywhere else.
ALTER TABLE live_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON live_event
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT ON live_event TO rampart_app;
    GRANT SELECT, INSERT, DELETE ON live_event TO rampart_system;
    GRANT USAGE ON SEQUENCE live_event_id_seq TO rampart_app, rampart_system;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- One row per (tenant, topic, application) per transaction, however many rows or statements it touched: a merge
-- that upserts 100k findings one statement at a time writes one row per application, not 100k. Rows are coalesced
-- only within the writer's own transaction. Coalescing with another transaction's row would drop a change committed
-- after the client had already refetched for that row.
-- +goose StatementBegin
CREATE FUNCTION live_event_findings() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO live_event (tenant_id, topic, application_id)
    SELECT DISTINCT c.tenant_id, 'findings', c.application_id FROM changed c
    WHERE NOT EXISTS (SELECT 1 FROM live_event l WHERE l.xact = pg_current_xact_id() AND l.tenant_id = c.tenant_id
        AND l.topic = 'findings' AND l.application_id IS NOT DISTINCT FROM c.application_id);
    RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION live_event_ingests() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO live_event (tenant_id, topic, application_id)
    SELECT DISTINCT c.tenant_id, 'ingests', c.application_id FROM changed c
    WHERE NOT EXISTS (SELECT 1 FROM live_event l WHERE l.xact = pg_current_xact_id() AND l.tenant_id = c.tenant_id
        AND l.topic = 'ingests' AND l.application_id IS NOT DISTINCT FROM c.application_id);
    RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION live_event_operations() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO live_event (tenant_id, topic, application_id)
    SELECT DISTINCT c.tenant_id, 'operations', NULL::uuid FROM changed c
    WHERE NOT EXISTS (SELECT 1 FROM live_event l WHERE l.xact = pg_current_xact_id() AND l.tenant_id = c.tenant_id
        AND l.topic = 'operations' AND l.application_id IS NOT DISTINCT FROM NULL::uuid);
    RETURN NULL;
END $$;
-- +goose StatementEnd

CREATE TRIGGER live_finding_ins AFTER INSERT ON finding REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_findings();
CREATE TRIGGER live_finding_upd AFTER UPDATE ON finding REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_findings();

CREATE TRIGGER live_ingest_ins AFTER INSERT ON ingest_run REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_ingests();
CREATE TRIGGER live_ingest_upd AFTER UPDATE ON ingest_run REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_ingests();

CREATE TRIGGER live_held_close_ins AFTER INSERT ON held_close REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_operations();
CREATE TRIGGER live_held_close_upd AFTER UPDATE ON held_close REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_operations();
CREATE TRIGGER live_acceptance_ins AFTER INSERT ON risk_acceptance REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_operations();
CREATE TRIGGER live_acceptance_upd AFTER UPDATE ON risk_acceptance REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_operations();
CREATE TRIGGER live_notification_ins AFTER INSERT ON notification REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_operations();
CREATE TRIGGER live_group_upd AFTER UPDATE ON finding_group REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_operations();

-- +goose Down
DROP TRIGGER IF EXISTS live_group_upd ON finding_group;
DROP TRIGGER IF EXISTS live_notification_ins ON notification;
DROP TRIGGER IF EXISTS live_acceptance_upd ON risk_acceptance;
DROP TRIGGER IF EXISTS live_acceptance_ins ON risk_acceptance;
DROP TRIGGER IF EXISTS live_held_close_upd ON held_close;
DROP TRIGGER IF EXISTS live_held_close_ins ON held_close;
DROP TRIGGER IF EXISTS live_ingest_upd ON ingest_run;
DROP TRIGGER IF EXISTS live_ingest_ins ON ingest_run;
DROP TRIGGER IF EXISTS live_finding_upd ON finding;
DROP TRIGGER IF EXISTS live_finding_ins ON finding;
DROP FUNCTION IF EXISTS live_event_operations();
DROP FUNCTION IF EXISTS live_event_ingests();
DROP FUNCTION IF EXISTS live_event_findings();
DROP TABLE IF EXISTS live_event;
