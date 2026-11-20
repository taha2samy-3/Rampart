-- +goose Up
-- Live updates for analyses and feeds (docs/39 Slice C, docs/16 D91).
-- expand-safe: widens a CHECK constraint to allow topic analysis; older binary never writes it
ALTER TABLE live_event DROP CONSTRAINT IF EXISTS live_event_topic_check;
ALTER TABLE live_event ADD CONSTRAINT live_event_topic_check CHECK (topic IN ('ingests', 'findings', 'operations', 'analysis'));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION live_event_analysis() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO live_event (tenant_id, topic, application_id)
    SELECT DISTINCT c.tenant_id, 'analysis', a.application_id FROM changed c
    JOIN sbom s ON s.id = c.sbom_id
    JOIN asset a ON a.id = s.asset_id
    WHERE NOT EXISTS (SELECT 1 FROM live_event l WHERE l.xact = pg_current_xact_id() AND l.tenant_id = c.tenant_id
        AND l.topic = 'analysis' AND l.application_id IS NOT DISTINCT FROM a.application_id);
    RETURN NULL;
END $$;
-- +goose StatementEnd

CREATE TRIGGER live_analysis_ins AFTER INSERT ON sbom_analysis REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_analysis();
CREATE TRIGGER live_analysis_upd AFTER UPDATE ON sbom_analysis REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_analysis();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION live_event_feeds() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO live_event (tenant_id, topic, application_id)
    SELECT t.id, 'analysis', NULL::uuid FROM tenant t
    WHERE NOT EXISTS (SELECT 1 FROM live_event l WHERE l.xact = pg_current_xact_id() AND l.tenant_id = t.id
        AND l.topic = 'analysis' AND l.application_id IS NULL);
    RETURN NULL;
END $$;
-- +goose StatementEnd

CREATE TRIGGER live_feed_ins AFTER INSERT ON feed_state REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_feeds();
CREATE TRIGGER live_feed_upd AFTER UPDATE ON feed_state REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION live_event_feeds();

-- +goose Down
DROP TRIGGER IF EXISTS live_feed_upd ON feed_state;
DROP TRIGGER IF EXISTS live_feed_ins ON feed_state;
DROP FUNCTION IF EXISTS live_event_feeds();
DROP TRIGGER IF EXISTS live_analysis_upd ON sbom_analysis;
DROP TRIGGER IF EXISTS live_analysis_ins ON sbom_analysis;
DROP FUNCTION IF EXISTS live_event_analysis();
ALTER TABLE live_event DROP CONSTRAINT IF EXISTS live_event_topic_check;
ALTER TABLE live_event ADD CONSTRAINT live_event_topic_check CHECK (topic IN ('ingests', 'findings', 'operations'));
