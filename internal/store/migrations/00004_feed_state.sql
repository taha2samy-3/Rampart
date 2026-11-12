-- +goose Up
-- Feed state (docs/12): tracking synchronization state of threat intelligence feeds (KEV, EPSS, OSV).
CREATE TABLE IF NOT EXISTS feed_state (
    feed TEXT PRIMARY KEY,
    cursor TEXT,
    last_sync TIMESTAMPTZ,
    records BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'idle',
    error TEXT
);

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON feed_state TO rampart_system;
    GRANT SELECT ON feed_state TO rampart_app, rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS feed_state;

