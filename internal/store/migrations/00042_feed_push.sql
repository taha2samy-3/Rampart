-- +goose Up
-- Feed plugins that push (docs/16 D89, D94). A plugin posts its file to POST /api/v1/feeds/{name}; the API checks
-- the token and the whole file, and stages it here. Only the feed syncer, as the system role, loads it into the
-- global intelligence tables (D19): the API never writes them. One row per feed: a new push replaces the last.
CREATE TABLE feed_push (
    feed TEXT PRIMARY KEY,
    body BYTEA NOT NULL,
    sha256 TEXT NOT NULL,
    records INT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE ON feed_push TO rampart_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON feed_push TO rampart_system;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS feed_push;
