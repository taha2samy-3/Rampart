-- +goose Up
-- Inbound webhooks are addressed by the connector's own id, /hooks/{type}/{connectorId} (docs/16 D78). The caller is
-- not signed in, so the request has no tenant, and row-level security hides every connector row from the application
-- role. This policy shows exactly one row: the one whose id the handler names in app.webhook_connector_id, set only
-- for the lookup transaction. The id is a random UUIDv7 nobody can list; the tenant comes from the row, never from
-- the path, and the signature is checked with that tenant's secret before anything is acted on.
CREATE POLICY webhook_lookup ON connector FOR SELECT
    USING (id = nullif(current_setting('app.webhook_connector_id', true), '')::uuid);

-- +goose Down
DROP POLICY IF EXISTS webhook_lookup ON connector;
