-- +goose Up
-- In-app notifications (docs/16 D45): what the deadline and expiry sweeps tell the people of a tenant. A row is
-- visible to the whole tenant; what each user has read is one timestamp per user, so "mark all read" is one write.
CREATE TABLE notification (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    link TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_notification_tenant_created ON notification (tenant_id, created_at DESC);

CREATE TABLE notification_marker (
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    user_ref TEXT NOT NULL,
    read_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, user_ref)
);

-- A warning goes out once: the finding remembers that it was warned about its deadline, and an acceptance
-- remembers the smallest "days left" threshold already announced (14, then 1).
ALTER TABLE finding ADD COLUMN IF NOT EXISTS sla_warned_at TIMESTAMPTZ;
ALTER TABLE risk_acceptance ADD COLUMN IF NOT EXISTS expiry_warned_days INT;

ALTER TABLE notification ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notification
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE notification_marker ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_marker FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notification_marker
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON notification, notification_marker TO rampart_app, rampart_system;
    GRANT SELECT ON notification, notification_marker TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
ALTER TABLE risk_acceptance DROP COLUMN IF EXISTS expiry_warned_days;
ALTER TABLE finding DROP COLUMN IF EXISTS sla_warned_at;
DROP TABLE IF EXISTS notification_marker;
DROP TABLE IF EXISTS notification;
