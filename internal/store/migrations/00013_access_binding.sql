-- +goose Up
-- Access bindings (docs/07 section 2, docs/16 D48): a role on one application, for one person or token. The
-- tenant role (tenant_member, the OIDC bindings of the configuration) stays the floor; a binding raises it for
-- that application only. Subjects are matched by e-mail or by token subject, case-insensitively.
CREATE TABLE access_binding (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'triager', 'maintainer', 'owner')),
    application_id UUID NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    managed_by TEXT NOT NULL DEFAULT 'api',
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_access_binding_subject_app ON access_binding (tenant_id, lower(subject), application_id);
CREATE INDEX idx_access_binding_app ON access_binding (tenant_id, application_id);

ALTER TABLE access_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_binding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON access_binding
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE, DELETE ON access_binding TO rampart_app, rampart_system;
    GRANT SELECT ON access_binding TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS access_binding;
