-- +goose Up
-- Support hierarchy-scoped and tenant-scoped access bindings (docs/04, docs/07 section 2, docs/09, docs/16 D8, D48).
-- application_id becomes nullable (NULL when scoped to hierarchy or tenant).
-- hierarchy_path holds the prefix (e.g. 'fintech.payments') for subtree access.
-- tenant_scope is TRUE for tenant-wide access bindings.
-- subject_kind is 'user' or 'group'.
-- idp qualifies the identity provider (e.g. 'okta' or empty for default).

ALTER TABLE access_binding ALTER COLUMN application_id DROP NOT NULL;

ALTER TABLE access_binding
    ADD COLUMN IF NOT EXISTS hierarchy_path TEXT,
    ADD COLUMN IF NOT EXISTS tenant_scope BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS subject_kind TEXT NOT NULL DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS idp TEXT NOT NULL DEFAULT '';

DROP INDEX IF EXISTS idx_access_binding_subject_app;

CREATE UNIQUE INDEX idx_access_binding_subject_app
    ON access_binding (tenant_id, lower(subject), application_id)
    WHERE application_id IS NOT NULL;

CREATE UNIQUE INDEX idx_access_binding_subject_hierarchy
    ON access_binding (tenant_id, lower(subject), hierarchy_path)
    WHERE hierarchy_path IS NOT NULL;

CREATE UNIQUE INDEX idx_access_binding_subject_tenant
    ON access_binding (tenant_id, lower(subject))
    WHERE tenant_scope = TRUE;

CREATE INDEX idx_access_binding_hierarchy ON access_binding (tenant_id, hierarchy_path) WHERE hierarchy_path IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_access_binding_hierarchy;
DROP INDEX IF EXISTS idx_access_binding_subject_tenant;
DROP INDEX IF EXISTS idx_access_binding_subject_hierarchy;
DROP INDEX IF EXISTS idx_access_binding_subject_app;

ALTER TABLE access_binding
    DROP COLUMN IF EXISTS idp,
    DROP COLUMN IF EXISTS subject_kind,
    DROP COLUMN IF EXISTS tenant_scope,
    DROP COLUMN IF EXISTS hierarchy_path;

DELETE FROM access_binding WHERE application_id IS NULL;
ALTER TABLE access_binding ALTER COLUMN application_id SET NOT NULL;
CREATE UNIQUE INDEX idx_access_binding_subject_app ON access_binding (tenant_id, lower(subject), application_id);

