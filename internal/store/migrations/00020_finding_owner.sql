-- +goose Up
-- Who works on a finding (docs/01 C9, docs/03 owner, docs/16 D59): the e-mail of a member of the tenant, or nothing.
-- docs/03 also names owner_team_id; teams arrive with SCIM groups (P2), so a team is not an owner yet.
ALTER TABLE finding ADD COLUMN IF NOT EXISTS owner TEXT;
CREATE INDEX IF NOT EXISTS idx_finding_owner ON finding (tenant_id, owner) WHERE owner IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_finding_owner;
ALTER TABLE finding DROP COLUMN IF EXISTS owner;
