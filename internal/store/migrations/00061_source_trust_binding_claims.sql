-- +goose Up
-- docs/51 step 1.3, D80: a trust rule for a generic issuer names the claims that carry the repository and the ref, so the token
-- exchanged under it is bound to one repository and one branch. Nullable, so the old binary's INSERT still works.
ALTER TABLE source_trust ADD COLUMN IF NOT EXISTS repository_claim TEXT;
ALTER TABLE source_trust ADD COLUMN IF NOT EXISTS ref_claim TEXT;

-- +goose Down
ALTER TABLE source_trust DROP COLUMN IF EXISTS ref_claim;
ALTER TABLE source_trust DROP COLUMN IF EXISTS repository_claim;
