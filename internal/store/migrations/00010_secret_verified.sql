-- +goose Up
-- A secret scanner that tries a credential against its provider (TruffleHog) says whether it is live. The risk score
-- weighs that most (docs/06: SECRET_VERIFIED), so the finding keeps it (docs/16 D42).
ALTER TABLE finding ADD COLUMN IF NOT EXISTS secret_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE finding DROP COLUMN IF EXISTS secret_verified;
