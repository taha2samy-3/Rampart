-- +goose Up
-- The break-glass local administrator (D3, doc 14 section 1). The table exists since 00001; this adds
-- what a safe password sign-in needs: the person row it signs in as, a failure counter with a lock,
-- and the last sign-in.
ALTER TABLE local_admin
    ADD COLUMN user_id UUID REFERENCES app_user(id) ON DELETE CASCADE,
    ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN locked_until TIMESTAMPTZ,
    ADD COLUMN last_login TIMESTAMPTZ,
    ADD COLUMN password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- +goose Down
ALTER TABLE local_admin
    DROP COLUMN IF EXISTS password_changed_at,
    DROP COLUMN IF EXISTS last_login,
    DROP COLUMN IF EXISTS locked_until,
    DROP COLUMN IF EXISTS failed_attempts,
    DROP COLUMN IF EXISTS user_id;
