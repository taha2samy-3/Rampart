-- +goose Up
-- Triage (docs/16 D18, D38): the OpenVEX justification and impact statement of a `not_affected` decision, and
-- the finding a `duplicate` points at. `tags`, `state_reason` and `severity_override_reason` already exist.
-- No foreign key on duplicate_of_id: it is checked by the application (D36).
ALTER TABLE finding ADD COLUMN IF NOT EXISTS justification TEXT;
ALTER TABLE finding ADD COLUMN IF NOT EXISTS impact_statement TEXT;
ALTER TABLE finding ADD COLUMN IF NOT EXISTS duplicate_of_id UUID;

-- +goose Down
ALTER TABLE finding DROP COLUMN IF EXISTS duplicate_of_id;
ALTER TABLE finding DROP COLUMN IF EXISTS impact_statement;
ALTER TABLE finding DROP COLUMN IF EXISTS justification;
