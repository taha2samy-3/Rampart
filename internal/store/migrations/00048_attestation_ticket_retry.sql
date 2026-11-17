-- +goose Up
-- An administrator can send a ticket that gave up back to the outbox (docs/16 D126). The application role could only read
-- attestation_ticket; it may now change the four columns a retry changes, and nothing else (row-level security still
-- confines it to its tenant). Expand-only: a grant.
-- +goose StatementBegin
DO $$
BEGIN
    GRANT UPDATE (status, attempts, next_at, error) ON attestation_ticket TO rampart_app;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    REVOKE UPDATE (status, attempts, next_at, error) ON attestation_ticket FROM rampart_app;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd
