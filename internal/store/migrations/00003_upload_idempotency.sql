-- +goose Up
-- Presigned uploads (D2, D9): the idempotency check compares the request body, so the upload keeps a
-- hash of it; finding the run of an upload (a repeated `complete`) needs an index.
ALTER TABLE upload ADD COLUMN request_hash TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_ingest_run_upload ON ingest_run (tenant_id, upload_id) WHERE upload_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_ingest_run_upload;
ALTER TABLE upload DROP COLUMN IF EXISTS request_hash;
