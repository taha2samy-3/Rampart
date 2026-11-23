-- +goose Up
-- ============================================================================
-- 00056_scansource_universal_binding.sql
-- Implements explicit Application Binding, Security Categories, and Universal
-- Workload Identity Federation (D140, D17, D22).
-- ============================================================================
-- expand-safe: adds application_id, categories, auth_type, token_hash, bound_claims columns with defaults, recreates foreign key with ON DELETE CASCADE, adds GIN and B-Tree indexes; existing queries and binaries remain fully compatible.

-- 1. ScanSource Table Enhancement: Application Binding & Categories
ALTER TABLE scan_source
    ADD COLUMN IF NOT EXISTS application_id UUID REFERENCES application(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS categories TEXT[] NOT NULL DEFAULT '{"all"}',
    ADD COLUMN IF NOT EXISTS auth_type TEXT NOT NULL DEFAULT 'token',
    ADD COLUMN IF NOT EXISTS token_hash TEXT,
    ADD COLUMN IF NOT EXISTS bound_claims JSONB NOT NULL DEFAULT '{}'::jsonb;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'scan_source_application_id_fkey'
    ) THEN
        ALTER TABLE scan_source DROP CONSTRAINT scan_source_application_id_fkey;
        ALTER TABLE scan_source ADD CONSTRAINT scan_source_application_id_fkey FOREIGN KEY (application_id) REFERENCES application(id) ON DELETE CASCADE;
    END IF;
END $$;
-- +goose StatementEnd

-- Index for high-throughput lookup during ingestion resolution
CREATE INDEX IF NOT EXISTS idx_scan_source_app_tenant ON scan_source (tenant_id, application_id);
CREATE INDEX IF NOT EXISTS idx_scan_source_auth ON scan_source (tenant_id, auth_type);

-- 2. Enhance source_trust table for Universal Claims Matching
ALTER TABLE source_trust
    ADD COLUMN IF NOT EXISTS bound_claims JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_source_trust_bound_claims ON source_trust USING GIN (bound_claims);

-- 3. Backfill existing rows if any exist
UPDATE scan_source
SET application_id = default_application_id
WHERE application_id IS NULL AND default_application_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_source_trust_bound_claims;
ALTER TABLE source_trust DROP COLUMN IF EXISTS bound_claims;

DROP INDEX IF EXISTS idx_scan_source_auth;
DROP INDEX IF EXISTS idx_scan_source_app_tenant;
ALTER TABLE scan_source
    DROP COLUMN IF EXISTS bound_claims,
    DROP COLUMN IF EXISTS token_hash,
    DROP COLUMN IF EXISTS auth_type,
    DROP COLUMN IF EXISTS categories,
    DROP COLUMN IF EXISTS application_id;
