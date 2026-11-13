-- +goose Up
-- Migration 00029: held_close table for mass-close guard (docs/16 D22, docs/21 Section 3.2).
CREATE TABLE held_close (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    ingest_run_id UUID NOT NULL REFERENCES ingest_run(id) ON DELETE CASCADE,
    scope JSONB NOT NULL,
    finding_ids UUID[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_by TEXT,
    decision TEXT,
    decided_at TIMESTAMPTZ
);

ALTER TABLE held_close ENABLE ROW LEVEL SECURITY;
ALTER TABLE held_close FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON held_close
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

CREATE INDEX idx_held_close_tenant_created ON held_close(tenant_id, created_at DESC);
CREATE INDEX idx_held_close_run ON held_close(tenant_id, ingest_run_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON held_close TO rampart_app, rampart_system;

-- +goose Down
DROP POLICY IF EXISTS tenant_isolation ON held_close;
DROP TABLE IF EXISTS held_close;
