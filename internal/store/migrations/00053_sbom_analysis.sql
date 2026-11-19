-- +goose Up
-- One row per SBOM and analyzer: where the analysis stands. It is what lets Rampart analyse an SBOM on upload, on request and
-- on a schedule without doing the same work twice, and what the scheduled sweep reads to find the SBOMs that are due.
CREATE TABLE sbom_analysis (
    tenant_id          UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    sbom_id            UUID NOT NULL REFERENCES sbom(id) ON DELETE CASCADE,
    analyzer_kind      TEXT NOT NULL CHECK (analyzer_kind IN ('external', 'sbom')),
    analyzer_scope     TEXT NOT NULL CHECK (analyzer_scope IN ('cluster', 'tenant')),
    analyzer_namespace TEXT NOT NULL DEFAULT '',
    analyzer_name      TEXT NOT NULL,
    state              TEXT NOT NULL CHECK (state IN ('pending', 'running', 'completed', 'failed', 'timed_out', 'cancelled', 'not_applicable')),
    trigger            TEXT NOT NULL CHECK (trigger IN ('upload', 'manual', 'scheduled')),
    attempts           INT NOT NULL DEFAULT 0,
    error              TEXT NOT NULL DEFAULT '',
    components         INT NOT NULL DEFAULT 0,
    findings           INT NOT NULL DEFAULT 0,
    created            INT NOT NULL DEFAULT 0,
    closed             INT NOT NULL DEFAULT 0,
    started_at         TIMESTAMPTZ,
    finished_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, sbom_id, analyzer_kind, analyzer_scope, analyzer_namespace, analyzer_name)
);
CREATE INDEX idx_sbom_analysis_inflight ON sbom_analysis (updated_at) WHERE state IN ('pending', 'running');
ALTER TABLE sbom_analysis ENABLE ROW LEVEL SECURITY;
ALTER TABLE sbom_analysis FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sbom_analysis
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- +goose StatementBegin
DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE ON sbom_analysis TO rampart_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON sbom_analysis TO rampart_system;
    GRANT SELECT ON sbom_analysis TO rampart_ro;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS sbom_analysis;
