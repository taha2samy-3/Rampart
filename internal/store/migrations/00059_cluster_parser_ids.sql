-- +goose Up
-- docs/51 step 2.8, D146: the parser ids of runs stored before D146 (`builtin:<name>`, and before D141 `lua:<name>` and
-- `wasm:<name>` for a cluster parser) become `cluster:<name>`. D146 removed the code that still read the old ids, so without this
-- the compliance report (CategoriesOf), the gate (runMatches) and a parser's "last run" lost every run made before it.
-- A run's scope recorded the parser id as its family when the report had no finding (docs/51 step 2.7); that family is the tool's
-- name, which is the parser's name.
-- Both tables have FORCE ROW LEVEL SECURITY; see 00058 for why it is lifted inside this transaction.
ALTER TABLE ingest_run NO FORCE ROW LEVEL SECURITY;
UPDATE ingest_run SET format = 'cluster:' || substring(format FROM position(':' IN format) + 1)
WHERE format LIKE 'builtin:%' OR format LIKE 'lua:%' OR format LIKE 'wasm:%';
UPDATE ingest_run SET scanner_family = substring(scanner_family FROM position(':' IN scanner_family) + 1)
WHERE scanner_family LIKE 'builtin:%' OR scanner_family LIKE 'cluster:%';
ALTER TABLE ingest_run FORCE ROW LEVEL SECURITY;

ALTER TABLE ingest_run_scope NO FORCE ROW LEVEL SECURITY;
-- A scope that already exists under the tool's name for the same run wins; the duplicate under the parser id goes.
DELETE FROM ingest_run_scope s
WHERE (s.scanner_family LIKE 'builtin:%' OR s.scanner_family LIKE 'cluster:%')
  AND EXISTS (SELECT 1 FROM ingest_run_scope d
              WHERE d.ingest_run_id = s.ingest_run_id AND d.asset_id = s.asset_id AND d.track = s.track
                AND d.scanner_family = substring(s.scanner_family FROM position(':' IN s.scanner_family) + 1));
UPDATE ingest_run_scope SET scanner_family = substring(scanner_family FROM position(':' IN scanner_family) + 1)
WHERE scanner_family LIKE 'builtin:%' OR scanner_family LIKE 'cluster:%';
ALTER TABLE ingest_run_scope FORCE ROW LEVEL SECURITY;

-- +goose Down
SELECT 1;
