-- +goose Up
-- Application selectors (docs/04, D10 step (b), docs/16 D56), and a per-application flag that asks the SLA sweep
-- to re-score: its context changed (D55) or assets moved into it (D56). The application role may set it; the
-- marker policy rows of D55 needed the system role.
ALTER TABLE application ADD COLUMN IF NOT EXISTS selectors JSONB NOT NULL DEFAULT '{}';
ALTER TABLE application ADD COLUMN IF NOT EXISTS rescore_needed BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_application_rescore ON application (tenant_id) WHERE rescore_needed;
-- D55 flagged a context change with a marker policy row; the flag now lives on the application.
UPDATE application a SET rescore_needed = TRUE
  FROM policy_object p
 WHERE p.tenant_id = a.tenant_id AND p.kind = 'sla' AND p.namespace = '_recompute' AND p.recompute_needed;
DELETE FROM policy_object WHERE kind = 'sla' AND namespace = '_recompute';

-- +goose Down
DROP INDEX IF EXISTS idx_application_rescore;
ALTER TABLE application DROP COLUMN IF EXISTS rescore_needed;
ALTER TABLE application DROP COLUMN IF EXISTS selectors;
