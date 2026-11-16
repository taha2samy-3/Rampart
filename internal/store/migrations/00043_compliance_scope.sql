-- +goose Up
-- User-defined compliance frameworks (docs/16 D102). An application names the compliance scopes it is in (for
-- example pci, sox); a framework with appliesTo.complianceScope reads only the applications that list the scope.
ALTER TABLE application ADD COLUMN IF NOT EXISTS compliance_scope TEXT[] NOT NULL DEFAULT '{}';

-- A ComplianceFramework is stored next to the tenant's SLA and risk policies, a ClusterComplianceFramework next to
-- the cluster policies: the same last-valid-spec rule (D41) applies.
ALTER TABLE policy_object DROP CONSTRAINT IF EXISTS policy_object_kind_check;
ALTER TABLE policy_object ADD CONSTRAINT policy_object_kind_check CHECK (kind IN ('sla', 'risk', 'compliance'));
ALTER TABLE cluster_policy DROP CONSTRAINT IF EXISTS cluster_policy_kind_check;
ALTER TABLE cluster_policy ADD CONSTRAINT cluster_policy_kind_check CHECK (kind IN ('risk', 'sla', 'feeds', 'compliance'));

-- +goose Down
DELETE FROM cluster_policy WHERE kind = 'compliance';
ALTER TABLE cluster_policy DROP CONSTRAINT IF EXISTS cluster_policy_kind_check;
ALTER TABLE cluster_policy ADD CONSTRAINT cluster_policy_kind_check CHECK (kind IN ('risk', 'sla', 'feeds'));
DELETE FROM policy_object WHERE kind = 'compliance';
ALTER TABLE policy_object DROP CONSTRAINT IF EXISTS policy_object_kind_check;
ALTER TABLE policy_object ADD CONSTRAINT policy_object_kind_check CHECK (kind IN ('sla', 'risk'));
ALTER TABLE application DROP COLUMN IF EXISTS compliance_scope;
