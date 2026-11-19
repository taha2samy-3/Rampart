-- +goose Up
-- expand-safe: only widens two CHECK constraints to allow kind 'parser'; the old binary never writes that kind and every value it writes stays valid
-- Cluster-wide and tenant parsers (docs/19 §4, docs/29). Stored in cluster_policy (ClusterParser)
-- and policy_object (Parser), with last-valid-spec semantics (D41).
ALTER TABLE cluster_policy DROP CONSTRAINT IF EXISTS cluster_policy_kind_check;
ALTER TABLE cluster_policy ADD CONSTRAINT cluster_policy_kind_check CHECK (kind IN ('risk', 'sla', 'feeds', 'compliance', 'parser'));

ALTER TABLE policy_object DROP CONSTRAINT IF EXISTS policy_object_kind_check;
ALTER TABLE policy_object ADD CONSTRAINT policy_object_kind_check CHECK (kind IN ('sla', 'risk', 'compliance', 'parser'));

-- +goose Down
DELETE FROM cluster_policy WHERE kind = 'parser';
ALTER TABLE cluster_policy DROP CONSTRAINT IF EXISTS cluster_policy_kind_check;
ALTER TABLE cluster_policy ADD CONSTRAINT cluster_policy_kind_check CHECK (kind IN ('risk', 'sla', 'feeds', 'compliance'));

DELETE FROM policy_object WHERE kind = 'parser';
ALTER TABLE policy_object DROP CONSTRAINT IF EXISTS policy_object_kind_check;
ALTER TABLE policy_object ADD CONSTRAINT policy_object_kind_check CHECK (kind IN ('sla', 'risk', 'compliance'));
