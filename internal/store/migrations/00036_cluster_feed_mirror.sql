-- +goose Up
-- ClusterFeedMirror (docs/04, D86) is kept with the other cluster-wide configuration, as kind 'feeds'.
ALTER TABLE cluster_policy DROP CONSTRAINT IF EXISTS cluster_policy_kind_check;
ALTER TABLE cluster_policy ADD CONSTRAINT cluster_policy_kind_check CHECK (kind IN ('risk', 'sla', 'feeds'));

-- +goose Down
DELETE FROM cluster_policy WHERE kind = 'feeds';
ALTER TABLE cluster_policy DROP CONSTRAINT IF EXISTS cluster_policy_kind_check;
ALTER TABLE cluster_policy ADD CONSTRAINT cluster_policy_kind_check CHECK (kind IN ('risk', 'sla'));
