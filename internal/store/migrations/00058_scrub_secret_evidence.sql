-- +goose Up
-- docs/51 step 1.1, D42: a secret is never stored. From D147 (2026-11-21) until this migration, occurrence.raw kept the parser's
-- raw record as given, and occurrence.normalized its attributes, so a secret finding could carry the credential (Gitleaks Secret,
-- Match, Line; TruffleHog Raw, RawV2; the secret_value of the emitted line). The ingest now redacts before storing
-- (internal/ingest/redact.go); this removes what is already stored.
--
-- occurrence has FORCE ROW LEVEL SECURITY, which applies to the owner that runs migrations: without lifting it inside this
-- transaction the UPDATE would match no row on a cluster where the owner is not a superuser (it did for 00056's backfill).
ALTER TABLE occurrence NO FORCE ROW LEVEL SECURITY;

-- A secret finding keeps no raw record, and none of the keys that hold the credential or the text around it.
UPDATE occurrence o
SET raw = NULL,
    normalized = CASE WHEN jsonb_typeof(o.normalized) = 'object'
        THEN o.normalized - ARRAY['secret', 'Secret', 'SECRET', 'secret_value', 'secretValue', 'Match', 'match', 'Line', 'line',
                                  'Raw', 'raw', 'RawV2', 'rawV2', 'rawv2', 'raw_v2']
        ELSE NULL END
FROM finding f
WHERE f.id = o.finding_id AND f.tenant_id = o.tenant_id AND f.category = 'secret'
  AND (o.raw IS NOT NULL OR o.normalized IS NOT NULL);

-- Any other finding: the secret keys at the top level of the record (the ingest now drops them at any depth).
UPDATE occurrence
SET raw = raw - ARRAY['secret', 'Secret', 'secret_value', 'secretValue']
WHERE jsonb_typeof(raw) = 'object' AND raw ?| ARRAY['secret', 'Secret', 'secret_value', 'secretValue'];
UPDATE occurrence
SET normalized = normalized - ARRAY['secret', 'Secret', 'secret_value', 'secretValue']
WHERE jsonb_typeof(normalized) = 'object' AND normalized ?| ARRAY['secret', 'Secret', 'secret_value', 'secretValue'];

ALTER TABLE occurrence FORCE ROW LEVEL SECURITY;

-- +goose Down
-- What was removed is not restored: it was a secret.
SELECT 1;
