# 16 — Implementation decisions (normative)

This document closes the gaps found by the design review ([17-design-review.md](17-design-review.md)). It is **normative**: where an older sentence elsewhere disagrees, this document wins. Each section says which review item it closes.

## D1. Who talks to the Kubernetes API (closes B1, M8)

| Target | Kubernetes API access |
|---|---|
| `operator` | Reads and writes Rampart CRs and their status. Reads Secrets referenced by CRs. Creates tenant namespaces, per-tenant Roles, `Job`/`CronJob` for `ScheduledScan`. Watches reports in managed clusters |
| `ingest-gateway` | Only `tokenreviews.authentication.k8s.io: create`, and only when ServiceAccount authentication is enabled |
| every other target | None. `automountServiceAccountToken: false` |

Consequences:

- **The gateway never creates `ReportIngest` objects.** An API upload produces only `upload` and `ingest_run` rows. `ReportIngest` is a user-facing, GitOps resource for "ingest this object that is already in storage". This also removes the risk of thousands of CRs per day in etcd.
- Visibility of API uploads in `kubectl` comes from `ScanSource.status` counters and `rampart ingests list`.
- **Secrets**: the operator is the only reader of Kubernetes Secrets. It copies referenced secret material into the `secret_material` table, envelope-encrypted (AES-256-GCM, one data key per tenant, wrapped by a KMS key or a mounted master key), with a content hash and the Secret `resourceVersion`. `notify`, `sync` and `query-api` decrypt from that table. A Secret change triggers reconcile and a new row version; consumers pick it up through the config change notification. This replaces the earlier statements "never copied into Postgres" (02 §5, 07 §3) and "operator-issued short-lived handle".
- Operator RBAC (explicit): cluster-wide `get/list/watch` on Rampart CRDs and `namespaces`; `create/patch` on `namespaces` (tenant reconcile); `update/patch` on Rampart `*/status` and finalizers; `get/list/watch` on `secrets` through a per-tenant Role it creates in each tenant namespace; `create/delete` on `roles`/`rolebindings` limited by an aggregated ClusterRole it is allowed to grant; `create/delete` on `jobs`/`cronjobs` in tenant namespaces only when the `ScheduledScan` module is enabled; `create` on `events`; `leases` in its own namespace.

## D2. Ingest run ownership and job identity (closes B2, M5, M14, M15)

- `POST /ingest/v1/uploads` inserts `upload` (status `created`) with the full context and options.
- `POST /ingest/v1/uploads/{id}/complete` in one transaction: sets `upload.status = completed`, inserts `ingest_run` (status `queued`), inserts River job `ParseJob{ingest_run_id}` with `UniqueOpts{ByArgs}`. It returns `ingestRunId`.
- For a user-created `ReportIngest` CR the operator performs the same three inserts, with `ingest_run.crd_uid` set (unique). It never enqueues for a CR whose uid already has an `ingest_run`.
- The parser owns every later change to `ingest_run` (status, stats, error, timestamps).
- One status enum everywhere: `queued | parsing | merging | enriching | scoring | completed | completed_with_errors | failed | stale`. `completed` means merged, enriched **and scored**, so the CI gate never evaluates a risk band that is still being computed. `ReportIngest.status.phase` is the same value capitalised (`Queued`, `Parsing`, …). The CI gate waits for `completed`, `completed_with_errors`, `failed` or `stale`.
- One stats shape: `{parsed, created, updated, untouched, reactivated, closed, skipped_min_severity, record_errors}`.
- Batch size is **5 000 staged rows per transaction** (one number; supersedes "1000" in 02 §3).
- A failed run keeps the findings its committed batches created; it never closes anything.
- `Idempotency-Key`: unique per tenant for 7 days. Same key with an identical request body returns the original response; with a different body returns `409` with problem type `idempotency-key-reused`.
- `first_seen` and `last_seen` use `context.scanFinished` when supplied and not in the future, otherwise the ingest time.

## D3. Running without Kubernetes (closes B3)

- The reconcile logic is a library, `internal/config/apply`, that turns a Rampart resource (the CRD YAML shape) into config rows. The operator calls it from reconcilers. The CLI calls it from `rampart apply -f <file|dir>`.
- `-target=all` starts the operator only when in-cluster config or `--kubeconfig` is present (`--operator=auto|on|off`).
- Docker Compose mounts `/etc/rampart/resources/*.yaml`; the `all` target applies them at boot and re-applies on file change. The quick-start ships a default tenant, one `ScanSource` and default policies.
- Status in file mode is stored in Postgres and shown by `rampart get <kind>`.
- **First administrator and break-glass** (built, see D33 and doc 14 section 11): on first boot, if `auth.bootstrapAdmin.passwordFile` is set, a `local_admin` row is created (argon2id) from that password, or from a generated one written to the file. Local login is refused once an identity provider is configured, unless `auth.bootstrapAdmin.keepEnabled=true`. Every use is audited.

## D4. Database roles, RLS, migrations (closes B4, M7)

| Role | Used by | Rights |
|---|---|---|
| `rampart_owner` | `rampart migrate` only | owns all objects; DDL |
| `rampart_app` | gateway, parser, enrich, policy, notify, sync, query-api | DML on tenant tables through RLS; read on global tables; no ownership |
| `rampart_system` | operator, scheduler, feed sync, cross-tenant maintenance | `BYPASSRLS`; DML on config and global tables; used only by code paths that either write global data or fan out one job per tenant |
| `rampart_ro` | query-api against replicas | `SELECT` through RLS |

- RLS policy text on every tenant table: `using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) with check (same)`. An unset tenant yields zero rows instead of an error.
- Every tenant-scoped transaction starts with `select set_config('app.tenant_id', $1, true)`. A store-level test fails the build if a query runs on `rampart_app` without it.
- Tables without RLS: global intelligence tables, `tenant`, `river.*`, `ingest_staging`. River job arguments carry `tenant_id`; the worker sets the tenant before touching data.
- Cross-tenant work (for example "KEV added, re-score") is done as: `rampart_system` selects affected `(tenant_id, finding_id)` pairs from an index-only query and enqueues per-tenant jobs. It never mutates tenant rows itself.
- Credentials come from the CNPG-generated application Secret (or external DSNs): `database.url` (pooled, PgBouncer transaction mode) and `database.directUrl` (direct to the primary).
- **`LISTEN/NOTIFY` needs the direct URL.** River's notifier and the config-change listener use `database.directUrl`; request handlers use the pooled URL. With no direct URL, River runs in poll-only mode and config is re-read every 15 s.
- Migrations: `rampart migrate up` runs goose migrations and River's own migrations. In Helm it is a plain Job on install (not a hook, so it can wait for the bundled CNPG cluster) and a `pre-upgrade` hook on upgrade. Every target has an init container `rampart migrate wait` that blocks until the schema version is at least the one the binary expects. `-target=all` auto-migrates by default (`database.autoMigrate`).
- Partitions (`finding_event`, `audit_event`, `trend_daily`) are created three months ahead by the scheduler's `maintenance` job; the first set is created by the migration. Built as `rampart maintenance` and the retention loop of the all-in-one target (D53); `trend_daily` does not exist (D43).

## D5. Identifiers (closes B5)

UUIDv7 values are generated in Go (`github.com/google/uuid`, `NewV7`). No database default. PostgreSQL 16 remains the minimum.

## D6. Configuration reference (closes B6, M3)

Environment prefix `RAMPART_`, nested keys joined with `_`. File `/etc/rampart/config.yaml`. Flags override env, env overrides file.

| Key | Default | Meaning |
|---|---|---|
| `target` | `all` | comma list of targets |
| `server.http.addr` | `:8080` | API, ingest, UI |
| `server.ops.addr` | `:9090` | `/metrics`, `/healthz`, `/readyz` (separate port, never exposed through the Gateway) |
| `server.publicUrl` | — | external base URL for links, redirects, cookies |
| `database.url` / `database.directUrl` / `database.readUrl` | — | pooled, direct, replica (all as `rampart_app` / `rampart_ro`) |
| `database.migrateUrl` | — | `rampart_owner`; used only by migrations (D30) |
| `database.systemUrl` | — | `rampart_system`; tenant bootstrap, feed sync, maintenance (D30) |
| `database.autoMigrate` | `true` for `all` | |
| `objectStorage.endpoint`, `.externalEndpoint`, `.region`, `.bucketRaw`, `.bucketExports`, `.accessKeyFile`, `.secretKeyFile`, `.usePathStyle` | — | `externalEndpoint` is the address CI can reach for presigned URLs |
| `ingest.maxReportBytes` | `536870912` | default per-upload cap |
| `ingest.batchRows` | `5000` | |
| `auth.oidc.issuer`, `.clientId`, `.clientSecretFile`, `.scopes`, `.groupsClaim` | — | static IdP for Phase 1 and for file mode |
| `auth.session.keyFile` | — | 32-byte key for cookie and envelope encryption (or `kms.keyUri`) |
| `auth.bootstrapAdmin.passwordFile` | — | the first administrator's password (generated into it when missing). Setting it enables the account |
| `auth.bootstrapAdmin.username` / `.tenant` | `admin` / `default` | |
| `auth.bootstrapAdmin.keepEnabled` | `false` | keep password sign-in on next to single sign-on |
| `auth.bootstrapAdminTokenFile` | — | Phase 1: file the first admin API token is written to (0600). Never logged (D30) |
| `feeds.nvd.url`, `feeds.osv.url`, `feeds.epss.url`, `feeds.kev.url`, `feeds.cwe.url`, `feeds.<x>.schedule` | public endpoints | overridden by a `ClusterFeedMirror` when one exists |
| `feeds.egress` | `allow` | `deny` blocks every non-mirror call |
| `eventBus.type` | `river` | `river` or `nats` |
| `cache.valkeyUrl` | — | optional |
| `telemetry.otlpEndpoint`, `log.level`, `log.format` | —, `info`, `json` | |
| `operator.mode` | `auto` | `auto`, `on`, `off` |
| `retention.enabled`, `.interval` | `true`, `6h` | the retention sweep (D53) |
| `retention.occurrencesDays`, `.rawReportsDays`, `.secretReportsDays`, `.resolvedFindingsDays`, `.eventsDays`, `.auditDays`, `.runResultsDays` | 180, 90, 7, 730, 730, 2555, 30 | days; 0 keeps for ever; minimums in D53 |

Helm values skeleton: `mode`, `image`, `config` (the tree above), `bundled.postgres.enabled`, `bundled.seaweedfs.enabled`, `bundled.valkey.enabled`, `bundled.nats.enabled`, `ingress|gateway`, `targets.<name>.{replicas,resources,autoscaling}`, `keda.enabled`, `networkPolicy.enabled`, `serviceMonitor.enabled`.

Feed sync ownership: the **scheduler enqueues** feed jobs; the **enrich** target executes them.

## D7. Decisions gating the Phase 0 scaffold (closes B7)

These are baked into module paths, CRD groups, labels and token prefixes, so they must be confirmed before scaffolding. Proposed values, used throughout these documents:

| Decision | Proposed |
|---|---|
| Product name | Rampart |
| API group | `rampart.aspm.dev` |
| Go module | `github.com/<org>/rampart` |
| License | Apache-2.0 |
| Minimum Kubernetes | 1.30 |
| Minimum PostgreSQL | 16 |

## D8. Identity model for tenants (closes part of B14)

- A person is one global `app_user` identified by `(issuer, subject)`. Membership in tenants is `tenant_member(tenant_id, user_id, status)`.
- A session has one active tenant. `POST /auth/tenant` switches it and rotates the session id. The UI tenant switcher lists `GET /api/v1/me/tenants`.
- Canonical login endpoint is `GET /auth/login?tenant=<slug>&return_to=<path>`. `/login` and `/t/<tenant>/login` are SPA routes that redirect to it.
- **Phase 1 scope**: one OIDC provider from static config (`auth.oidc.*`), built-in roles `viewer`, `triager`, `admin` bound at tenant scope in the `role_binding` table, API tokens with scopes. `IdentityProvider` and `AccessBinding` CRDs, scoped bindings and the remaining roles arrive in Phase 2.
- **CLI login**: Phase 1 is `rampart login --token`. From Phase 2, Rampart itself is the device-authorization server: `POST /auth/device/code`, the user approves in the browser with their SSO session, the CLI polls `POST /auth/device/token` and receives a user-bound API token stored in the OS keychain. This works with any IdP.

## D9. Presigned uploads (closes B15)

- `objectStorage.externalEndpoint` is the host placed in presigned URLs. With the bundled object store (SeaweedFS) the chart exposes it through its own route (`/s3` path or a dedicated hostname).
- The client declares `sizeBytes` at `POST /uploads`. The gateway rejects sizes above the tenant limit and signs `Content-Length` into the presigned PUT, so a different size fails at the storage layer.
- The parser verifies size and SHA-256 while streaming and fails the run on mismatch before any merge.
- Object key: `tenants/<tenant_id>/uploads/<yyyy>/<mm>/<dd>/<upload_id>`. Presigned URLs expire after 15 minutes.

## D10. Assets, versions and tracks (closes B11 image problem, B12)

**An asset is the long-lived thing; a version is one build of it.**

| Asset type | `key` | Version (`asset_version.version`) |
|---|---|---|
| `repository` | normalized clone URL | commit SHA |
| `image` | `registry/repository` (no tag, no digest) | `sha256:` digest (tags kept as attributes) |
| `workload` | `cluster/namespace/kind/name` | pod template hash |
| `url` | `scheme://host:port` + path prefix | — |
| `sbom_project` | `dtrack://<connector>/<project name>` | DT project version |
| `package`, `host`, `cloud_resource`, `pipeline` | as in 03 §1 | — |

`asset_version(tenant_id, asset_id, version, attributes, first_seen, last_seen)`.

**Track.** Findings on an asset are kept per *track*, a named line of versions: for repositories the branch (`main`, `release/1.x`), for images and workloads the environment (`prod`, `staging`) or, if none is given, `default`. The track comes from `ScanSource.mapping.trackFrom` (default: `context.environment`, else `context.branch` when it is a tracked ref, else `default`).

**Tracked and ephemeral runs.** A `ScanSource` lists `trackedRefs` (default: the repository default branch and `release/*`). A run whose branch is not tracked (pull requests, feature branches) is **ephemeral**: it is parsed, fingerprinted and compared with the baseline track (`mapping.baselineTrack`, default `main`) to produce the CI gate result (new, existing, fixed), and its results are stored for 30 days in `ingest_run_result`. It does not create, update or close findings in the inventory. This removes branch churn entirely.

**Resolution order for a run** (first match wins, per finding when a report spans several targets):

1. Primary asset type from the finding category and context:

| Category | Context has | Asset type |
|---|---|---|
| sast, secret, iac, license | `repository` | `repository` |
| sca | `imageDigest` or report target is an image | `image` |
| sca | otherwise `repository` | `repository` |
| container | image reference in report or context | `image` |
| dast | target URL | `url` |
| cspm | resource id | `cloud_resource` |
| compliance (Kubernetes) | resource key | `workload` |

2. Asset lookup by `(tenant, type, key)`; created if missing.
3. Application: (a) the asset's existing `application_id`; (b) `Application.selectors` matching the asset key; (c) `ScanSource.mapping.applicationFrom` (a CEL expression that must return an application slug); (d) `ScanSource.defaultApplication`; (e) the tenant's built-in **Unassigned** application. `finding.application_id` is therefore never null.
4. `service` and `environment` come from selectors, then from `context.service` / `context.environment`.

A report with several targets (for example Trivy scanning three images) yields one `ingest_run` and several rows in `ingest_run_scope`, one per `(asset, track)`.

**Shared assets.** `asset.application_id` is nullable. `package` assets and shared base images belong to no application; they are linked by `asset_edge`. A finding always attaches to the consuming primary asset (the image or repository that was scanned), never to the shared package asset.

**Canonical upload context** (one schema for 03, 04, 05, 11): `repository`, `branch`, `commit`, `imageRef`, `imageDigest`, `environment`, `service`, `version`, `buildId`, `pipelineUrl`, `scanStarted`, `scanFinished`, `tags[]`.

## D11. Fingerprint specification (closes B11)

- Computed in `internal/normalize`, inside the parser target, after normalization. Parsers only map; `normalize` derives `snippet_hash`, `secret_hash`, `image_repository`, `manifest_path`, `resource_address`, `normalized_url` from `RawFinding.Location` and `Evidence`.
- Serialization: `finding_key = SHA-256( "v1" US family US scope_key US f1 US f2 … )` where `US` is byte `0x1F`. Each field is UTF-8, NFC-normalized, trimmed; identifiers, hosts and paths are case-folded only where the table says so. A missing field is the empty string.
- `scope_key = tenant_id US asset_id US track` for `scope: asset` (default); `tenant_id US application_id` for `scope: application`; `tenant_id` for `scope: tenant`. The version (digest, commit) is never part of the key.
- Default fields (compiled-in `DedupPolicy`, overridable by CRD):

| Class | Fields, in order | Fallback when the discriminating field is empty |
|---|---|---|
| SAST | `rule_id`, `file_path`, first non-empty of (`logical_location`, `snippet_hash`, tool `primaryLocationLineHash`) | `start_line` (marks the finding `weak_fingerprint`) |
| SCA | `canonical_vuln_id`, `purl_base`, `manifest_path` (repository assets only) | `component_name` when no purl |
| Secret | `rule_id`, `file_path`, `secret_hash` | `start_line` |
| IaC | `rule_id`, `file_path`, `resource_address` | `start_line` |
| Config / compliance | `control_id` or `rule_id`, `resource_key` | — |
| DAST | `rule_id`, `normalized_url`, `method`, `param` | — |
| License | `purl_base`, `license_id` | — |

- If every field after `family` is empty, `finding_key` is the hash of the canonical JSON of the raw record and the finding is flagged `weak_fingerprint`. Weak fingerprints are counted in run stats and shown in the UI.
- `canonical_vuln_id` at parse time uses only the identifiers in the record and the alias table as it exists: prefer a CVE, else the smallest GHSA, else the first identifier. When enrichment later links an identifier to a CVE, a `RekeyJob` computes the new key; if a finding with the new key exists the two are merged (older `first_seen` wins, events kept), otherwise the key is updated. `finding_key_alias(old_key → finding_id)` keeps old keys resolvable for one retention period so triage memory and VEX still match.
- `scanner_family` for SARIF input comes from a table keyed by lower-cased `tool.driver.name`: `semgrep`, `codeql`, `trivy`, `grype`, `gitleaks`, `checkov`, `bandit`, `nuclei`, `snyk`, `zap`, `kics`, `dependency-check`, `osv-scanner`, `scorecard`, `hadolint`. Unknown drivers get `sarif:<driver-name>`. There is no bare `sarif` family.
- Field names are fixed as: `rule_id`, `file_path`, `logical_location`, `snippet_hash`, `canonical_vuln_id`, `purl_base`, `manifest_path`, `image_repository`, `secret_hash`, `resource_address`, `resource_key`, `control_id`, `normalized_url`, `method`, `param`, `license_id`. (`purl_no_version`, `uri`, `function` in older examples are aliases to be removed.)
- Go types to define in Phase 0: `Location` (struct with optional `Code`, `Package`, `Web`, `Resource`, `Image` parts), `ParseContext` (upload context + source options + limits), `Hint` (filename, content type, declared format), `VEXStatement`, `CVSSVector`.

## D12. Occurrences (closes M4 and inconsistency 23, 24)

An **occurrence is the current evidence of one finding from one source at one concrete location**, not a per-run log.

- Unique key: `(tenant_id, finding_id, scan_source_id, occurrence_key)` where `occurrence_key = SHA-256(tool_record_id)` when the tool gives a stable id, else the hash of the full location including line and version.
- Columns: `first_seen`, `last_seen`, `last_ingest_run_id`, `seen_count`, `present` (bool), `asset_version`, `tool_severity`, `cvss_vectors`, `location`, `normalized`, `raw`.
- Each run upserts: seen → `present = true`, `last_seen`, `seen_count + 1`, `raw` replaced. Not seen in a run of the same scope → `present = false`.
- Occurrences with `present = false` are deleted after `RetentionPolicy.occurrencesDays`. The table is not time-partitioned.
- `finding.occurrence_count` = number of occurrences with `present = true`. Counters are always recomputed from rows, never incremented, so a retried batch cannot double-count.
- History ("which run saw this") lives in `finding_event` and `ingest_run` stats, which are partitioned by time.
- `finding_source` is removed; `occurrence.present` replaces it.

## D13. Merge and reimport-close (closes B9, B10)

**Scope of a run.** `close_scope = (tenant_id, scan_source_id, scanner_family, asset_id, track)`. One `ingest_run_scope` row per scope touched by the run.

**Locking.** Before merging a scope, the parser takes `pg_advisory_xact_lock(hashtextextended(close_scope_text, 0))` in each batch transaction, and a session-level advisory lock for the whole run. Two runs on the same scope are therefore serialised; runs on different scopes proceed in parallel.

**Ordering.** Each scope stores `last_applied_scan_finished`. A run whose `scanFinished` is older is marked `stale`: stored, visible, not merged, nothing closed.

**Staging.** `ingest_staging` is an unlogged table without RLS, written only by `COPY` from the parser, keyed by `(ingest_run_id, seq)`. Rows are deleted when the run ends (never truncated). `COPY` is used only for this table, because PostgreSQL does not support `COPY FROM` on tables with row-level security; tenant tables are written with `INSERT … SELECT`.

**Per batch** (one transaction, ≤ 5 000 staged rows):

```sql
with batch as (                       -- one representative row per finding_key
  select distinct on (finding_key) *
  from ingest_staging
  where ingest_run_id = $run and seq between $lo and $hi
  order by finding_key, severity_rank desc, seq
),
existing as (
  select f.id, f.finding_key, f.state, f.content_hash, f.severity_override_reason
  from finding f join batch b on b.finding_key = f.finding_key
  where f.tenant_id = $tenant
  for update of f
),
ins as (
  insert into finding (id, tenant_id, finding_key, …, state, first_seen, last_seen, content_hash, version)
  select b.new_id, $tenant, b.finding_key, …, b.initial_state, b.seen_at, b.seen_at, b.content_hash, 1
  from batch b
  where not exists (select 1 from existing e where e.finding_key = b.finding_key)
  on conflict (tenant_id, finding_key) do nothing
  returning id, finding_key
),
upd as (
  update finding f set
    last_seen     = greatest(f.last_seen, b.seen_at),
    location      = b.location,
    tool_severity = b.tool_severity,
    title         = case when $merge = 'keep' then f.title       else b.title end,
    description   = case when $merge = 'keep' then f.description else b.description end,
    severity      = case when $merge = 'keep' or e.severity_override_reason is not null then f.severity else b.severity end,
    cvss_vector   = coalesce(b.cvss_vector, f.cvss_vector),
    content_hash  = b.content_hash,
    state         = case when e.state = 'fixed' and not $do_not_reactivate then 'open' else f.state end,
    resolution    = case when e.state = 'fixed' and not $do_not_reactivate then null   else f.resolution end,
    resolved_at   = case when e.state = 'fixed' and not $do_not_reactivate then null   else f.resolved_at end,
    reopened_count= f.reopened_count + (e.state = 'fixed' and not $do_not_reactivate)::int,
    version       = f.version + 1,
    updated_at    = now()
  from batch b join existing e on e.finding_key = b.finding_key
  where f.id = e.id
  returning f.id, f.finding_key, e.state as old_state, f.state as new_state,
            (e.content_hash is distinct from b.content_hash) as changed
)
select 'created' as outcome, id, finding_key from ins
union all
select case when old_state = 'fixed' and new_state = 'open' then 'reactivated'
            when changed then 'updated' else 'untouched' end, id, finding_key from upd;
```

Notes:
- `existing` captures the pre-update state, so reactivation is detected on PostgreSQL 16 without `RETURNING old`.
- `content_hash` is SHA-256 over the fields a rescan may legitimately change: title, description, tool severity, CVSS vectors, fixed version, location without line and column. It defines "updated".
- Two staged rows with the same `finding_key` in one batch are collapsed by `distinct on`; all of them still become occurrences.
- `fieldMerge` has two values: `scanner` (default; the scanner's text and severity replace stored ones unless an analyst overrode severity) and `keep` (stored text and severity win; only `last_seen`, location and occurrences change). The value `merge` is dropped.
- After the statement, in the same transaction: upsert occurrences (`INSERT … SELECT … ON CONFLICT … DO UPDATE`), insert `finding_event` rows for `created`, `reactivated`, `updated`, set `search` and promoted columns, restart SLA for reactivated rows when the policy says so, and enqueue enrich and policy jobs keyed by run.
- A lost insert race (`on conflict do nothing` returns no row) cannot happen inside one scope because of the lock; across scopes keys differ by construction.

**Close step** (once per scope, after the last batch, only if the run has status `completed`, i.e. zero record errors):

```sql
-- 1. occurrences of this scope not seen in this run
update occurrence o set present = false
where o.tenant_id = $tenant and o.scan_source_id = $source and o.scanner_family = $family
  and o.asset_id = $asset and o.track = $track
  and o.present and o.last_ingest_run_id <> $run;

-- 2. findings with no present occurrence left, in an active state
update finding f set state = 'fixed', resolution = 'fixed', resolved_at = now(), version = version + 1
where f.tenant_id = $tenant and f.asset_id = $asset and f.track = $track
  and f.state in ('open','under_investigation','affected')
  and not exists (select 1 from occurrence o where o.finding_id = f.id and o.present)
returning f.id;       -- → finding_event 'closed_by_rescan', stats.closed
```

Rules:
- A finding reported by two sources stays open until **both** stop reporting it.
- Findings in `not_affected`, `risk_accepted`, `out_of_scope`, `duplicate` keep their state; only their occurrences flip to `present = false`, which the UI shows as "no longer detected".
- `minimumSeverity`: a staged record below the threshold does not create a finding, but if the finding already exists its occurrence is refreshed, so it is not closed by absence.
- `closeOldFindings = false`: step 2 is skipped; step 1 still runs.
- `closeScope: application` widens step 1 and 2 from one asset to all assets of the application for that source and family.
- A run with `record_errors > 0` ends as `completed_with_errors` and skips the close step.

## D14. Phase 1 read path and risk (closes M1, M2)

- The explorer reads the `finding` table directly; it **is** the denormalized read model (`finding_view` does not exist). `application_summary`, `hierarchy_rollup`, `trend_daily`, `control_status` are the aggregate read models, added in Phase 2.
- In Phase 1 the parser sets `severity` and a provisional `risk_score` from the built-in base table (critical 600 … info 10) plus KEV and EPSS points when the vulnerability row already has them. The `policy` target takes over scoring in Phase 2 with the same formula.
- `vulnerability` rows: the merge inserts a stub (`id`, `aliases` from the record) when a finding references an unknown identifier. Phase 1 alias and metadata sources are OSV (bulk dumps), KEV and EPSS; NVD is added in Phase 2. `vulnerability.id` never changes; if a stub `GHSA-…` later maps to a CVE, a new CVE row is created, `vulnerability_alias` points both to the CVE row, and findings are re-pointed by the `RekeyJob`.

## D15. Parsing libraries and streaming (closes M6)

- SARIF, Trivy, Grype, Semgrep and generic JSON use a hand-written `encoding/json` token walk over the results array, with our own struct types for single elements. (This said `go-sarif` supplies them; it was never used, D54.)
- CycloneDX and SPDX documents are decoded whole with our own structs over `encoding/json` and `encoding/xml` (not `cyclonedx-go` / `tools-golang`, D54), under a size cap and a parser memory limit. SBOMs are bounded by component count, so this is acceptable.
- Every parser has a decompression and nesting-depth limit and a fuzz test.

## D16. Query grammar, cursors, sorting (closes B13)

```
query   = term { SP term } ;
term    = [ "-" ] ( field ":" values | text ) ;
values  = value { "," value } ;                  (* OR within a field *)
value   = bare | quoted | range | wildcard ;
range   = ( ">" | ">=" | "<" | "<=" ) ( number | duration | date ) ;
wildcard= bare "*" ;                              (* prefix match only *)
quoted  = '"' { any char, \" escaped } '"' ;
text    = bare | quoted ;                         (* full-text search *)
duration= number ( "h" | "d" | "w" ) ;
```

Terms are ANDed. `-` negates a term. No parentheses and no cross-field OR in v1.

Phase 1 fields and their columns: `state`, `severity`, `risk` (band), `score` (range), `category`, `scanner`, `rule`, `cve` (vulnerability id or alias, prefix wildcard), `cwe`, `app` (slug), `asset` (key prefix), `assettype`, `env`, `track`, `path` (file path prefix), `purl` (purl_base prefix), `tag`, `owner`, `kev` (bool), `fix` (bool), `sla` (`breached`, `due:<duration>`), `age` (range on `first_seen`), `seen` (range on `last_seen`), `source`, `run`.

- The parser lives in Go (`internal/query/grammar`). The SPA has its own TypeScript implementation; both run the same shared test vectors (`grammar_cases.json`), which keeps their behaviour identical.
- SQL is built by a small internal builder with positional arguments (no string interpolation of values). `sqlc` is used for static queries only.
- Sort keys in Phase 1: `-score` (default), `score`, `-seen`, `-age`, `age`, `severity`. Each has a covering index that starts with `tenant_id`.
- Cursor: base64url of `{sort key values, id}` plus an HMAC; opaque to clients; invalid after a sort or filter change.

## D17. Small decisions (closes M9–M13, nits)

- A namespaced CR in a namespace that has no `Tenant` gets `Ready=False`, reason `TenantNotFound`.
- Hierarchy path labels are slugs: lower-case, `[a-z0-9_]`, other characters replaced by `_`, to satisfy `ltree`.
- `scheduler` belongs to the `write` composite. `mcp` is always its own Deployment.
- River retry policy: 25 attempts with exponential backoff for transient errors (network, 5xx, lock timeout); permanent errors (unparseable report, hash mismatch, unknown format) fail immediately with a typed code on `ingest_run.error`.
- Problem type catalogue (prefix `https://rampart.aspm.dev/problems/`): `validation`, `unauthorized`, `forbidden`, `not-found`, `conflict-version`, `idempotency-key-reused`, `rate-limited`, `quota-exceeded`, `payload-too-large`, `unsupported-format`, `upstream-unavailable`, `internal`.
- Fixtures live in `internal/parsers/<name>/testdata/<tool-version>/`. `hack/fixtures` holds only large load-test inputs.
- Test requirements: a cross-tenant leak test runs every list and get endpoint as tenant A against tenant B data; a seed generator (`hack/seed`) builds the 5M-finding benchmark database; the ingestion benchmark and its 60 s target were withdrawn after measurement (D35).
- Report generation moves to `POST /api/v1/report-jobs` so it no longer collides with `POST /ingest/v1/reports`.
- Event names are `rampart.<entity>.<verb>` everywhere, for example `rampart.finding.sla_breaching`.
- Enum spelling: CRD fields use camelCase (`apiPull`, `azureBoards`); database and API values use snake_case (`api_pull`, `azure_boards`); the mapping is mechanical.
- Category enum: `sast`, `sca`, `secret`, `iac`, `container`, `dast`, `cspm`, `compliance`, `license`, `supply_chain`.
- SAML is implemented in-process with `crewjam/saml`. Dex or Keycloak are only for LDAP and non-OIDC social logins.
- The SLA matrix axis is **risk band × application business criticality**.
- `ClusterFeedMirror` is the only feed-mirror kind. GHSA data comes through OSV.
- API tokens have an optional `scan_source_id` column that restricts an ingest token to one source.
- Arabic ships in Phase 4; English only before that. RTL-safe CSS (logical properties) is required from Phase 1 so the later locale is not a rewrite.

## D18. Detection and disposition are separate (closes architecture finding 5)

A finding carries two independent facts:

| Field | Values | Set by |
|---|---|---|
| `detection` | `present`, `absent` | derived: `present` when any occurrence has `present = true` |
| `state` (disposition) | `open`, `under_investigation`, `affected`, `not_affected`, `risk_accepted`, `out_of_scope`, `duplicate`, `fixed` | people, policies, upstream triage, and the close step |

Rules that follow:
- The close step moves only active dispositions to `fixed`. For `risk_accepted`, `not_affected`, `out_of_scope` and `duplicate`, `detection` becomes `absent` and the UI shows "no longer detected".
- **Risk-acceptance expiry on an absent finding resolves it** (`fixed`, `resolution = fixed`) instead of reopening it. Expiry on a present finding returns it to the disposition it had before acceptance (stored in `previous_state`), not always to `open`.
- Reactivation (`fixed` → active because the scanner reports it again) also restores `previous_state`.
- A `not_affected` decision on a code finding stores the `content_hash` it was made against. If the code at that location changes (`content_hash` differs), the finding is flagged for re-review and listed under "decisions to re-check"; it is not silently trusted forever.
- `verified` is removed. "Confirmed" is the `affected` state.
- An upstream state of "resolved" (for example Dependency-Track `RESOLVED`) while the component is still listed maps to `not_affected` with a note, never to `fixed`, so it cannot oscillate with reactivation.

## D19. Global tables are written only by feed sync (closes finding 7)

- `vulnerability`, `vulnerability_alias`, `weakness`, `taxonomy`, `taxon`, `taxon_mapping` and `rule` are written only by `rampart_system` feed jobs from official sources.
- Rule metadata found in tenant reports goes to a tenant-scoped `rule_local(tenant_id, scanner_family, rule_id, …)`. The UI prefers the global rule when one exists and shows the local one otherwise.
- An identifier unknown to the feeds creates a row in tenant-scoped `vulnerability_local`. Aliases asserted by a tenant's report or by Dependency-Track are stored in `vulnerability_alias_local` and affect only that tenant.
- This replaces "the merge inserts a stub" in D14: the stub is tenant-local.
- A tenant can therefore never change another tenant's severity, taxonomy mapping, alias graph or SLA.

## D20. Tenant boundary in the control plane (closes findings 9, 23)

- A `Tenant` (cluster-scoped, platform-admin only) lists the namespaces it owns: `spec.namespaces: [payments, checkout]`. The binding comes only from that list. The namespace label is informational and never trusted.
- Config identity is `(tenant, kind, namespace, name)`. Teams inside one tenant can therefore have their own namespaces with ordinary Kubernetes RBAC between them, and still share hierarchy, dedup and roll-ups. A namespace may set a default hierarchy node.
- `ReportIngest.spec.object` must point inside the tenant's own prefix (`tenants/<tenant_id>/…`) in the configured raw bucket. The reconciler rejects anything else with `Ready=False`, reason `ObjectOutsideTenant`.
- Watching the **local** cluster or any cluster with operator credentials is only possible through the cluster-scoped `ClusterScanSource`, which a platform admin creates and which names the target tenant per namespace selector. A namespaced `ScanSource` of type `kubernetes` must supply its own kubeconfig Secret.
- Creating an `AccessBinding` in a tenant namespace is equivalent to tenant administration. This is documented, and the Helm chart ships a narrower ClusterRole for team members that excludes `accessbindings`, `identityproviders` and `connectors`.
- The CRD kind `Application` keeps its name; it is addressed as `applications.rampart.aspm.dev` with short name `rapp` to avoid confusion with Argo CD's `Application`.

## D21. Config rows, deletion, status volume (closes finding 14)

- Config rows are keyed by `(tenant_id, kind, namespace, name)`; the CR uid is an attribute. Re-applying CRs from Git after a restore re-attaches to the same rows and ids.
- A UI-created object and a CR with the same `(kind, name)` in a tenant conflict: the CR gets `Ready=False`, reason `NameTakenByUI`, until one is renamed or the UI object is "adopted" (an explicit action).
- Deleting a CR:

| Kind | On delete |
|---|---|
| `Application`, `HierarchyNode` | The row is kept and marked `managed_by = none` (orphaned, editable in the UI). Findings are untouched. `spec.deletionPolicy: Archive` instead archives the application and closes its findings with `resolution = deleted_asset` |
| `ScanSource`, `Connector`, `IdentityProvider` | Disabled, tokens and webhooks revoked (finalizer), history kept |
| Policies, `Exception` | Removed; findings they affected are re-evaluated |
| `Tenant` | Refused while data exists unless `spec.deletionPolicy: Purge` |

- Status is throttled to one write per object per 5 minutes (immediately only on condition changes). Rolling counters (`ingests24h`, `logins24h`, `evaluations24h`) are **not** written to status; they are Prometheus metrics. Status keeps conditions, ids, `lastIngest`, and open-finding counts by band.
- The operator needs egress to connector, Dependency-Track and IdP endpoints for validation probes; the NetworkPolicy table in 15 §5 gains that row. KEDA needs a read-only database role (`rampart_keda`, `SELECT` on a queue-depth view) and a network path to PostgreSQL.
- Watching reports in managed clusters moves out of the operator into a separate `collector` target (it has an S3 path, content-hash dedup and a per-subject debounce, and it produces ordinary ingest runs). It is deferred to after v1.0.

## D22. Ingest credentials and CI federation (closes finding 11)

- The tenant is part of the request: ingest endpoints are `/ingest/v1/t/{tenant}/…`, and the federated token audience is `rampart:<public-host>:<tenant>`. A token is only matched against that tenant's trust rules.
- Trust rules match immutable identifiers (`repository_id`, `repository_owner_id`, GitLab `project_id`, `namespace_id`), with names allowed only as an additional display check.
- The CI token is exchanged once (`POST /ingest/v1/t/{tenant}/token`) for a 15-minute Rampart ingest token bound to the source and the derived context. Replays of the original token after exchange are rejected by `jti`.
- **Clients may tighten, never loosen.** `minimumSeverity` can only be raised above the source's value for *creating* findings and never affects closing (D13). `closeOldFindings` and `doNotReactivate` are source settings; a request can only turn closing off.
- Closing happens only for tracked refs (D10).
- **Mass-close guard**: if a run would close more than `ingestionPolicy.maxClosePercent` (default 50%) of a scope's open findings and more than 20 findings, the close step is held, the run ends as `completed_with_errors` with reason `close_held`, and a maintainer confirms or discards it.
- ServiceAccount tokens are verified against the issuing cluster's OIDC discovery and JWKS (registered per `ClusterScanSource`), so the gateway needs no Kubernetes API access at all. This supersedes the TokenReview line in D1.

## D23. Dependency-Track: scope for v1 and corrections (closes findings 12, 13)

- **v1 ships flows B and C with triage mode `import` only.** SBOM forwarding (A) and write-back (D) follow after v1.0.
- The webhook secret is never written to status. `status.webhookURL` shows the URL without the secret; the secret lives in a Secret created by the operator (`<source>-webhook`). When the DT publisher supports custom headers the secret is sent as a header instead of in the path.
- Debounce is trailing-edge with a dirty flag: an event during a running sync schedules exactly one more sync afterwards.
- A project sync triggered by `BOM_PROCESSED` waits until DT reports analysis settled for that project (processing token finished and the project's metrics `lastOccurrence` is newer than the BOM import); otherwise it retries with backoff. A run that sees components changed but **zero** vulnerabilities where the previous run had some is subject to the mass-close guard (D22).
- An SBOM upload that is forwarded records a `linked_run` on the SBOM ingest run; the CI gate waits for both the SBOM run and the linked Dependency-Track sync run.
- An imported upstream decision that needs approval is stored as a pending upstream decision on the finding (one per finding, replaced not duplicated) and is not pushed back in any mode until it is approved or rejected.
- When write-back ships, change detection uses a per `(finding, matrix)` sync record with the last pushed and last pulled hash, compares human-actor events only, and round-trips `risk_accepted` through a marker in `analysisDetails`. One Rampart finding may map to several DT analyses; the push fans out to all of them and a disagreement on pull is shown as a conflict for a human to settle.
- The DefectDojo-compatible shim is mounted at `/compat/defectdojo/api/v2` (not `/api/v2`), does not auto-create applications unless the source opts in, scopes engagement aliases to the token, and stays in the post-v1.0 list.

## D24. Cross-tool correlation is non-destructive and deferred (closes finding 6)

- v1 keeps one finding per `(scanner_family, fingerprint)`. Findings are never merged into each other across tools.
- A `correlation_key` (for SCA: `canonical_vuln_id`, `purl_base`, asset, track) is stored and indexed. Findings that share it form a **correlation group** used for display ("also reported by Grype"), for one ticket per group, and for counting unique issues. Triage on one member can be applied to the group as an explicit bulk action.
- Statements elsewhere about "one Finding with two Occurrences from different tools" and `source_count` describe the later, optional merge and do not apply to v1.

## D25. Events and automation (closes finding 18)

- The pipeline emits **one event per run and per scope**, carrying the run id and the outcome sets (created, reactivated, updated, closed) as id ranges, not one job per finding. Consumers process sets.
- Aggregate read models are recomputed per application from source rows after a run; they are never incremented.
- Outbound per-finding webhooks and notifications are produced by the `notify` target from those sets, with digesting above a threshold (more than 20 findings in one run produce one summary message).
- Policy actions carry a causation id; a chain stops at depth 3 and at any repeated `(policy, finding)` pair.
- A side effect (ticket, notification) is reserved in `action_ledger(tenant, policy, finding, action)` in the same transaction that decides it, so a retried or repeated event cannot create a second ticket.
- CEL errors: a missing field evaluates the condition to `false` and is counted in the policy's status. For `failGate` policies an evaluation error fails the gate (fail closed) and says so in the reasons.
- Per-tenant fairness is implemented by us, not assumed from River: each tenant has a concurrency cap per queue, enforced by a semaphore table checked at job start (jobs over the cap snooze).

## D26. CI gate semantics (closes finding 24)

- The pipeline declares what it will upload: `rampart gate --expect semgrep,trivy,sbom` (or `POST …/builds` then `…/builds/{id}/seal`). The gate waits for those runs, plus linked Dependency-Track runs, to reach a final status.
- "New" means present in this run and absent from the baseline track (D10). "Fixed" is the reverse.
- The gate endpoint lives on `query-api` (`POST /api/v1/gate`), because it is a read over scored findings; `rampart gate` calls it.
- On timeout the gate returns `pass: false`, reason `timeout`, unless the source sets `gate.onTimeout: pass`.

## D27. Identity corrections (closes finding 20)

- `login.emailDomains` on a tenant `IdentityProvider` takes effect only after a platform admin approves the domain claim (`status.domains[].approved`).
- `AccessBinding` subjects are qualified by identity provider: `{kind: User, idp: okta, subject: 00u1…}` or `{kind: Group, idp: okta, name: payments-devs}`. Email-only subjects are accepted only when the tenant has exactly one IdP with verified email.
- A `ClusterIdentityProvider` lists the tenants allowed to use it; just-in-time provisioning into other tenants is refused.
- Platform roles are bound with the cluster-scoped `ClusterAccessBinding`.
- Refresh-token re-validation takes a per-session advisory lock so only one replica refreshes. SAML sessions are not re-validated; they rely on the absolute lifetime and SCIM.
- Revocation: sessions and tokens are checked against Postgres at most 30 seconds stale (cache TTL), and a revocation publishes a notification that evicts the cache entry on every replica at once. "Immediately" in 14 means "within 30 seconds, normally under one".
- An inbound ticket transition mapped to `risk_accepted` or `not_affected` creates a **request** that follows the approval workflow; it never sets the state directly.
- `query-api` is the API for the UI and automation and therefore serves both queries and commands. The rule in 02 and ADR 0004 is restated as: `query-api` never parses reports and `ingest-gateway` never serves UI data. Reads that follow a write in the same session go to the primary; other reads may use a replica.

## D28. Performance claims restated (closes findings 16, 17, 19)

- One query SLO: **p95 under 500 ms at the API for a supported filter and sort combination on 5 million findings**; p99 under 1 s.
- Supported combinations are a published matrix; each row has an index. Filters outside the matrix work but carry no latency promise.
- `kev`, `epss_bucket`, `fix_available`, `hierarchy_path`, `environment_kind` and `owner_team_id` are denormalized onto `finding` and indexed with `tenant_id` first (using `btree_gin` for array columns). A partial index set covers active states.
- Facet counts are exact up to 10 000 matches and shown as "10k+" above that; counts for the unfiltered view come from roll-ups.
- Time-dependent risk factors are not stored in the score. "Open longer than 90 days" is evaluated at query time as a filter and badge, so nothing needs a nightly mass re-score. EPSS changes re-score a finding only when the vulnerability crosses a band boundary defined in the policy.
- Ingestion target: **withdrawn** (D35). It was "100 000 new SARIF results in under 60 s, rescan in under 20 s"; it was measured and not reached (about 130 s for 100 000 on a laptop), and no throughput figure is promised.
- With D12, a rescan with no changes writes one `UPDATE` per occurrence (`last_seen`, run id) and no new rows, so storage grows with change, not with scan frequency. `raw` evidence larger than 8 KiB is stored in object storage and referenced.
- The `search` vector is maintained asynchronously by the policy target, not in the merge transaction.

## D29. Scope of the first release (closes finding 25)

Adopted cuts for the MVP and v1.0; the roadmap in [09-roadmap.md](09-roadmap.md) reflects them.

| Area | MVP / v1.0 | Later |
|---|---|---|
| Tenancy | Schema, RLS and API are multi-tenant from day one; the product runs with one tenant by default | Tenant self-service, quotas, MSSP |
| CRDs | `Tenant`, `Application`, `ScanSource`, `Connector`, `SLAPolicy`, `RiskPolicy`, `IdentityProvider`, `AccessBinding`, `ReportIngest` | `Policy` (CEL automation), `Exception`, `DedupPolicy`, `RetentionPolicy`, `HierarchyNode`, `ScheduledScan`, `ClusterScanSource`. `ClusterFeedMirror` and `IntegrationPackage` (mappings, declarative connectors, WebAssembly parsers) are inside v1.0; see [19](19-integration-sdk.md) |
| Deployment | monolithic and simple-scalable | distributed with KEDA, NATS, Valkey, MCP |
| Dedup | per-tool fingerprints, correlation groups for display | merge across tools, re-key tooling UI |
| Automation | built-in rules: auto-close by rescan, SLA, one gate rule, ticket on critical | generic CEL action engine with simulate |
| Dependency-Track | pull, webhook trigger, triage import, FPF file | SBOM forwarding, write-back, policy violations, shim |
| Kubernetes report watching | none | `collector` target |
| Identity | OIDC, API tokens, CI federation, built-in roles | SAML, SCIM, custom roles |
| Other | — | SSVC, posture-score formula tuning, scheduled PDF reports |

## D30. Corrections found while implementing Phases 0 and 1

These were found by running the code against PostgreSQL and the HTTP API. Each closes a gap between an earlier section and what can actually work.

- **Roles carry no secrets in SQL (D4).** The migration only creates the four roles as `NOLOGIN` when missing. Passwords and `LOGIN` come from the platform (CNPG managed roles, Helm, `deploy/compose/initdb`). `rampart_app` and `rampart_ro` cannot write `tenant`, `vulnerability`, `vulnerability_alias` or `rule` (D19); tenants are written by `rampart_system`.
- **Migrations use their own connection.** `database.migrateUrl` (`rampart_owner`) is used only for `AutoMigrate` and, since D53, for partition maintenance in the same process; `database.directUrl` remains the application's direct connection for `LISTEN/NOTIFY`. A configured database that cannot be reached is a startup error, never a silent fall back to the in-memory store.
- **The token names its tenant (D8, D4).** Wire format `rpt_<tenant-uuid-hex>_<secret>`. The lookup runs under that tenant's RLS context, so `api_token` keeps the strict policy (an unset tenant sees zero rows). The record must carry the same tenant. The hash is SHA-256; the secret is never stored.
- **No secret in logs.** With a database, the bootstrap admin token goes to `auth.bootstrapAdminTokenFile` once. It is logged only on the in-memory store.
- **One transaction per merge batch (D13).** `Store.InTenantTx` runs the batch under `pg_advisory_xact_lock(hashtextextended(scope))`; the finding upsert, occurrence upsert, counter recompute and `finding_event` rows commit or roll back together. The close step is decided before any write; a held close (D22) changes nothing.
- **Close scope is per scanner (D13).** Records are grouped by `scanner_family` (the tool, not the parser). A report with no findings has no tool to read, so the `scanner` request parameter names it; without it the scope is the parser id and a clean rescan closes nothing. Parsers should later emit run metadata so this parameter is not needed.
- **D22 thresholds.** The guard holds a close that would close more than 50% of the scope's open findings **and** more than 20.
- **Upload context decides the asset (D10).** `repository`, `branch`, `commit`, `imageRef`, `imageDigest`, `environment`, `service`, `version`, `scanFinished` come from the request. A file name is never an asset key. `first_seen`/`last_seen` use `scanFinished` when valid and not in the future (D2). Ephemeral is decided by the branch (PR refs and untracked branches), not by the track name, so `staging` is a normal track.
- **Scan sources are configuration (D3, D10).** An upload names a source by id or name; empty means the tenant's built-in `default` source, created on first use. Any other unknown source is `404 not-found`.
- **Event partitions.** `finding_event` and `audit_event` get a default partition so a row outside the pre-created ranges cannot fail the pipeline; the scheduler's maintenance job still creates monthly partitions ahead of time.
- **PgBouncer.** The pgx pool uses `QueryExecModeCacheDescribe`: no server-side prepared statements, as required by transaction pooling.

## D31. Bundled object storage is SeaweedFS, not MinIO

- MinIO's community edition is in maintenance mode and no longer ships maintained images, so it is not a base to build on. The application only needs the S3 API (D9, doc 15), so the bundled default is **SeaweedFS** (Apache-2.0; one `weed` binary with an S3 gateway), pinned to a version tag. Any other S3 API (AWS S3, GCS interop, Ceph RGW, Garage) is configured through `objectStorage.endpoint` with the bundled store switched off.
- Checked against SeaweedFS 4.53 with the exact calls the gateway needs: bucket creation; a SigV4 presigned `PUT` with `Content-Length` signed in (a body of a different size is rejected with 403, D9); a tampered presigned URL is rejected; object round trip with matching SHA-256; bucket lifecycle rules (retention, doc 15).
- Credentials: the object store itself reads `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` from its environment. The application reads the same two keys from files (D34), never from its environment.
- Helm: `seaweedfs.enabled` (default true) deploys a standalone StatefulSet running as a non-root user; its keys are generated once and kept across upgrades. Compose: the `objectstore` service.

## D32. Browser sign-in, the operator, telemetry and the UI server (Phase 0 and 1)

**Sign-in (doc 14 section 2, D8).**
- `query-api` is the OIDC relying party: Authorization Code with PKCE S256, `state` and `nonce`, ID token checked for signature (cached JWKS), `iss`, `aud`, `exp` and `nonce`. Discovery is lazy and retried, so the platform can start before its IdP.
- The login state (state, nonce, verifier, tenant, `return_to`) sits in a short-lived, single-use cookie sealed with AES-256-GCM under a key derived from `auth.session.keyFile`. `return_to` accepts same-origin paths only.
- A session is an opaque 256-bit secret; only its SHA-256 is stored. The cookie is `<tenant-uuid-hex>.<secret>` so the lookup runs under that tenant's row-level security. Over https it is `__Host-rampart_session` (Secure, Path=/); over http, `rampart_session`. HttpOnly and SameSite=Lax always. Idle 8 h, absolute 24 h, both configurable.
- Revocation is immediate: the lookup joins `app_user` (status) and `tenant_member`, so removing a membership or disabling a person ends the session on the next request. Refresh-token re-validation (D27) is not built yet.
- CSRF: `X-CSRF-Token` equals HMAC(key, session id) and is required on every state-changing request authenticated by a cookie. API tokens are not cookie-based and are exempt.
- Roles never come straight from the IdP. `auth.oidc.bindings` (kind `user` by email or subject, kind `group`) is the Phase 1 form of an `AccessBinding`; the strongest match wins, then the role the person already holds, then `auth.oidc.defaultRole`. An empty result means no access (`no_access`). `email_verified` is required unless disabled.
- A person may read their own memberships across tenants through the `member_reads_own` policy on `tenant_member` (SELECT only, keyed on `app.user_id`); writes still need the tenant context. That is how the tenant switcher lists tenants without a bypass role.
- Failure goes back to the SPA as `/login?error=<code>` with codes `invalid_state`, `idp_error`, `email_unverified`, `tenant_not_found`, `no_access`, `internal`.
- Endpoints: `GET /api/v1/ui-config` (public), `GET /auth/login`, `GET /auth/oidc/{idp}/callback`, `GET /auth/session`, `POST /auth/logout`, `POST /auth/tenant`, `GET /api/v1/me`, `/me/tenants`, `/me/permissions`. Every problem response carries `request_id`.
- Local sign-in: only the single first administrator of D3 (see D33). Regular local users with passwords are not supported: password policy and MFA belong to the IdP.

**Operator (D1, D3, D20, D21).**
- The reconcilers run on controller-runtime against the real API server (tested with envtest and in CI on kind). A status write happens only when the status changed. A resource waiting for a Tenant or a Secret is retried, and a Tenant appearing or changing its namespaces requeues the resources in them.
- It starts only in a cluster or with an explicit `--kubeconfig`. It never reads `~/.kube/config` or `$KUBECONFIG`, so running the binary on a laptop cannot start reconciling whatever cluster the developer happens to be pointed at.
- It creates the namespaces a Tenant lists and one `RoleBinding` per tenant namespace to a ClusterRole that can only read Secrets, so it reads Secrets there and nowhere else. It can only bind that one ClusterRole. Secrets are read with an uncached client, so it needs no list or watch on Secrets cluster-wide.
- Referenced Secrets are encrypted (D1) before they reach PostgreSQL. Deleting a CR does what D49 says: rows are kept, sources are disabled and a tenant with data is refused.

**Telemetry (D6).** `/metrics` is real (Prometheus text) on the ops port: Go runtime and process metrics, HTTP request metrics labelled by the matched route pattern (never the raw path), and `rampart_ingest_runs_total` and `rampart_ingest_findings_total`. With `telemetry.otlpEndpoint` set, traces and metrics are also exported over OTLP/HTTP. Every request has an `X-Request-ID`; logs written with a context carry `trace_id`, `span_id` and `request_id`.

**UI server (doc 13 section 2).** `web/dist` is embedded in the binary and served at `/` with `Content-Security-Policy: default-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'`, `X-Content-Type-Options`, `Referrer-Policy: same-origin`, and HSTS when the public URL is https. Hashed assets are immutable, `index.html` is `no-cache`, client routes fall back to `index.html`, and paths under `/api`, `/auth`, `/ingest`, `/hooks`, `/scim` and `/compat` are 404 rather than the shell.

**Configuration file (D6).** The YAML keys are the documented ones (`server.http.addr`, `database.directUrl`, `auth.oidc.*`); the environment form is `RAMPART_` plus the key path joined with `_`.

**CI.** The Go suites run as separate parallel jobs by dependency (no services, PostgreSQL, a real API server), then Helm, the web build, and a kind job that installs the chart, applies a Tenant, an Application and a ScanSource, checks `Ready=True`, the RBAC limits, encrypted secret material, upgrade and rollback. `hack/e2e/kind.sh` refuses to run on anything but a local kind cluster.

## D33. The first administrator, Dex in the quick start, and the web and CI tooling

**First administrator (D3, doc 14 section 11).** Built as specified there. Decisions worth recording:
- Schema: migration `00002_local_admin.sql` adds `user_id`, `failed_attempts`, `locked_until`, `last_login` and `password_changed_at` to `local_admin`. The account signs in as an `app_user` row with issuer `rampart:local`, so sessions, membership and audit work exactly as for single sign-on. `CurrentExpectedSchemaVersion` is 2 and the chart's `database.minSchemaVersion` is 2.
- The failure counter and the lock are one `UPDATE ... RETURNING` (no read-modify-write), tested with simultaneous guesses on PostgreSQL.
- `audit_event` is now written (it was only a table): `Store.RecordAudit` (partitioned table, `inet` address stored as NULL when unparseable so auditing never fails a request).
- A password change ends the account's sessions in the same transaction.
- The route and the form are JSON only. The cookie, CSRF and revocation rules are those of D32.
- Helm: the Secret `<release>-admin` holds `username` and a generated `password` (kept across upgrades through `lookup`), mounted as a file; `NOTES.txt` prints how to read it. `auth.bootstrapAdmin.enabled` (default true), `.username`, `.keepEnabled`.
- Compose: `deploy/compose/init.sh` writes `.env` with random values for every secret (mode 0600), and renders `dex/config.yaml` from `dex/config.yaml.tpl` with bcrypt hashes of two random demo passwords. Nothing is a default credential.

**Dex in the quick start.** The `mockCallback` connector (which signs anyone in without credentials) is gone. Dex runs with `enablePasswordDB` and two `staticPasswords` users created by hand: `ada@example.com` (bound to `admin`) and `grace@example.com` (a viewer). Dex's password database returns no groups, so roles are bound by e-mail. Dex storage is `memory` in the quick start and must be `kubernetes` or `postgres` in production. The Rampart container shares Dex's network namespace so that `http://localhost:5556/dex` is the same issuer URL for the browser and for the server, with no `/etc/hosts` entry. Dex's config file is mode 0644 because Dex runs as another user in its container; it holds hashes only.

**Web tooling.** The web UI is built and tested with **Bun** (`bun install --frozen-lockfile`, `bun --bun run build|test|lint|typecheck`; lockfile `web/bun.lock`; version pinned in `packageManager` and in CI). The Dockerfiles build the UI in a Bun stage and copy `web/dist` into the Go build, so every image embeds the UI.

**CI.** Parallel jobs after lint: three Go suites by dependency (no services, PostgreSQL, a real kube-apiserver), Helm, the web build, and the Compose quick start (builds the image, starts Dex, PostgreSQL and the object store, signs in both ways); then the kind end-to-end test; then publish and sign. Lessons fixed on the way, kept here so they are not repeated: the linter is built with the job's Go (`go install golangci-lint/v2`), because a linter built with an older Go refuses a module that targets a newer one; `go mod tidy` must leave no diff (CI checks it); a bare `! grep` in a shell step does not fail the step, so negative checks use `if grep ...; then exit 1; fi`; every workflow is checked with `actionlint` and every script with `shellcheck`.

## D34. Presigned upload and the parse worker (Phase 1, first slice)

Built as D2 and D9 specify. What was decided while building it:

- **Create** (`POST /ingest/v1/uploads`): `sizeBytes` is required and must be at most `ingest.maxReportBytes` (else 413), because the size is signed into the URL: the object store itself refuses a body of another size (D9, checked against SeaweedFS). The key is `tenants/<tenant_id>/uploads/<yyyy>/<mm>/<dd>/<upload_id>`; the URL lives 15 minutes. `Idempotency-Key` is kept per tenant for 7 days: the same key with the same body returns the original upload (200), with another body 409. The comparison is a SHA-256 of the request body stored in `upload.request_hash` (migration `00003_upload_idempotency.sql`; schema version 3). Without an object store the route answers 501 and says to use `POST /reports`.
- **Complete** (`POST /uploads/{id}/complete`): checks the object exists with the declared size (else 422), then in **one transaction** marks the upload completed, resolves the asset and application, creates the ingest run (`queued`) and inserts the River job through `InsertTx`. There is never a queued run without a job or a job without a run. A repeated call returns the same run.
- **Worker** (`Processor.HandleParse`, wired in `internal/targets/runner.go`): before any merge it re-reads the object and verifies size and SHA-256 (`size_mismatch`, `sha256_mismatch`); then it streams the report through the parser in batches of `ingest.batchRows` (5 000) per family, each batch merged in its own transaction. It is idempotent: a run already in a terminal state is acknowledged and left alone. Permanent errors (bad hash, unparseable report, unsupported format, report over the limit) fail the run with a stable code and cancel the job; any other error is retried by River, and after 25 attempts the run fails with `retries_exhausted`. The direct `POST /reports` route uses the same `Processor`, so there is one code path.
- **Object store client** (`internal/objectstore`): S3 API over aws-sdk-go-v2 with two clients, one for the server (`endpoint`) and one used only to sign URLs (`externalEndpoint`), because the signature covers the host. The checksum calculation is "when required" so that S3-compatible stores that lack the newer checksum headers still accept the upload. `Memory` is the in-process implementation for unit tests.
- **Configuration**: `RAMPART_OBJECT_STORAGE_{ENDPOINT,EXTERNAL_ENDPOINT,REGION,BUCKET_RAW,ACCESS_KEY_FILE,SECRET_KEY_FILE,USE_PATH_STYLE}`. Keys are files. Helm mounts them from the bundled store's Secret, or from `objectStorage.existingSecret` (keys `accessKey`, `secretKey`) when `seaweedfs.enabled=false`; `objectStorage.externalEndpoint` is the address clients use. Compose passes them as Docker secrets and signs for `http://localhost:8333`.
- **Tests**: `internal/store/presigned_upload_test.go` runs the whole path against real PostgreSQL (as `rampart_app`, RLS on), River and, when `RAMPART_TEST_S3_ENDPOINT` is set (always in CI), SeaweedFS: create, PUT to the presigned URL, complete, the worker finishes, findings exist; repeated complete returns one run; a wrong SHA-256 fails the run and merges nothing; idempotency (same body 200, other body 409); oversize declaration 413; a body of the wrong size is refused by the object store; completing before the upload is 422. CI starts SeaweedFS with `-volume.max=100` because every bucket costs the store volumes, so the tests share one bucket.
- **Not done in this slice**: ephemeral run results for the CI gate, tracked refs from the scan source, the abandoned-upload sweeper. (This said a bucket lifecycle rule would remove them; no such rule was ever configured. D53 removes them.)

## D35. Query over SQL, threat-intelligence sync, aliases, and the first ingest measurements (Phase 1)

- **Query API on SQL (D16).** `GET /api/v1/findings` runs the filter grammar as parameterized SQL with keyset pagination when the store is PostgreSQL (`Store.QueryFindings`, `CountFindings`, built by `internal/query/sqlbuilder`); the in-memory store keeps the in-memory path for tests. The cursor is HMAC-signed and bound to the sort and the filter; a tampered cursor, or one used with another sort or filter, is **400**, never ignored. The signing key is derived from the session key (shared by replicas); the constant key that was in the code is gone. Tested on PostgreSQL: 7 sorts walked page by page with ties on the score (every finding exactly once), filters, a hostile value, a replayed cursor of another tenant.
- **Feed sync (D19).** `internal/enrich` downloads KEV (JSON), EPSS (gzip CSV) and, per ecosystem and opt-in, OSV (`<base>/<ecosystem>/all.zip`) and writes the global tables as `rampart_system`. Every URL can point at a mirror (`feeds.kevUrl`, `epssUrl`, `osvBaseUrl`); downloads are size-capped and refused, not truncated; one feed failing does not stop the others and shows in `feed_state` (migration `00004_feed_state.sql`, schema version 4). One replica syncs at a time (advisory lock). `feeds.enabled` is true in Helm and false in Compose (works offline).
- **Intelligence at read time.** KEV and EPSS are read from the global `vulnerability` table for the ids on the page, not held in memory (`IntelSource`). The `kev:` filter reads the same table.
- **Aliases.** OSV `aliases` only; `upstream` and `related` are directional or loose and are never aliases (OSV schema). The canonical id is the CVE when the record has one, else the OSV id, and every other identifier is an alias of it (docs/03, D11). The `cve:` filter matches the id or any alias, in both directions (D19); KEV and EPSS reach a finding identified by a GHSA id through its CVE alias. The `RekeyJob` is built (D50). Cross-tool merging stays after v1.0 (D24).
- **Ingest throughput: the D28 goal was not reached, and is withdrawn.** D28 asked for 100 000 new results in under 60 s and a rescan in under 20 s. We built the benchmark, measured it on a laptop (i7-7820HQ, PostgreSQL 16 in Docker with default settings), and could not reach it: 10 000 new results took 114 s at first, 62 s after sending each call as one batch, and 13 s after D36; a rescan of 10 000 unchanged results took 55 s, then 12 s. Time is linear (about 1.3 ms per result), so 100 000 results take about 130 s. The rest of the cost is in `UpsertFindings`, which binds 35 parameters per row; the `COPY` into a staging table that doc 12 describes was not built. **Decision (Phase −1 exit: measured numbers replace goals): the 60 s and 20 s goals are removed from D28 and from the Phase 1 exit; the benchmark test was deleted; no throughput figure is promised.** What is kept: ingest streams (heap stayed near 120 MiB for a 25 MiB report), commits per batch of 5 000 and is safe to retry. River's default one-minute job timeout was cutting parse jobs off and is now 30 minutes.

## D36. The hot path drops two foreign keys

- `finding.asset_id` and `finding.application_id` no longer have foreign keys (migration `00005_finding_hot_path_fks.sql`, schema version 5). Measured in PostgreSQL 16, the three keys of `finding` cost about three quarters of its insert time (about 0.14 ms per row and key), and the two on asset and application, which are tables with forced row-level security, are the expensive ones; dropping them took 10 000 results from 62 s to 15 s. The key to `tenant` stays, because it carries the cascade that removes a tenant's data. The keys of `occurrence` and `finding_event` were measured too and cost little (13 s against 15 s), so they stay.
- **The application upholds the invariant.** An asset and an application are resolved or created in the same transaction that writes the finding, so a finding always points at rows that exist. Nothing deletes assets or applications today. **Any future delete of an asset or application (retention, the operator, an API) must delete or re-point its findings in the same transaction.** `TestPresignedUpload_EndToEnd` checks after a real ingest that no finding points at a missing asset or application.
- This is a deliberate departure from doc 12, which lists these keys; doc 12 should be read with this decision.

## D37. Correlation key, ephemeral runs, the CI gate, and a SARIF severity fix (Phase 1 and the gate of Phase 2)

- **`correlation_key` (D24).** Written at ingest and indexed; findings that share it form a correlation group shown as `also_reported_by` on `GET /findings/{id}` (`[{id, scanner, rule_id, state}]`, at most 50). It never merges findings. SCA: canonical vulnerability id + `purl_base` + asset + track, where an identifier that is an alias of a CVE (D11, D19) correlates under the CVE; SAST: first CWE + file path + function (the logical location) + asset + track; other categories have no key. Tested on PostgreSQL: Trivy under a CVE and Grype under a GHSA id of that CVE stay two findings and list each other; an unrelated finding does not join. Parse time still does not resolve aliases: a finding stored under a GHSA key is moved to the CVE's key by the `RekeyJob` (D50), and `finding_key_alias` keeps the old key finding it.
- **Ephemeral runs (D10).** A run from an untracked ref (`refs/pull/*`, `pr/*`, `merge-requests/*`, a feature branch) parses and fingerprints the report **against the baseline track** (`main`) and writes one `ingest_run_result` row per finding (`is_new` = absent or no longer present on the baseline, existing, and `is_fixed` for baseline findings of the same tools that the run lacks). It creates, updates and closes nothing in the inventory, and a retried job replaces its rows. Stats: `created` is new, `untouched` is existing, `closed` is fixed. The baseline track name is not yet configurable per source (`mapping.baselineTrack` is `main`).
- **Tracked runs** store the findings they created or reactivated as `ingest_run_result` rows too (`is_new`), written by the merge, so "new in this run" never depends on a clock (a client's scan time can be minutes older than the upload).
- **CI gate (D26).** `POST /api/v1/gate` on the query API with `{source, context{commit|imageDigest}, expect[], wait, timeoutSeconds, failOn}`. It finds the runs of the build by commit or image digest, matches each `expect` entry to a run by the scanner in its report, its declared family or format (`sbom` matches an SBOM format), waits for them to finish (`wait`, polling every 2 s, at most 30 minutes), and answers `{pass, reasons[], summary{new, fixed, existing}, blocking[], runs[]}`. It fails closed: a declared run that is missing, failed or stale, a build with no runs, an unreadable result, and a timeout all give `pass: false`. The built-in rule is "a new or reactivated finding at `failOn` or above blocks" (default `critical`); `failOn` is ours, and the generic `Policy` rules of doc 05 are Phase 5. Not built: `byBand`, the `url`, the SARIF subset for annotations, waiting for linked Dependency-Track runs (Phase 3).
- **CLI.** `rampart upload` sends `--branch --commit --repository --image-ref --image-digest --environment --scanner --format --build-id --pipeline-url`, defaulting from GitHub Actions and GitLab CI variables (a pull request ref makes the run ephemeral). `rampart gate --commit|--image-digest --expect a,b [--wait] [--timeout] [--fail-on]` calls the endpoint and exits non-zero when it fails. The old `gate` that read the whole inventory is gone.
- **SARIF severity.** `security-severity` was read from the result only; CodeQL, Semgrep and Trivy put it on the **rule**. A result now falls back to its rule's value (a string or a number), so a rule-level 9.5 is `critical`. Found while testing the gate.
- **Parser fuzzing.** Every parser (SARIF, CycloneDX, SPDX, Syft, OpenVEX) has a fuzz test (no panic, no hang, every error an error value); 340 000 to 440 000 executions each found nothing, and CI runs each for 30 seconds.
- **`GetIngestRun`** now reads `context`, which a worker needs (the run's repository, branch and commit).
- **Ingest run page.** `GET /api/v1/runs` and `GET /api/v1/runs/{id}` on the query API (the UI talks only to it). The page lists runs newest first with the selected run docked beside it: how far it got (queued, parsing, merging, enriching, scoring, completed), what it did (records, new, updated, unchanged, reopened, closed, failed records), where it came from (repository, branch, commit, image, build) and, for a failure, the stable error code with a plain sentence. It refreshes every 3 s while a visible run is still going, and a deep link to a run outside the loaded pages fetches it directly. Not built: the link to the raw report and line references for record errors (docs/13), which need the report to be kept and parsed errors to be stored.

## D38. Triage: one decision at a time, with rules in one place (Phase 2, first slice)

- **Rules in the domain, not the handler.** `domain.ApplyTriage` is a pure function that checks a request and applies it to a finding, returning the timeline events. It validates everything before changing anything, so a refused request leaves the finding untouched. It enforces D18: the transition table; `not_affected` needs one of the five OpenVEX justifications (and keeps an optional impact statement); `duplicate` needs the id of another finding and cannot be itself; a justification or `duplicateOf` anywhere else is refused; a severity override needs a reason; tags are trimmed, deduplicated, sorted and bounded (50 tags of 64 characters); a note is at most 4 000 characters. Moving from an active state to a non-active one (`risk_accepted`, `not_affected`, `fixed`, `out_of_scope`, `duplicate`) stores where it came from in `previous_state`; moving back to an active state clears it, the resolution, the justification and `duplicate_of`; reopening a fixed finding counts in `reopened_count`. A request that changes nothing is `nothing to change` (400; `unchanged` in a bulk result).
- **`PATCH /api/v1/findings/{id}`** needs the `triager` role (a `viewer` gets 403; `docs/07`). The actor on the timeline is the caller's email or token subject (it was the literal `user`). `If-Match: "<version>"` (or `version` in the body) is optimistic locking: a stale version is **409** `conflict-version`; without either, the decision applies to the version read at the start of the request. The response carries an `ETag`. The decision and its events are written in **one transaction** (`Store.UpdateFindingTriage`), and only the triage columns are touched, so an ingest cannot be undone by it, and a decision cannot be undone by an ingest.
- **Fixes found on the way.** The old PATCH wrote through the merge upsert, ignored every error (it could answer 200 and save nothing), never persisted a severity override on PostgreSQL, and stored the VEX justification in `state_reason`. `finding` gains `justification`, `impact_statement` and `duplicate_of_id` (migration `00006_triage_columns.sql`, schema version 6; no foreign key on `duplicate_of_id`, D36). The merge upsert no longer adds 1 to `version` on every rescan, which made any scan invalidate the version an analyst held: it takes the larger of the stored version and the one the engine computed, and the engine bumps it where something real changed. The merge now locks the rows it is about to change (`FOR UPDATE`), so a decision made during an ingest waits for it and is not overwritten.
- **`POST /api/v1/findings/bulk`** takes `ids[]` or `q` (exactly one) and a `patch`; each finding is decided on its own, and the answer is `{matched, updated, unchanged, failed[{id, error}]}`: one refusal does not stop the rest. At most 1 000 findings; more is 422 (docs/11 says larger operations become jobs: there is no job runner for that yet, so there is no `bulkOperationId`).
- **`GET /api/v1/findings/{id}/events`** returns the timeline oldest first (`state_changed`, `severity_changed`, `tags_changed`, `note_added`, plus the ingest events), readable by a `viewer`.
- **VEX export** now follows the table of docs/03: `open` and `under_investigation` export as `under_investigation`, `risk_accepted` as `affected` with an action statement, `not_affected` with its justification and impact statement, `out_of_scope` and `duplicate` are not exported. Only findings with a vulnerability id are exported.
- **Tested on PostgreSQL** (`internal/store/triage_test.go`): roles, each refusal, a full decision that is stored and survives a rescan, the timeline's actors, stale and current `If-Match`, two simultaneous decisions on one version (exactly one wins; stable over repeated runs), bulk by ids and by filter with refusals reported, and another tenant getting 404 and changing nothing. **Not built in this slice:** risk acceptance with an owner, expiry and approval (next), notes as their own object, owner assignment, severity-override and tag editing in the UI, and VEX import.
- **A risk cannot be accepted by a plain decision.** `risk_accepted` through `PATCH` or bulk is refused (400): docs/01 C5 and docs/13 want an owner and an expiry, and a plain state change would be an acceptance that never ends. The domain function has an internal `ViaRiskAcceptance` flag for the risk-acceptance flow; it is not part of any API body.
- **UI.** In the findings workbench the inspector has **Change state** (also the `s` key, unless the keystroke is for a field), shown only to a `triager` or `admin`. The dialog offers only the moves the server allows (the same table), asks for the OpenVEX justification on `not_affected` and the finding id on `duplicate`, sends the version it saw as `If-Match`, shows the server's reason when a decision is refused (keeping what was typed), and, on a conflict, says someone else changed the finding and offers to reload. The inspector shows the justification, impact and reason of a decision, and the **timeline** of the finding in words, oldest first. Vitest covers each of these with axe on the dialog; checked in a browser against the dev mock, which now applies the same rules.

## D39. Risk acceptance, tenant settings, and what a decided finding does when it disappears (Phase 2)

- **Model (docs/03, docs/06 section 6).** A `risk_acceptance` covers one or more findings (at most 100) with a justification, an optional impact statement, an **owner** (default: the requester), the requester, the approver, an **expiry** (required, at least an hour away and at most `riskAcceptanceMaxDays`, default 180, settable 1 to 730), `onExpiry` (`reactivate`, the default, or `notify_only`) and `restartSlaOnExpiry`. Statuses: `pending`, `approved`, `rejected`, `expired`, `revoked`. Only the decision `accept` exists (docs/03 also lists mitigate, transfer, avoid). Tables `risk_acceptance` and `risk_acceptance_finding`, both with row-level security, plus `finding.risk_acceptance_id` (migration `00007_risk_acceptance.sql`, schema version 7). A finding can be under only one pending or approved acceptance, and only an open, under-investigation or affected finding can be accepted. A plain `PATCH` still cannot accept a risk (D38).
- **Approval.** The tenant setting `riskAcceptanceApproval` (default off) decides: off, a request is approved at once (approver `system:auto`) and applied; on, it waits, and an approver who is **not the requester** approves or rejects (a rejection needs a reason the requester can read). Approval needs the **`admin`** role: docs/06 says `maintainer`, a role that arrives with scoped access bindings. A triager may revoke what they asked for or own; an admin, anything. Two approvers at once: exactly one wins (a conditional status update).
- **Effects.** Approval puts each finding in `risk_accepted`, remembers where it came from in `previous_state`, links it to the acceptance, and writes `risk_acceptance_approved` and a `state_changed` event on its timeline. A finding that stopped being active between the request and the approval is skipped and reported, and the others still go through. Revoking returns the findings the acceptance still holds to where they came from; a finding someone already moved is left alone. All of it, for one acceptance, is one tenant transaction.
- **Expiry** (a sweeper in the server, every 15 minutes, one replica at a time by an advisory lock; each acceptance in its own tenant transaction): `reactivate` returns each finding to the disposition it had before (docs/16 D18), or **resolves it (`fixed`) when no scanner reports it any more**; `notify_only` leaves the findings accepted and says so on their timeline. Either way the acceptance becomes `expired`. `risk_accepted` may now move back to `affected` (it could not, which would have lost a previous `affected`). **Not built:** the notifications 14 days and 1 day before expiry (they need the connectors and in-app notifications), the SLA pause while accepted and the restart on expiry (they need `SLAPolicy`), exceptions matched by selector at ingest, proof files, and `mitigate`, `transfer`, `avoid`.
- **Tenant settings.** `GET /api/v1/settings` (any role) and `PATCH /api/v1/settings` (`admin`), for `riskAcceptanceApproval` and `riskAcceptanceMaxDays`. The application role may not write `tenant` (D4), so the write goes through a `SECURITY DEFINER` function, `set_tenant_settings(jsonb)`, that updates only the `settings` column of the caller's own tenant.
- **API.** `POST /api/v1/risk-acceptances` (triager), `GET /api/v1/risk-acceptances[?status=]` and `GET .../{id}` (any role), `POST .../{id}/approve|reject|revoke`. Answers carry the acceptance and, for approval and revocation, how many findings were applied and which were skipped and why.
- **Fix found on the way (D18).** When a scanner stopped reporting a finding a person had decided on (`risk_accepted`, `not_affected`, `out_of_scope`, `duplicate`), its `detection` stayed `present` for ever, because the close step only looked at active findings. It now becomes `absent` and the disposition stays, with a `no_longer_detected` event; a scanner that reports it again makes it present again. The finding queries of the close step also lock their rows, so a decision made during an ingest is not overwritten by it.
- **Tested on PostgreSQL** (`internal/store/acceptance_test.go`): roles, each refusal with its reason, the auto-approved and the approval-required paths, rejection, the requester unable to approve their own request, two simultaneous approvals, revocation, expiry of all three kinds (back to `open`, back to `affected`, resolved when absent, `notify_only`), the list by status, the settings (stored, bounded, admin only), and another tenant unable to read, revoke, accept or see settings. **UI.** The inspector has **Request risk acceptance** (also the `e` key, for a triager or admin, on a finding that is open, under investigation or affected): a reason, an optional impact statement, an end date (required, capped by the tenant maximum), an owner (default: you) and what happens at the end. While a finding is accepted the inspector says until when and who owns it. The **Workflow** page lists acceptances (filter by status) with the selected one docked beside it: who asked, who owns it, why, when it ends, who decided; an admin who is not the requester approves, an admin rejects (a reason is required), and the owner, the requester or an admin revokes or withdraws. The timeline of a finding names each step. Vitest covers the dialog, the roles and each refusal, with axe on the dialog and the page.
- **Vulnerability analysis stays in Dependency-Track (D23, docs/10).** Matching components against NVD, GHSA, OSV, OSS Index, Snyk, Trivy and VulnDB is done by Dependency-Track, which is the SCA source of truth for its projects; Rampart does not write its own matcher. Teams without Dependency-Track send reports from scanners (Trivy, Grype, osv-scanner) or a CycloneDX VDR. In v1.0 the pipeline sends the SBOM to Dependency-Track directly; forwarding it through Rampart (flow A) is after v1.0.

## D40. The risk score, band and SLA are stored, and the SLA clock runs (Phase 2)

- **A gap that was there since Phase 1.** The score of a finding was computed only when it was read. In the database `risk_score` stayed 0, `risk_band` stayed `low` and `sla_due_date` stayed NULL for every finding, so the explorer's sort by `-score` and its filters `risk:`, `score:` and `sla:` (all SQL since D35) worked on constants. The earlier test of the SQL path passed because it wrote `risk_score` by hand. The SLA shown was also computed as if every application were `critical`. All of that is fixed.
- **Stored at ingest (`internal/scoring`).** The merge scores every finding it creates, reactivates or updates, before it writes it: score, band, `kev`, `epss_bucket` (high from 50 %, moderate from 10 %, else low), `sla_start` and `sla_due_date`. The inputs are the severity, the KEV and EPSS data of the global `vulnerability` table (aliases included), and the application's criticality, internet exposure and data classification. **The stored score has no age factor** (D28: time-dependent factors are evaluated when read, as the `age:` filter); docs/06 lists age (+30) as a factor, and D28, which wins, says it is not stored. The API explains a score with the same function that stored it, so the number a user sees is the number that sorts. A severity override re-scores the finding and moves its due date.
- **Re-score when the feeds change (D28).** After each feed sync, every tenant's active and accepted findings that have a vulnerability id are re-scored in pages of 500, and only those whose score, band, KEV, EPSS bucket or due date changed are written. A re-score is not a decision: it does not bump `version`, so it never invalidates what an analyst holds.
- **SLA (docs/06 section 4, docs/04 `SLAPolicy`).** `domain.SLAPolicy` with the built-in matrix (band by criticality: 3/7/14/30, 7/14/30/60, 30/45/90/120, 90/120/180/365 days), `maxDays`, and the CISA KEV due date winning when it is earlier. The due date counts from `sla_start` (first seen), is recomputed when the band changes, and **never moves later than a due date that has already been breached**. **Not built:** the `SLAPolicy` and `ClusterSLAPolicy` objects that replace the built-in policy (the engine takes a policy source; only the built-in one exists), `businessDays`, `startFrom: verified`, and the notifications `beforeBreach` and `onBreach` (they need the connectors and in-app notifications).
- **Breach sweep.** Every 15 minutes, one replica at a time, each tenant: an active, unpaused finding past its due date gets `sla_breached_at` once and `sla_breached` on its timeline.
- **Pause and resume.** Approving a risk acceptance pauses the clock (`sla_paused_at`; `pauseDuringRiskAcceptance`, on in the built-in policy). When the acceptance ends and the finding returns to an active state, the time spent accepted is not counted: both `sla_start` and `sla_due_date` move by it (so a later re-score agrees), or, with `restartSlaOnExpiry`, the clock starts again from that moment. `notify_only` leaves it paused.
- **Reactivation restarts the clock** (`restartOnReactivation`, on in the built-in policy): a finding that a scan reports again after it was fixed gets a new start, no breach mark and a new due date.
- **The merge owns the clock columns while it writes.** Its upsert writes `sla_start` and `sla_breached_at` as it read them (or as the reactivation reset them) because it reads those rows under `FOR UPDATE`; the sweeper and the acceptance steps wait for it.
- **Tested on PostgreSQL** (`internal/store/scoring_test.go`): score, band and SLA stored at ingest, ordering and the `risk:`, `score:` filters on real ingested data, the API explaining the stored number, a rescan moving nothing, a severity override, KEV and EPSS changing a stored score and an earlier CISA date winning, a second re-score changing nothing and not bumping the version, the breach sweep (once, not while paused, `sla:breached` finds it), pause and resume shifting the due date by the time spent accepted, `restartSlaOnExpiry`, and reactivation restarting the clock.

## D41. SLAPolicy as a custom resource

- **The object (docs/04).** `SLAPolicy` (namespaced, `rampart.aspm.dev/v1alpha1`, CRD in `deploy/crds/slapolicy.yaml`, kept identical to the chart's by CI): `matrix` (days, by risk band and application criticality), `caps.kevDueDate`, `caps.maxDays`, `startFrom`, `restartOnReactivation`, `pauseDuringRiskAcceptance`, `businessDays`, `notify`. What is left out takes the built-in value, so `spec: {}` is the built-in policy. The CRD schema bounds the days (1 to 3650) and `startFrom`; the operator checks the rest, with one set of rules shared with `rampart apply` (`domain.ParseSLAPolicySpec`).
- **What this version refuses, instead of ignoring.** `businessDays: true` and `startFrom: verified` are not built; a policy that asked for them and silently did something else would be worse than one that says it is not applied. Such a spec is stored with its reason, the object's `Ready` is `False` with reason `InvalidSpec` and the message, and `rampart apply` exits with the error. `notify` is accepted and not acted on (notifications need the connectors).
- **An invalid edit does not undo a valid policy.** `policy_object` keeps `spec` (what was asked) and `applied_spec` (the last spec that passed validation, which is the one in force) apart. A typo changes the first and `compile_error`, never the second, so it cannot quietly put a tenant back on the built-in policy and loosen its deadlines.
- **Which policy applies.** Per tenant: the object named `default`, else the one whose name sorts first; with none, the built-in policy (docs/06 section 4). **Not built:** `ClusterSLAPolicy` (a cluster-wide default between the namespace policy and the built-in one), and selecting a policy per application (docs/04 shows no selector, and the resolution order in docs/06 mentions one).
- **Recompute (docs/04: "enqueue recompute job when changed").** Saving a valid spec that differs from the one in force sets `policy_object.recompute_needed`. The 15-minute SLA sweep recomputes every active finding of a flagged tenant first (the due date follows the new policy; a due date already breached is never moved later), clears the flag, and then marks breaches. Saving an identical spec, or an invalid one, flags nothing. The policy the engine reads is cached for 30 seconds per tenant.
- **Storage.** `policy_object` (migration `00009_policy_object.sql`, schema version 9), keyed `(tenant, kind, namespace, name)` as D21 says, with row-level security; the operator writes it as `rampart_system`, the application reads it and clears the flag. Deleting the object keeps the row (D21).
- **Tested.** The CRD against a real kube-apiserver and etcd (envtest): a valid policy becomes `Ready`, the schema refuses 0 days, the operator refuses business days with a reason. The reconciler (valid, invalid and its stored reason, no tenant). `rampart apply`. On PostgreSQL: a stored policy replaces the built-in one for new findings and, once recomputed, for existing ones; another tenant's due dates do not move; an identical spec flags nothing; a changed one does; an invalid one flags nothing, keeps the policy in force and keeps its reason; `default` wins over another name.
- **Also not built, in the same area:** `RiskPolicy` and `ClusterRiskPolicy` (the factors are CEL expressions, which need the CEL engine), so the scoring factors are still the built-in ones (D40).

## D42. Native parsers for Trivy, Grype, Semgrep, Gitleaks and TruffleHog (Phase 2)

- **What they read.** The report each tool writes by default, not its SARIF: Trivy JSON (schema 2: package vulnerabilities of OS and language packages, secrets, misconfigurations that failed, licenses), Grype JSON (matches), Semgrep JSON, Gitleaks JSON (an array) and TruffleHog JSON lines. Their SARIF output still goes through the SARIF parser. Each parser is a token walk, so memory does not grow with the report (D15): Trivy walks into the `Vulnerabilities` of each result, the others one record at a time. A line of 4 MiB or more, or a document nested more than 200 deep, is refused. Each has fixtures under `testdata/`, tests for mapping, detection, key stability and malformed input, and a fuzz test (`parseutil` too); CI fuzzes each for 30 seconds.
- **Detection without a hint.** Each parser scores a head of 64 KiB on its own structure and scores 0 on a SARIF document; `internal/integrations/detect_test.go` checks that every fixture of every parser, the SBOM and VEX ones included, goes to its own parser and to no other. The processor falls back to this when the client does not name a format.
- **Mapping.** Package vulnerabilities are `sca`, with the canonical package URL (derived from the package manager when the tool gave none) and the manifest or image path, so the fingerprint (D11) rests on vulnerability, package and manifest. Severity is the tool's, and when it says unknown or nothing, the CVSS score decides (docs/05 section 3); Grype's "negligible" is the lowest. Semgrep: ERROR high, WARNING medium, INFO low; CWEs from `metadata.cwe` (a string or a list); the code snippet hash from `lines`, which Semgrep's open-source build hides (then the line number is the fallback, a weak fingerprint). Trivy `not_affected` vulnerabilities and `PASS` misconfigurations are not findings.
- **Secrets are never stored.** Gitleaks, TruffleHog and Semgrep secret rules give the secret to the pipeline, which hashes it for the fingerprint (D11); the raw record that is stored has it replaced by `[redacted]`, and the snippet is dropped. TruffleHog's own "redacted" form is shortened to its first four characters, because the test that scans the database found it keeps 20 characters of a GitHub token. A test uploads all of these reports through the whole pipeline and searches every raw, location and description column for each secret.
- **TruffleHog verification (docs/06 SECRET_VERIFIED).** TruffleHog tries a credential against its provider. A verified one is critical, an unverified one high, and `finding.secret_verified` (migration `00010_secret_verified.sql`, schema version 10) feeds the +250 factor of the risk score. Verification changes the severity and the score, not the identity: a credential that is later revoked is the same finding, updated, with a lower score (tested).
- **Fixes found on the way.** (1) The canonical vulnerability id was the first one the parser gave; D11 says a CVE, else the lowest GHSA, else the first: Grype reports the GHSA it matched on and the CVE related to it, so findings were keyed and shown by the GHSA. `normalize.CanonicalVulnID` now does what D11 says, in the fingerprint and in the pipeline. (2) A presigned upload chose its asset before reading the report, from the format the client declared, so an image scan without a declared format became a repository asset. It now detects the parser from the first 64 KiB, as the worker does: SCA reports of an image go to an image asset (D10).
- **Not built.** Reading the image name from the report when the client gave no `imageRef` (D10 says the report target is an image); Trivy's `Packages` (an SBOM inside a vulnerability report) and its Kubernetes and cloud scans; Grype's ignored matches; detect-secrets (listed in docs/05).


## D43. Overview and Applications (Phase 2)

- **Live aggregate queries, not read models.** docs/09 names `application_summary` and `trend_daily` tables. At the size this version targets, one grouped query over the active findings (indexed by tenant and application) answers in milliseconds and cannot be stale, so no table, refresher or migration was added (schema version stays 10). If a tenant outgrows it, the same `Aggregator` interface can be backed by a table.
- **Endpoints** (all tenant-scoped through RLS): `GET /applications` (summary rows), `GET /applications/{id}/summary` (adds SLA standing, MTTR, coverage and `top_findings`), `GET /overview?sinceHours=` and `GET /trends?metric=open|new|closed&days=` (at most 180).
- **SLA adherence** is `within / (within + late + breached)` over the last 90 days of resolved findings, where still-open findings past their deadline count as breached. MTTR is the mean of `resolved_at - first_seen` per band over the same window.
- **Coverage** is the last completed run of each asset and scanner, from `ingest_run_scope`. "Not scanned lately" lists applications with no completed scan in 14 days, or never.
- **Trend limits.** History is rebuilt from `first_seen` and `resolved_at`, so a finding that was reopened shows as open for its whole life, and accepted findings count as closed. A daily snapshot table would remove both; not built.
- **Not built.** "Newly exploited" in the Overview (needs KEV/EPSS change history); see D44 for which tools reported a finding.
- **UI** follows docs/13 §6: sentences and ruled lists, no tiles or pills, colour only for risk; the trend is a plain line with a text alternative and a table behind "Show the numbers".

## D44. "Reported by" on a finding (Phase 2)

- **The question.** "Which tool, or which two or three, reported this, and since when?" ArmorCode, DefectDojo and similar platforms answer it by listing the source tools on the finding. Their model merges the same issue from several tools into one record with several sources. Ours does not merge (D24): each tool keeps its own finding, and findings that share a `correlation_key` form a group. So the answer has two parts.
- **This finding's own tools.** `GET /findings/{id}` returns `reported_by`: its `occurrence` rows folded by tool family (`Reporter`): name, version of the latest scan, first and last time it reported, number of scans, whether the latest scan of that tool still reports it (`present`), what the tool itself rated it, and the latest run. One tool with many scan sources is one line. The oldest report comes first.
- **The same issue in other tools.** `also_reported_by` (D37), shown in the same section with the tool, the state of that finding, and a link to it. Together they read "Trivy 0.58 still reports it; Grype also found this, as another finding (open)".
- **A tool that stopped.** `present = false` is shown as "no longer reports it". It is the signal that a tool was removed from the pipeline or that the issue was fixed in the code that tool scans.
- **Filter.** `scanner:grype` now matches a finding the tool reported through any occurrence, not only the family of the finding's rule.
- **Not built.** A column in the findings table; counting unique issues across a group; merging (still after v1.0, D24).

## D45. In-app notifications (Phase 2)

- **What and why.** The MVP exit says "deadlines breach and notify in-app". The sweeps already knew; now they tell. Slack, email and webhooks are Phase 3 and will read the same rows.
- **Schema** (migration `00011_notifications.sql`, schema version 11): `notification` (tenant-wide, RLS) and `notification_marker` (one `read_at` per user and tenant). What a user has read is one timestamp, so "mark all read" is one write and an unread count is one query. `finding.sla_warned_at` and `risk_acceptance.expiry_warned_days` make each warning go out once.
- **Events.** (1) Findings that passed their deadline, from the breach sweep: one message per sweep, with the count, so a sweep after an outage is not a flood. (2) Findings due within 24 hours (docs/06 `beforeBreach`), once each; a changed due date clears the mark. (3) A risk acceptance ending in 14 days, then in 1 day (docs/06). (4) An acceptance that ended, with what happened to its findings. Each message links to a filtered list (`sla:breached`, `sla:due:1d`) or to the Workflow page; a test follows the link and checks it finds the finding.
- **API.** `GET /api/v1/notifications?limit=` (newest first, `unread` per item and in total) and `POST /api/v1/notifications/read`. Any role may read its own. The in-memory store answers 501.
- **UI.** A bell in the top bar. The unread count is in the accessible name and shown as a bare number, not a badge; the list opens as a menu, unread items in bold, and closing it marks everything read.
- **Not built.** Per-user or per-event routing, digests by email, Slack, Teams and webhooks (Phase 3), notification retention, a page of all notifications, SLA warnings configurable per policy (`beforeBreach` is a fixed 24 hours).

## D46. The audit log (Phase 2)

- **What was there.** `audit_event` existed and recorded sign-in events only. docs/07 says every mutating API call, and "append-only, no UPDATE/DELETE grants"; the application and system roles had both grants. Both are fixed.
- **Recording.** `API.Audited` wraps the HTTP handler: every POST, PUT, PATCH and DELETE on `/api/v1` and `/ingest/v1` by an authenticated caller is recorded with the actor, the route pattern (`PATCH /api/v1/findings/{id}`), the resource type and id, the status the server answered, the address, the user agent and the request id. A refused call (403) is recorded; an unauthenticated one has no tenant and is not. Reads are not. Query strings and bodies are never stored. A failed audit write is logged and does not fail the request.
- **Append-only** (migration `00012_audit_append_only.sql`, schema version 12): `UPDATE`, `DELETE` and `TRUNCATE` are revoked from the application, system and read-only roles, on the parent and on every existing partition. A test runs each statement as both roles and expects "permission denied". Old months leave by dropping a whole partition as the owner (the retention job, built in D53).
- **API.** `GET /api/v1/audit` for administrators: `actor`, `action` (a route or a method prefix), `resourceType`, `from`, `to`, an opaque cursor (a position only; the tenant comes from the session), and `format=csv|ndjson` for export (up to 50,000 rows, the next cursor in `X-Next-Cursor`). Cells that start with `=`, `+`, `-` or `@` are defused for spreadsheets.
- **UI.** Administration shows the audit log with two filters, paging and the two downloads; other roles are told it is for administrators and no request is sent.
- **Not built.** Before and after values of a change (the table has the columns; handlers do not fill them), policy actions and connector pushes as audit events (no such actions yet), audit retention, streaming to an external log store, users, teams and access bindings on the Administration page.

## D47. VEX import and export (Phase 2)

- **What was wrong.** The OpenVEX export ignored `format`, wrote no products, and `/applications/{id}/vex` treated the id as an asset id. The OpenVEX parser was registered as a scan-report parser, so uploading a VEX document created "VEX Statement for CVE-x" findings of severity info, instead of deciding the existing ones (docs/05 section 7); it also could not read OpenVEX 0.2 products, which are objects. All three are fixed.
- **Package `internal/vex`.** `Parse` reads OpenVEX (0.1 string products and 0.2 object products, identifiers, aliases, subcomponents that narrow a statement to packages) and CycloneDX VEX (analysis state, justification, `affects` through `bom-ref` to a component purl; a vulnerability with no analysis is a VDR entry and is skipped). `OpenVEX` and `CycloneDX` write them. A statement that cannot be used (unknown status, `not_affected` with no justification) carries a reason; the rest of the document still goes through.
- **Export.** `GET /api/v1/applications/{id}/vex` and `/assets/{id}/vex`, `format=openvex|cyclonedx` (csaf answers 400, not built). One statement per vulnerability and package. Where several findings speak for the same pair, the most worrying state wins (affected, then under investigation, then fixed, then not affected), so a document never claims "not affected" while an instance is open. `risk_accepted` is exported as `affected` with the reason: a business decision is not an exploitability claim. `duplicate` and `out_of_scope` say nothing and are left out. CycloneDX has nine justifications, OpenVEX five; the original is written as the property `rampart:justification` and read back first, so the round trip is lossless (tested in both formats).
- **Import.** `POST /api/v1/vex?application=&dryRun=` (triager). A statement matches findings by vulnerability id or any alias, in both directions (D19), and package: the same package, and the same version when the statement names one (a statement about lodash 4.17.20 does not decide 4.17.21). A statement with no package is rejected, not applied to a whole product. The decision goes through the same rules as a person's (D38), so an illegal transition or a missing justification is refused per finding, and the state, justification, impact and an action note land on the timeline with the actor `vex:<author>` and the importer's name in the note. The report says: statements, matched, applied, unchanged, newer decision kept, rejected, unmatched, failed. Nothing is created by an import.
- **Precedence** (docs/05: later overrides earlier). Inside a document the statements are applied oldest first. A statement older than a person's decision on the same finding does not override it (`stale`); a newer one does. `dryRun` runs the same rules on a copy and changes nothing.
- **A VEX document is not a scan report.** The ingest worker refuses an OpenVEX upload with `vex_document` and the way to send it, instead of creating findings.
- **CLI and UI.** `rampart vex export --app|--asset --format` and `rampart vex import <file> [--app] [--dry-run]`; the application page links both downloads.
- **Not built.** CSAF (import and export), a UI for import (the CLI and API do it), importing a document that names only a product (an image) without packages, VEX signing, publishing VEX per product release.

## D48. Roles on single applications (Phase 2)

- **Roles.** viewer < triager < maintainer < owner < admin (docs/07). maintainer approves and rejects risk acceptances (before: admin only, noted in D39 as waiting for this); owner also manages access bindings of the applications it owns; admin is the whole tenant and is not scoped. `auth.oidc.defaultRole` and the OIDC bindings accept the two new roles.
- **Model.** The tenant role (`tenant_member`, the OIDC bindings of the configuration, a token's role) stays the floor. An `access_binding` (migration `00013_access_binding.sql`, schema version 13) gives one person or token a role on one application and **raises** the role there, never lowers it. One row per subject and application (a second grant replaces the role). Subjects are matched by e-mail or token subject without regard to case.
- **Enforcement.** An endpoint's door is the highest role the caller holds anywhere; the decision is then checked against the application of the finding it touches. This covers PATCH of a finding, bulk decisions (a finding the caller cannot decide is a named failure, the rest still go through), VEX import (per finding), requesting a risk acceptance (every finding), approving and rejecting (maintainer on every application the acceptance covers) and revoking (the requester or owner, or a maintainer of its applications). A failed lookup of bindings falls back to the tenant role. Removing a binding takes effect on the next request.
- **API.** `GET/POST /api/v1/access-bindings`, `DELETE /api/v1/access-bindings/{id}` (owner of the application, or admin): an owner sees and changes the bindings of the applications it owns and no others, can give any role up to owner, and cannot give admin; a binding it cannot manage answers 404. `managed_by` is reserved for bindings that come from custom resources (those cannot be removed through the API). `GET /api/v1/me/access` returns the tenant role and the roles on applications, so the UI offers a decision only where it will be accepted.
- **UI.** Administration has an Access section for owners and admins (list, give, remove; an owner is offered only the applications it owns). The findings page offers Change state and Request risk acceptance by the role on the finding's application.
- **What this does not do (read it before relying on it).** Reading stays tenant-wide: a binding adds rights, it does not hide applications from a viewer. Restricting reads needs a scope in every query and in row-level security, and is not built. Not built either: the `AccessBinding` custom resource (so bindings are made in the UI and API), group subjects, hierarchy-node scopes (the hierarchy itself is not built), `ClusterAccessBinding`, SCIM, and the casbin engine docs/07 mentions (the rules are a few comparisons, tested).

## D49. Deleting resources, network policies and the ServiceMonitor (Phase 0)

- **Finalizers (D21).** `Tenant`, `Application`, `ScanSource` and `SLAPolicy` carry the finalizer `rampart.aspm.dev/finalizer`. The work is repeatable: if the operator stops halfway, the next pass does it again, and a deletion waits for an operator that is down.
  - **Application:** the row and its findings stay and `managed_by` becomes `none`, so the UI can edit it (migration `00014_crd_deletion.sql`, schema version 14). Applying the resource again takes it back. One made in the UI (`ui`) is never taken over by a resource of the same name, and deleting that resource leaves it alone. `deletionPolicy: Archive` is not built.
  - **ScanSource:** disabled, not deleted (`disabled_at`): its tokens are revoked, the secret material the operator copied for it (`scansource:<name>:*`) is removed, its history stays. An upload to a disabled source is refused with 403 and says to apply the resource again; applying it enables the source again. This is the per-source revocation docs/09 listed.
  - **SLAPolicy:** removed; the tenant's due dates are recomputed against what is left (the built-in policy if nothing is).
  - **Tenant:** `spec.deletionPolicy` is `Retain` (default) or `Purge`. A tenant with applications, assets, findings or ingest runs is **not** deleted under `Retain`: the resource stays, `Ready=False` with reason `DeletionBlocked` and the way out in the message; setting `Purge` on the resource deletes the tenant and everything that belongs to it (every tenant table references it with `ON DELETE CASCADE`; tested, including its audit rows). An empty tenant is deleted without `Purge`. Waiting costs nothing, and the decision is the owner's, on the resource.
  - The operator's ClusterRole gains `update` and `patch` on the four kinds (a finalizer is a change to the object) and `finalizers` on all four.
  - Tested with envtest (the real API server) and on PostgreSQL.
- **NetworkPolicy** (`networkPolicy.enabled`, off by default because the allow-lists depend on the cluster: the ingress controller's namespace and the Kubernetes API address): default-deny in both directions for the pods of the release, then HTTP in from `ingressFrom`, the ops port from `metricsFrom`, DNS, PostgreSQL (the bundled cluster's pods, or the peers in `networkPolicy.database.to`), the object store, the Kubernetes API for the operator (443 and 6443, narrowed by `kubeApiCidrs`), HTTPS out for feeds, the identity provider and connectors (`allowHttpsEgress`; off for an air-gapped install, with `egressExtra` for the mirrors). An external database or object store with no address to allow is refused at render time rather than opened to everyone. The data services themselves (CloudNativePG, SeaweedFS) are not denied by this chart: their own charts and operators own their policies. Needs a CNI that enforces NetworkPolicy. CI renders it on and off.
- **ServiceMonitor** (`metrics.serviceMonitor.enabled`, off by default: it needs the prometheus-operator CRDs): scrapes `/metrics` on the ops port, with `interval`, `labels` (for the Prometheus selector) and an optional `namespace`.
- **Not built.** `ClusterAccessBinding`-style cluster scoped kinds, the `NameTakenByUI` conflict between a resource and a UI object of the same name (a resource does not take over a UI one, but does not say so in `Ready`), a NetworkPolicy for the CloudNativePG and SeaweedFS pods, a PodMonitor.

## D50. The RekeyJob (Phase 1)

- **The problem (D11).** A software-composition finding is keyed by its vulnerability identifier. A scanner that reports `GHSA-…` makes a finding under the GHSA key. Later the feed sync learns that the id is an alias of a CVE; from then on a report that gives the CVE makes a different key, and the flaw would exist twice, with any decision on only one.
- **The job.** `ingest.RekeyTenant` runs after every feed sync, before findings are re-scored. For each software-composition finding whose identifier is not a CVE it asks the alias table for the canonical id. If it differs, it recomputes the key with the canonical id, **first checking that it can reproduce the stored key from what the finding keeps** (a finding whose key it cannot reproduce is counted as `unverified` and left alone, not guessed at). Then `RekeyFinding` runs in one transaction, with the rows locked.
  - **No finding has the new key:** the finding takes the new key and identifier. Timeline event `rekeyed`.
  - **One does:** the two become one. A finding a person decided about outranks one a scan only guessed at; otherwise the older `first_seen` wins (D11). Occurrences, timeline events, risk-acceptance links, older aliases and duplicate-of links move to the winner (an occurrence it already has is not duplicated), tags are united, `first_seen` is the earlier and `last_seen` the later, and the timeline says `merged_duplicate`.
  - **`finding_key_alias(old key → finding)`** records the old key.
- **The old key still finds the finding.** `GetFindingsByKeys` falls back to the alias table, so a tool that goes on reporting the GHSA id updates the same finding instead of creating a second one, and its decisions stand (triage memory, VEX). The pull-request comparison of the CI gate does the same, so a re-keyed baseline finding is not "fixed" in a PR that reports the old id.
- **Tested on PostgreSQL:** rename keeps the finding's identity and decision; the merge keeps the decided one; the aliases exist; a second pass changes nothing; a rescan under the old and under the new id leaves two findings, not four.
- **Not built.** Re-keying other categories (only identifiers have aliases); re-keying on demand through the API.

## D51. Unreadable records and the raw report (Phase 1)

- **Record errors (D13).** A parser can report a record it cannot read (`ParseContext.RecordError`) and go on, instead of stopping the report. The native parsers do for a record of the wrong shape (Trivy, Grype, Semgrep, Gitleaks: an element of the results array, "results 12"; TruffleHog: "record 12"). The message names the field and the type, never the value: a report can hold secrets (tested with a secret in the bad record). The run keeps the count and the first hundred (`ingest_run_error`, migration `00015_run_errors.sql`, schema version 15).
- **Consequence.** A run with unreadable records ends `completed_with_errors`, reason `record_errors`, and **skips the close step**: a report that may be missing findings must not close the ones it does not mention. A pull-request run counts them and ends the same way.
- **Raw report.** `GET /api/v1/runs/{id}/report` streams the report as the scanner wrote it (`attachment`, `no-store`). It needs the **maintainer** role on the run's application, because a secret scanner's report names the secrets; the bytes pass through the API and are never behind a public link; and every download is written to the audit log with who and how many bytes. A report removed by retention answers 404.
- **UI.** The run page lists the unreadable records with where they are, and links the raw report to those who may download it. `GET /api/v1/runs/{id}` carries the list; the list endpoint does not.
- **Not built.** Line numbers: a JSON array has positions, not lines (the position is what is given); recoverable records in the SARIF, CycloneDX, SPDX and Syft parsers. (Retention of raw reports: built, D53.)

## D52. Frameworks and the Compliance screen (Phase 2)

- **Frameworks are data.** `internal/compliance/data/*.json`, embedded in the binary and validated when loaded (a control that matches nothing, a repeated id or an unknown category fails the load; a test covers it). Five ship: **OWASP Top 10 2021** (10 controls, each with the CWE list OWASP publishes under "List of Mapped CWEs", read from the OWASP pages, 196 distinct weaknesses; the lists are kept as OWASP prints them, including a deprecated CWE-100 under A03 and only category-level entries under A06) and the **CWE Top 25** (2025 edition, from cwe.mitre.org), both matched to findings **by weakness**; and **PCI DSS 4.0.1 (requirement 6 and 8.6.2)**, **ISO/IEC 27001:2022 (Annex A technology controls)** and **NIST SSDF 1.1**, matched **by the kind of scan**, because those standards do not list weaknesses: a requirement such as 6.3.3 (patching known vulnerabilities) is evidenced by software-composition and container scans, 6.4.1 by dynamic scans, 8.6.2 by secret scans. Those mappings are Rampart's reading, written in the file with the framework's own wording, not a mapping the standard publishes; each file says so in its `note`, and the screen shows it.
- **What a control's status means.** `open`: findings that bear on it are open (open, under investigation, affected). `clear`: none are open **and** a scan that could evidence it completed in the last 30 days (by the scanner families in `compliance.FamilyCategories`: Semgrep is SAST and secrets, Trivy is components, containers, IaC and secrets, and so on). `not_assessed`: no such scan ran, so an empty list proves nothing. A control matched by weakness needs any code or component scan. The screen says it is evidence, not a certification. This is the honest reading of "no findings": a framework page that shows green for a scanner that never ran would mislead an auditor.
- **API.** `GET /api/v1/taxonomies`; `GET /api/v1/taxonomies/{id}/status?application=&format=csv`: per control the open findings by risk band, the status, the scanners that are its evidence, and `query`, the findings filter that lists exactly what was counted (a test runs the filter and compares the count). One SQL statement per framework. `format=csv` is the evidence export (framework, version, application, control, status, counts, evidence, time).
- **UI.** The Compliance page: choose a framework and an application, a table of controls with the status in words, the open findings by band with the worst band's shape, the evidence and a link to the findings, and the CSV download.
- **Not built.** The per-application Compliance tab, ASVS, CIS, SLSA and the OWASP API Top 10, `control_status` as a stored table with history (the screen evaluates live), mapping by scanner rule id (the key exists in docs/03), `passed_checks` from policy-report style scanners, editing or adding frameworks without a release (a tenant-owned framework would be the next step), and the OWASP Top 10 2025. (This said 2025 has no published CWE mapping; it has one, see D54.)

## D53. Retention (Phase 2)

docs/01 H7 makes a retention job for occurrences and events part of the MVP; docs/04 gives `RetentionPolicy` its fields and example values. Two gaps came up while building it: no bucket lifecycle rule existed, so **every raw report was kept for ever**, including secret-scanner reports that name the secrets (D42 keeps secrets out of the database, not out of the stored report). And the monthly partitions of D4 were created only by `migrate up`, so a server running more than three months without an upgrade would write every event into the default partition.

**What the defaults rest on.** Retention periods are each organisation's to define (NIST SP 800-53 AU-11 and SI-12), so every value is configurable. Some values have a floor because a standard or a promise made elsewhere depends on them:

| Kind | Default | Minimum | Why |
|---|---|---|---|
| `auditDays` | 2555 (7 years) | 365 | PCI DSS 4.0.1 requirement 10.5.1: audit history for at least twelve months, three immediately available. The default is docs/04's |
| `eventsDays` (finding timelines) | 730 | 365 | the timeline is the record of who decided what about a finding (accepted, not affected); it is the same kind of trail |
| `resolvedFindingsDays` | 730 | 180 | SLA adherence and MTTR look back 90 days, trends 180 (D43). Deleting resolved findings sooner would change those numbers. ServiceNow's default for closed findings is 365 days; ours is docs/04's |
| `occurrencesDays` (evidence no scanner reports any more) | 180 | 1 | docs/04, docs/12 |
| `rawReportsDays` | 90 | 1 | docs/04 |
| `secretReportsDays` | 7 | 1 | docs/07: raw reports of secret scanners default to 7 days. GDPR Art. 5(1)(e) (storage limitation) and ISO/IEC 27001:2022 A.8.10 (delete what is no longer required) point the same way |
| `runResultsDays` | 30 | 1 | D10 |

Zero keeps that kind of data for ever and is always allowed. A value under its minimum is refused at startup, by `rampart maintenance` and by the CronJob with the same message, instead of being quietly raised: a policy that silently does something other than what it says is worse than one that refuses.

**Decisions.**
- **One policy for every tenant, from configuration** (`retention.*`, env `RAMPART_RETENTION_*`, Helm `retention`). The `RetentionPolicy` resource is P2 (docs/01 H7, D29). On by default, with docs/04's values, because H7 is a P0 and an install that keeps everything for ever only fails later, at the worst time. With `retention.enabled=false` nothing is deleted and partitions are still created.
- **What is removed, per tenant, as `rampart_app` under row-level security** (D4: the system role never mutates tenant rows), in transactions of 5 000 rows so a backlog never holds long locks:
  - occurrences with `present = false` last seen before the cutoff. A finding's count and detection depend only on present ones (D12), so neither changes;
  - findings `fixed` before the cutoff that no scanner reports, with their occurrences and timeline (the foreign keys cascade). **A finding another finding names in `duplicate_of_id` is kept**, so that link never points nowhere. The rows are locked with `SKIP LOCKED`: a merge reporting one again either waits or is skipped, and if the finding was deleted the next scan creates it anew;
  - `ingest_run_result` rows (D10, D37: what was new for the CI gate);
  - `finding_key_alias` rows older than the occurrence period. D11 keeps an old key "for one retention period" so a tool still reporting a GHSA id updates the same finding; after it, none is expected to. This closes D50's "not built";
  - raw reports: a run that **found a secret** (`ingest_run.holds_secrets`, set when any record of the report is in the `secret` category, not by the scanner's name, because Trivy and Semgrep also find secrets and a Trivy report without one should keep the longer period) or that **failed** (what it held is unknown) after `secretReportsDays`; any other finished run after `rawReportsDays`; an upload created and **never completed** after one day (its presigned URL lives 15 minutes, D9). A run still in progress keeps its report.
- **Raw reports are deleted by the application, not by a bucket lifecycle rule.** A lifecycle rule cannot tell a secret report from another, differs between S3 implementations, and would leave the run page offering a download that 404s. The object is deleted first and the row marked after (`upload.status = purged`, `ingest_run.report_purged_at`), so a failure in between is repaired by the next sweep and a report is never marked gone while still stored. The run page says when the report was removed; `GET /runs/{id}/report` answers 404 with that date; completing a purged upload answers 410.
- **Evidence of deletion.** Each tenant that lost anything gets one audit entry (`retention.purge`, actor `system:retention`) with the counts by kind and the policy in force. ISO/IEC 27001:2022 A.8.10 asks for a record of what was deleted and when. The entries go to the audit log, which is itself kept 365 days or more.
- **The logs leave a month at a time, as the owner.** `finding_event` and `audit_event` partitions are dropped when the whole month is older than the cutoff (a month still partly inside the period stays), and old rows that fell into the default partition are deleted. Only the owner may drop a table, and the audit log is append-only for every other role (D46), so this never runs as the application. Partition drops are cluster-wide, which is one more reason the policy is not per tenant yet.
- **Who holds the owner's credentials.** In Helm the server never does (least privilege, D4): a CronJob, `rampart maintenance` (`retention.maintenance.schedule`, default daily at 03:17), runs with the migration Job's credentials and the server's retention settings. The all-in-one target, which already has `database.migrateUrl` for auto-migration, also does it in-process. Either one creating the coming months closes the D4 gap above.
- **One replica sweeps at a time** (a session advisory lock), every `retention.interval` (default 6 h). Each step only removes what is already expired, so a sweep stopped halfway is finished by the next one.
- **Not built.** The `RetentionPolicy` and `ClusterRetentionPolicy` resources and per-tenant periods; retention of notifications (D45) and of SBOM documents; a "purge this asset" endpoint for GDPR requests (docs/07); the 90-day "immediately available" tier of PCI 10.5.1 is met by keeping everything online, there is no archive tier.
- **Tested on PostgreSQL** (`internal/store/retention_test.go`): each kind removed at its own cutoff and nothing inside it; the duplicate target kept; the secret report gone after 7 days while a normal one of the same age stays; the abandoned upload gone and refused at completion; the run page and the download say so; no other tenant touched; a second pass removes nothing; the audit entry; the minimums refused; partitions dropped only when wholly past the cutoff and the coming months created. Migration `00016_retention.sql`, schema version 16.

Sources: PCI DSS v4.0.1 requirement 10.5.1; ISO/IEC 27001:2022 Annex A 8.10; NIST SP 800-53 Rev. 5 AU-11, SI-12; GDPR Article 5(1)(e); ServiceNow Vulnerability Response auto-delete rules (closed findings, 365 days by default).

## D54. Documents checked against the code, and four priority decisions (2026-11-12)

Every document (00–19, research, ADRs) was read against the code after D53. What follows corrects statements the code contradicts and settles four priority conflicts between [01](01-features.md) and [09](09-roadmap.md). Work that belongs to a later phase is not a defect and is not listed here; the MVP list in 09 holds what is due.

**Corrections (the code is right, the document was not).**
- **Libraries.** D15 and doc 08 named `go-sarif`, `cyclonedx-go`, `tools-golang`, `go-vex`, chi, huma, sqlc, cobra, koanf, casbin, testify and testcontainers. None is in `go.mod`. The parsers are our own token walks and structs over `encoding/json` and `encoding/xml` (fuzzed, D37, D42), routing is the standard `ServeMux`, SQL is hand-written with the D16 builder, configuration and flags are the standard library, and authorization is role comparisons in code (D48). D15 and doc 08 now say so; doc 08 marks each row built or planned with its phase.
- **OWASP Top 10 2025 has a CWE mapping.** D52 said only the 2021 list had one. MITRE publishes one CWE grouping per 2025 category (for example CWE-1438 for A03:2025, in view 1450) and the OWASP pages list the mapped CWEs. The reason D52 gave for leaving 2025 out does not hold; it is on the MVP list.
- **Doc 04:** the finalizer column now matches D49; the `ScanSource` example had `maxReportBytes` and `acceptedFormats` indented under `trackedRefs`; the `ReportIngest` object key now lies under `tenants/<tenant id>/` (D20); `RetentionPolicy` has the D53 fields. Doc 03 likewise.
- **Doc 07:** compliance data is in `internal/compliance/data/` and lists what ships (D52); authorization is not casbin (D48).
- **Doc 13 section 10** described Phase 0 only; it now names what Phases 1 and 2 built and what the UI still lacks.
- **Doc 17 "Still open"** listed the withdrawn ingest goal and libraries that were never used.
- **Phase 0 promised canonical JSON Schemas** for the integration contracts (09, 19). They were not delivered; they are on the MVP list.

**Priority decisions.**

| Item | Conflict | Decision | Source |
|---|---|---|---|
| Hierarchy (B1, H3, D8) | 01 makes it P0; 09 had only the `HierarchyNode` resource, in Phase 5 | A tree of nodes, the link from an application, a filter on every list and roll-ups are in the MVP. The resource that declares nodes in Git stays P2 | ArmorCode's hierarchies filter every view and report SLA adherence by organisational unit, and the market research lists business-unit hierarchy as a common enterprise requirement (research/02 sections 2 and 4). An ASPM that cannot answer "how is this business unit doing" misses a core use |
| CVSS parsing (D4) | P0 in 01, in no phase of 09 | P1. Vectors are stored as given; the MVP scores from severity, KEV and EPSS (D40) | Nothing in the MVP exit depends on computing a vector. Scanners already send a severity and usually a score |
| CSAF VEX (A8) | P0 in 01; Phase 2 of 09 names OpenVEX and CycloneDX only | P1 | CISA's *Minimum Requirements for VEX* (April 2023) is format-neutral and names CSAF, CycloneDX and OpenVEX; OpenVEX is the one designed to meet them directly. Two of the three cover the MVP |
| CLI device login | P1 in 14; Phase 2 in 09 and D8 | MVP (Phase 2); 14 corrected | D8 is normative |

**C6: a decision follows the finding across tracks, for new findings only** (built as D57). The fingerprint includes the track (D11), so a `not_affected` decided on `main` did not reach the same issue on `release/1.x`, although 01 C6 promises "across branches". The decision: when a scan creates a finding on one track of an asset, and the same issue (the same key with the track left out) has a decision on another track of that asset, the new finding starts with that decision, with a timeline entry naming where it came from. Only `not_affected` and `out_of_scope` carry over (decisions about the code); `risk_accepted` does not, because an acceptance has its own owner, expiry and scope (D39). Existing findings are never changed retroactively. D18's re-check on changed code still applies. Source: DefectDojo's *False Positive History* marks new findings that match an earlier false positive within the product; its retroactive option changes every match with no preview and its documentation recommends care, so ours is not retroactive.

Sources: CWE-1438 (https://cwe.mitre.org/data/definitions/1438.html); OWASP A03:2025 (https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/); CISA, Minimum Requirements for VEX (https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf); DefectDojo, False Positive History (https://docs.defectdojo.com/triage_findings/finding_deduplication/false_positive_history/); ArmorCode, Hierarchies (https://www.armorcode.com/blog/armorcode-hierarchies).

## D55. The Application resource reaches the score (Phase 2)

Found while closing item 1 of the MVP list (B5, compensating controls). The score explained its context factors, but on PostgreSQL most of them could not apply:

- **Data classification was never stored.** `CreateApplication` did not write `data_classification`, and no read selected it, so the +80 "sensitive data" factor (docs/06) never applied to a stored score.
- **A change to an application was lost.** On a second apply the upsert updated only the name and description, so raising `businessCriticality` or setting `internetFacing` after the first apply changed neither the score nor the due date.
- **`rampart apply` and the operator mapped the resource differently.** The CLI ignored `dataClassification` entirely. D3 says the reconcile logic is one library.
- **Compensating controls had no field.** The −80 factor existed in `internal/risk` and nothing set it.
- **Ingest could rename an application** (on a slug collision its upsert set the name to the slug), and **every application ingest created was marked `ui`**, the column default, so a resource of the same name could never adopt it (D49). Nothing in the UI or the API creates applications yet, so every `ui` row was ingest's.
- **`rampart apply` wrote as `rampart_app`**, which may not write policy rows (D41); config is written as `rampart_system` (D4), as the operator and the server's file mode already did.

Decisions:
- **One mapping.** `domain.ApplicationSpec.ToApplication` validates the spec and builds the row; the operator and `rampart apply` both call it. Unknown values (criticality, classification, control) are refused with the reason (`Ready=False`, reason `InvalidSpec`; `rampart apply` exits with the error) instead of dropped, because a dropped value is a silently lower score. The CRD schema carries the same enums.
- **Compensating controls** are `waf`, `apiGateway`, `mtls`, `privateNetwork` in the resource and snake_case in the row (D17), stored in `application.compensating_controls` (migration `00017_application_context.sql`, schema version 17). **Which findings a control lowers**: docs/06 says "relevant to category" and docs/04's example is a WAF on a DAST finding. A WAF or an API gateway inspects HTTP requests, so it counts (−80) against findings a dynamic scan made over HTTP and nothing else; PCI DSS 4.0.1 requirement 6.4.2 describes a WAF as a solution that detects and prevents web-based attacks in front of public-facing web applications. It does not lower a SAST, SCA or secret finding: the flaw is still in the code or the package whatever sits in front. `mtls` and `privateNetwork` change who can reach the application, which the internet-exposure factor already carries; they are recorded and not counted twice. A `RiskPolicy` (MVP list) can weigh them differently.
- **Who may change the row.** Ingest only creates (`ON CONFLICT DO NOTHING`, then reads the existing row) and marks its rows `none`; the migration moves existing `ui` rows to `none` and makes `none` the default. A resource creates, adopts `none` rows and updates `crd` rows; it never touches a `ui` row (D49).
- **A changed context re-scores.** When criticality, exposure, data classification or compensating controls change, the save flags the application (`application.rescore_needed`, since D56; at first a marker policy row), and the 15-minute SLA sweep re-scores and re-dates every active finding of the tenant. Saving the same values flags nothing.
- **Tested.** Unit: the spec's validation and spelling, which control counts on which category, sensitive data +80 and a WAF −80 on DAST only. On PostgreSQL: an ingest-made application is unmanaged and adopted by a resource; the stored score of an existing finding rises by exactly 180 after criticality goes medium → critical and personal data is declared (the WAF does not count on a SAST finding); a rescan does not undo it; the same values again flag nothing; a UI row is not touched.

Source: PCI DSS v4.0.1 requirement 6.4.2 (automated technical solution for public-facing web applications that detects and prevents web-based attacks).

## D56. Application selectors, and the asset link that was never stored (Phase 2)

Item 2 of the MVP list (B3; D10 resolution step (b)). How the reference products do it: ArmorCode's *Tool Mapping* binds each connected scanner or repository to a product (research/02 section 2); docs/04 gives `Application.selectors` the same job, declared in Git.

**A defect found first.** Resolution created an asset, then attached it to an application by calling `CreateAsset` again. Its `ON CONFLICT` updated only `last_seen`, so `asset.application_id` stayed NULL for every asset, and D10's first rule ("the asset's existing application") never applied: every run resolved the application from scratch. The link is now written by `MoveAssetToApplication`.

**Decisions.**
- **Patterns.** `selectors.repositories[].url` and `selectors.images[].repository`, each an exact key or a prefix ending in `*`, normalized exactly as asset keys are (D10): `git@github.com:Acme/Shop.git` matches `https://github.com/acme/shop`, a tag in an image pattern is ignored, and `github.com/acme/*` claims the repositories under `acme/`, not `acme-labs`. `*` elsewhere, an empty pattern and a bare `*` are refused. Glob syntax was not adopted: the filter grammar already uses "prefix with a trailing `*`" (D16), so users meet one rule.
- **The most specific wins.** An exact key beats any prefix, a longer prefix beats a shorter one, and between equally specific patterns of two applications the smaller slug wins, so the result never depends on row order. doc 10 handles the same conflict for Dependency-Track by "first rule wins" plus a condition; the condition (`AmbiguousMapping`) is not built here yet.
- **Order** (D10, with one refinement): the asset's application, unless it is the tenant's Unassigned application; then selectors; then the application the upload names; then Unassigned. **An asset in Unassigned is resolved again on every run**, because otherwise a selector declared after the first scan could never apply, which is the usual order of adoption (scan first, organise later). An asset already in a real application stays there, even when a broader selector appears later: moving it would undo what a person, an upload or a narrower selector decided.
- **Applying a resource moves what it claims now**, not on the next scan: after the save, repository and image assets with no application or in Unassigned that the selectors claim move. Waiting for the next scan would leave the Applications page wrong for days.
- **Findings move with their asset**, in the same transaction (the invariant of D36), and the receiving application is flagged so the SLA sweep re-scores them in its context (criticality, exposure, data, controls; D55). Past `ingest_run` rows keep the application they ran under: they are history.
- **The flag moved to the application.** D55 flagged a context change with a marker policy row, which only the system role may write (D41); ingest, which moves assets, runs as the application role. `application.rescore_needed` (migration `00018_application_selectors.sql`, schema version 18) carries both cases; the migration carries over any pending marker.
- **Workload selectors are refused**, not ignored: they need a connected cluster, which arrives with the collector after v1.0 (D21). A resource that sets them is `Ready=False` with the reason.
- **Tested.** Unit: normalization of patterns, exact over prefix, longer prefix, the `/` boundary, images, the tie rule in both orders, refused patterns. On PostgreSQL: a selector declared before the first scan places the asset and stores the link; an asset scanned first waits in Unassigned and moves with its finding when a resource claims it, and the finding's score rises by exactly the critical application's 100 after the re-score; a broader selector added later does not take an asset from its application; no finding disagrees with its asset's application.
- **Not built.** Workload selectors; the `AmbiguousMapping` condition for overlapping patterns; a flag set while the sweep is re-scoring the same tenant can be cleared with it (the same window D41 has), so such a change waits for the next change or feed sync.

## D57. Decisions follow the issue across tracks (Phase 2)

Item 3 of the MVP list, built as D54 decided. The finding key includes the track (D11), so the same issue on `main` and on `release/1.x` is two findings, and a `not_affected` decided on one never reached the other, although 01 C6 promises triage memory "across branches".

- **`lineage_key`**: D11's key computed with the track left out of the scope (`"v1-lineage" US family US tenant US asset US fields…`), stored on `finding` and indexed with the tenant and asset (migration `00019_finding_lineage.sql`, schema version 19). A weak fingerprint gets none: its identity is too loose to carry a decision. Findings that existed before learn their lineage key on their next scan; nothing is back-filled by guessing.
- **When it carries**: a finding the merge **creates** on one track starts in the state a person gave the same issue (same lineage key) on another track of the same asset, with its justification and impact statement, `previous_state = open`, and a `decision_carried` timeline entry naming the source finding and its track. When several tracks have one, the most recently changed wins.
- **What carries: `not_affected` and `out_of_scope` only.** They are statements about the code or the component, which the other branch of the same asset shares. `risk_accepted` does not: an acceptance has its own owner, expiry and scope (D39) and was given for one place. `duplicate` names another finding of its own track.
- **Only with the same evidence**: the content hash must match (D13: the fields a rescan may change). Different evidence is looked at again, which is the rule D18 already applies to a decided finding whose code changed.
- **Nothing retroactive.** Existing findings on other tracks are never changed. DefectDojo's *False Positive History* offers a retroactive mode that changes every match in the product without a preview; its documentation advises care, and a silent mass change of decisions would be hard to audit.
- **The CI gate.** A finding that arrives already decided is not counted as new: the decision stands, as it does for a decided finding that was already on the track. Without this, every release branch would fail the gate on issues people had already judged.
- **Tested on PostgreSQL**: a decision with justification and impact carries to a new finding on `release/1.x` with its timeline entry; different evidence does not carry; a risk acceptance does not carry; a finding that already existed on the other track is not changed; the gate on the release commit blocks only the two undecided new findings. Unit: the lineage key is shared across tracks of one asset, differs across assets, and is empty for a weak fingerprint.

Source: DefectDojo, False Positive History (https://docs.defectdojo.com/triage_findings/finding_deduplication/false_positive_history/).

## D58. OWASP Top 10 2025, and working Phase 2 in its order (Phase 2)

**OWASP Top 10 2025** (Phase 2 bullet 6; D54 found that D52's reason for leaving it out was wrong).
- **Source.** Each category page on top10.owasp.org/2025 lists its weaknesses under "List of Mapped CWEs" and states the count in its score table: A01 40, A02 16, A03 6, A04 32, A05 37, A06 39, A07 36, A08 14, A09 5, A10 24 (249 in all, none repeated). The data file `internal/compliance/data/owasp-top10-2025.json` holds exactly those lists, and a test checks every count against the page. MITRE's view 1450 was not used as the source: it is titled "Weaknesses in OWASP Top Ten **RC1** (2025)", the release candidate, and differs from the final pages (A03 in the view has CWE-447 and CWE-477 and lacks CWE-1357).
- **One correction.** A03's page lists "CWE-447 Use of Obsolete Function". CWE-447 is "Unimplemented or Unsupported Feature in UI"; "Use of Obsolete Function" is CWE-477, which the same page's background text names and MITRE's grouping CWE-1438 contains. CWE-477 is used, and the framework's note says so. (A07's page repeats the title of CWE-297 for CWE-298 and CWE-299; only numbers are stored, so nothing changes.) The 2021 lists were kept exactly as printed (D52); this is the only departure, because here the page contradicts itself.
- **Order.** Frameworks were sorted by name only; two versions of "OWASP Top 10" would come back in random order and the UI's default could change between requests. They are sorted by name, then the newest version first.
- **Tested.** The counts, weaknesses where 2025 moved them (SSRF into A01, XXE into A02, injection in A05, CWE-703 in the new A10), the A03 correction, and the order; on PostgreSQL the taxonomy endpoint lists six frameworks and the existing per-control status test runs unchanged.

**Working Phase 2 in its order.** Items 1 to 3 of the MVP list (D55 to D57) and this one were picked by size. The roadmap gives Phase 2 as eight bullets in an order, and that order is the plan we keep: the MVP list in 09 is now grouped by bullet, and the remaining work goes bullet 1, 2, 3, 4, 5, 8, then the P0 rows outside the bullets, each bullet finished before the next.

Sources: OWASP Top 10:2025 category pages (https://top10.owasp.org/2025/); CWE-1438 (https://cwe.mitre.org/data/definitions/1438.html); CWE view 1450 (https://cwe.mitre.org/data/definitions/1450.html).
