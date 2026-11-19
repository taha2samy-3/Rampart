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
| `connectors.ssrfAllowlist.cidrs`, `.hosts`, `.allowInternalHttp` | — | private ranges and internal hosts connectors may reach (D69); never metadata, loopback or link-local |
| `connectors.ssrfAllowlist.tenants`, `.connectorTypes` | — | required when the allowlist grants anything: tenant ids or `*`, connector types or `*` (D77) |
| `server.trustedProxies` | — | CIDRs of the reverse proxies whose `X-Forwarded-For` is believed (D84) |
| `feeds.nvdUrl`, `feeds.nvdApiKeyFile`, `feeds.nvdDisabled` | NVD CVE API 2.0, —, `false` | the NVD sync (D86); a `ClusterFeedMirror` overrides the URL |

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

**Web tooling.** The web UI is built and tested with **Bun** (`bun install --frozen-lockfile`, `bun --bun run build|test|lint|typecheck`; lockfile `web/bun.lock`; version pinned in `packageManager` and in CI). `mise.toml` pins the same version (`bun = "1.4.4"`, added 2026-11-12) so a developer machine gets it with `mise install`, like Go and golangci-lint. The Dockerfiles build the UI in a Bun stage and copy `web/dist` into the Go build, so every image embeds the UI.

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

## D59. Bullet 1 finished: owners, bulk in the UI, and a filter that never widens (Phase 2)

What was left of Phase 2 bullet 1 (01 C9 "update status/severity/tags/owner for N findings"; the MVP exit "an analyst triages end to end in the UI").

- **Owner.** `finding.owner` (migration `00020_finding_owner.sql`, schema version 20): the e-mail of a **member of the tenant**, lower-cased, or nothing. A non-member is refused with the reason, so a typo cannot assign work to nobody. The market does the same: Snyk and Datadog assign findings to a user of the team. docs/03 also names an owner *team*; teams arrive with SCIM groups (P2), so a team is not an owner yet, and a person who has never signed in is not a member yet (membership is created at sign-in, D8). Changing the owner is a triage decision (`triager`, and the per-application roles of D48) and writes `owner_changed` on the timeline.
- **Filters.** `owner:<e-mail>`, `owner:none` (unassigned) and `owner:me` ("My work", docs/13), where "me" is the caller's e-mail, or a token's subject when that is an e-mail (D48 matches subjects the same way). `assettype:` is also wired; it was in the D16 list and in no code.
- **A filter never widens.** Two defects found while wiring `owner:`: a field the SQL builder did not know was silently dropped, and so was a term none of whose values could be read (`cwe:abc`). Both widened the match; on `POST /findings/bulk` with `q` that meant a change meant for a few findings reached every finding of the tenant. Now an unknown field is a 400 that lists the known ones (the same list as the SPA's `KNOWN_FIELDS`), and an unreadable term matches nothing (its negation, everything). Free text that contains a colon is written in quotes.
- **Tags in bulk are added and removed.** `tags` replaces the list; in a bulk change that would wipe each finding's own tags. `addTags` and `removeTags` change only what they name; `tags` together with either is refused.
- **UI** (docs/13 section 5). A selection box on each row and `x` on the focused row (both: the key for the keyboard, the box for a pointer and for assistive technology); a bar under the list while findings are selected, with "Select all N matching", which switches the change from ids to the current filter; one dialog for the change (state with its justification, owner, tags to add and to remove, a note) that reports how many changed, how many were already that way, and each one refused with the server's reason. Edit (`a`, the key docs/13 gives "assign") changes owner, severity and tags of one finding; a new severity cannot be saved without its reason, and only what changed is sent, with the version the analyst saw. The inspector shows owner, tags and a severity set by a person. Selection is offered to anyone who may decide somewhere; the server decides each finding by its application (D48) and the dialog lists what it refused.
- **Tested.** On PostgreSQL: a non-member refused; assignment lower-cased and on the timeline; bulk by `owner:none`; `owner:me` for two callers; clearing; tags added in bulk without losing a finding's own, removed, and `tags` with `addTags` refused; a bulk change with a misspelled field refused and nothing changed; `cwe:abc` matches nothing. Vitest with axe: `x` and the box select, the dialog sends ids and the patch and lists the refused finding, "select all matching" sends the filter, "nobody" unassigns, a viewer gets no selection, Edit sends only what changed with `If-Match`. Checked in Chromium against the dev mock (which now applies owner, severity, tags and bulk), light and dark.

Sources: Snyk, assign vulnerabilities to a team member (https://docs.snyk.io/scan-fix-and-prevent/scan-with-snyk/snyk-api-web/review-and-fix/assign-vulnerabilities-to-team-member); Datadog, assignee management (https://docs.datadoghq.com/security/assignee_management/).

## D60. Proof files on a risk acceptance (Phase 2, bullet 2)

01 C5 lists "proof" among what a risk acceptance carries; D39 left it out. DefectDojo attaches proof files to a full risk acceptance, and its documentation gives the kind of file: "emails from colleagues acknowledging the Risk Acceptance, meeting notes, or simply a written justification".

**Accepting a file on a security platform**, following the OWASP File Upload Cheat Sheet:
- **An allow-list, by content as well as by name**: `.pdf` (must start with `%PDF-`), `.png` (the PNG signature), `.jpg`/`.jpeg` (`FF D8 FF`), and `.txt`, `.md`, `.eml` (UTF-8 with no NUL byte). The `Content-Type` the browser sends is ignored ("cannot be trusted"). Office documents are refused: a `.docx` is a ZIP archive, which the cheat sheet advises against accepting; a PDF export is the answer, and the error says so.
- **Limits**: 10 MiB per file, ten per acceptance (checked under a lock on the acceptance, so two uploads at once cannot pass it).
- **Names**: the file is stored under a name the server chose, `tenants/<tenant>/acceptances/<acceptance>/<proof id>`, in object storage, never on the web server. The person's file name is kept only to show it, cut to its base name, with control characters, colons, leading and repeated dots removed, and at most 200 characters.
- **Download**: always as an attachment, with the type the server determined, `X-Content-Type-Options: nosniff`, a `sandbox` Content-Security-Policy and `no-store`, so a file is never rendered in the application's origin. Every download is written to the audit log, as raw reports are (D51).
- **Not built**: antivirus or content disarm (the cheat sheet says "if available"; there is no scanner to call in an air-gapped install, and a pluggable scanner hook is for later); image re-encoding.

**Who and when.** The person who asked for the acceptance, its owner, or a maintainer of its applications adds proof, while it is pending or approved; once it is rejected, revoked or expired it is a closed record and accepts nothing more. Anyone who may read the acceptance may list and download its proof.

**Proofs are evidence and are never changed or removed.** `risk_acceptance_proof` (migration `00021_risk_acceptance_proof.sql`, schema version 21) grants the application role `SELECT` and `INSERT` only; the system role may delete for a tenant purge (D49). A mistaken file stays, and the next one corrects it, as in the audit log (D46). The UI says this next to the upload.

**Storage.** The object store gained `Write` for small objects the server itself received. Reports still never pass through the server: they go to storage on a presigned URL (D9).

**UI.** The Workflow page lists the proof under the acceptance as download links with size, who attached it and when, and offers "Attach a file" to the people who may. The API client sends a `FormData` body as multipart (without the JSON content type), with the CSRF header like any other change. The dev mock (`web/dev/mock-server.mjs`) now serves one risk acceptance with two proof files and accepts uploads, so the Workflow page can be checked without a backend; it does not check file content, the real server does.

**Tested.** Unit: every allowed kind, a text file named `.pdf`, a `.docx`, an executable, a NUL in text, too large, empty, no extension, a hidden file, double dots, a colon, and a long name shortened with its extension. On PostgreSQL: a PDF and an `.eml` attached; a fake PDF and a `.docx` refused; an unrelated triager and a viewer refused; the list; the download with its headers and its audit entry; the eleventh file refused; nothing after revocation. Vitest with axe: the list, an upload, a refused file with the server's reason, no upload offered to an unrelated triager. Checked in Chromium against the dev mock.

Sources: DefectDojo, risk acceptances (https://docs.defectdojo.com/triage_findings/findings_workflows/risk_acceptances); OWASP File Upload Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

## D61. Every check runs in CI

The rule from here on: a check used to accept a change is a test in CI, not something run by hand. Where D53 to D60 relied on a manual step, it is now automated.

- **Browser tests.** D59 and D60 were checked by driving Chromium by hand against the dev mock. That is now `web/e2e/*.spec.ts` with `@playwright/test` 1.62.1 (`bun --bun run e2e`; config `web/playwright.config.ts`, which starts the dev mock and Vite): bulk change of two findings with the result line, Edit with the severity reason, `x` from the keyboard, and the proof list and upload. Every test fails on a console error or an uncaught exception. The tests run one at a time because the mock keeps state in memory. CI job `web-browser` installs Chromium with `bunx playwright install --with-deps chromium`, uploads the report and traces when it fails, and the kind job waits for it. Vitest keeps the component tests with axe; Playwright covers what jsdom cannot (real layout, focus, file inputs, the dev proxy).
- **Helm.** The Helm job asserts that the maintenance CronJob (D53) renders, runs `rampart maintenance` with the owner's URL and the retention settings, and that the server Deployment never receives the owner's URL.
- **Fuzzing.** Two more untrusted inputs are fuzzed for 30 seconds in the unit job, as D17 asks of every parser of untrusted input: proof file names and contents (`FuzzCheckProof`) and the filter grammar (`FuzzParse`, which also checks that nothing but a known field is ever parsed, D59). **`FuzzCheckProof` found a defect in D60 at once:** a name whose "extension" was longer than 200 characters made the name shortening slice out of range and panic, and the shortening could cut a multi-byte character in half. Such a name is now refused, and the cut keeps whole characters. The failing input is kept under `internal/domain/testdata/fuzz` and replays in every `go test`.
- **A defect found by looking.** The screenshots taken for a review showed the risk bar on the Applications page empty for every application: `ScoreBar` draws one segment per group of factors, and an application's score (the highest of its findings, D43) has no factors. Without a breakdown it now draws one segment as long as the score on the 1000 scale (doc 13 section 6: "length is points over the 1000 scale"), and nothing for zero; a Vitest case covers both.
- **Unchanged and already in CI**: every Go package (unit job; PostgreSQL and SeaweedFS for the store; envtest for the operator), Vitest, typecheck, lint, Helm lint and templates, the kind end-to-end job, the Compose quick start. The workflow passes actionlint.

## D62. Hierarchy, roll-ups and the posture score they feed (Phase 2, bullet 3)

`hierarchy_node` (migration `00023_hierarchy.sql`) holds a tenant's tree with a dot-joined `path` (e.g. `fintech.payments`), built by `EnsureHierarchyPath`: each segment is slugified to `[a-z0-9_]` (hyphens, spaces and dots fold to `_`, so a path segment can never itself contain a `.` or a SQL wildcard), walked or created one level at a time, `ON CONFLICT (tenant_id, path)` so re-applying an `Application`'s `hierarchy` list is idempotent. `application.hierarchy_node_id` and the denormalized `application.hierarchy_path` (propagated onto `finding.hierarchy_path`, the D28 pattern) let both the query grammar's new `hierarchy:` field and RBAC's `roleScope.allowsHierarchy` (D57) match a node and everything under it with `path = prefix OR path LIKE prefix || '.%'` — equality or a dot-bounded prefix, never a bare `LIKE prefix%`, so `fintech` cannot match `fintech-labs`.

**Found during this review and fixed:**
- **The posture score (docs/06 section 2: weighted open risk normalized by asset count) was never normalized by a real asset count.** `AppSummary` had no asset count at all; `Overview()` passed the tenant's *application* count and `HierarchyRollups()` passed the subtree's *application* count, both as a stand-in for "assets", so two applications or subtrees with the same open risk but very different numbers of assets always scored identically, and the normalization term in the formula was dead in practice. Fixed by adding `AppSummary.AssetCount`, populated by a scalar subquery (`(SELECT count(*) FROM asset WHERE asset.tenant_id = a.tenant_id AND asset.application_id = a.id)`) rather than a second `JOIN asset` next to the existing `JOIN finding` in `summaryCols`, which would otherwise fan out the finding-count aggregates (the same Cartesian-product trap the existing `last_scan` column already works around with a subquery). `HierarchyRollups` gained the equivalent subquery scoped to the subtree. Regression test: `internal/store/posture_score_test.go`, two applications with one asset and ten assets respectively, same single critical finding each, asserting `AssetCount` is correct and the ten-asset application's posture score is strictly higher (less risk per asset) than the one-asset application's.
- **`SaveApplication`'s call into `EnsureHierarchyPath` ran in a second, independent transaction.** `SaveApplication` already holds its own `withTenantTx`-scoped `pgx.Tx`, but called the exported `(*PostgresStore).EnsureHierarchyPath`, which opens *its own* `withTenantTx` — a new connection from the pool, not the one already open — because the outer callback only has a raw `pgx.Tx`, not a tx-bound store. A hierarchy node could therefore commit even if the application write that asked for it later rolled back (worst case: an orphaned-but-harmless `hierarchy_node` row; `ON CONFLICT (tenant_id, path) DO UPDATE` makes a repeat attempt self-heal). Fixed by splitting the walk-or-create loop into `ensureHierarchyPathTx(ctx, tx, …)`, called with the caller's own transaction by both the exported `EnsureHierarchyPath` and `SaveApplication`, so the two writes now commit or roll back together.

Sources: docs/06 section 2 (posture score formula); D28 (scalar-subquery-over-JOIN pattern for adding an aggregate without disturbing existing ones); D56/D57 (the equal-or-dot-prefix boundary rule, applied here to hierarchy paths the same way it was to selectors and RBAC scopes).

## D63. `RiskPolicy`/`ClusterRiskPolicy`/`ClusterSLAPolicy` CEL engine and compliance presets (Phase 2, bullet 3)

The risk-policy CEL engine (`internal/risk/policy.go`) compiles `RiskPolicySpec` (base points per severity, a list of `{name, when, points, reason, group}` factors, band thresholds) with `cel-go`, probing each factor's expression against a `fullInput()` value before accepting the policy so a misspelled field (`vuln.epps` for `vuln.epss`) is rejected at apply time instead of silently evaluating to `false` at scoring time forever after. `BuiltinSpec()` is exactly the docs/06 section 2 formula (KEV +300, EPSS tiers, internet-facing, sensitive data, criticality, production track, a WAF/API-gateway compensating-control reduction) expressed as data rather than code, so a tenant can override it with their own `ClusterRiskPolicy`/`RiskPolicy` without a code change.

**Five compliance `ClusterSLAPolicy` presets ship under `deploy/presets/` (and an embedded copy under `internal/config/presets/`), as docs/06 section 4 asks for.** Reviewed against their cited standards and corrected where the comment overclaimed or conflated sources (no day-count numbers were changed, only the citations):
- `pci-dss`: 30-day critical/high is PCI DSS v4.0.1 requirement 6.3.3 (patch critical/high-risk vulnerabilities within 30 days of the patch's release); 11.3.1 adds the post-remediation rescan. The medium/low tiers are not separately mandated by 6.3.3 and are now labelled as Rampart's own extension.
- `fedramp-rev5`: the 30/30/90/180-day tiers are FedRAMP's commonly published continuous-monitoring remediation timelines, applied against the NIST SP 800-53 Rev 5 baseline FedRAMP currently uses (the preset's name refers to that baseline, not to Rev 5 itself setting the day counts).
- `cisa-bod`: the day-count matrix (critical 15d, high 30d) is CISA BOD 19-02 ("Vulnerability Remediation Requirements for Internet-Accessible Systems"); the original comment also cited BOD 22-01 for the same 15d/30d figures, which is wrong — 22-01 does not set a flat day count, it requires remediation by the specific due date CISA publishes per KEV entry. That mechanism is what `caps.kevDueDate: true` already enforces (`domain.SLAPolicy.Due`: never later than the KEV catalog's own due date), so the preset was functionally correct; only the comment was corrected to attribute each directive to the mechanism it actually governs.
- `fedramp-vdr`: **initially flagged as unverified in this section; now confirmed against the primary source and corrected.** A first review pass could not find a public document for FedRAMP's incoming Vulnerability Detection and Response (VDR) / Vulnerability Evaluation and Reporting (VER) rules and marked the preset "UNVERIFIED". Pulling FedRAMP's own machine-readable dataset directly (`github.com/FedRAMP/rules`, `fedramp-consolidated-rules.json` — the canonical source behind FedRAMP Notice NTC-0014, FedRAMP's response to CISA BOD 26-04, mandatory from 2026-12-07 with a grace period to 2027-03-07) confirms the standard is real and gives its exact structure: rule `VDR-TFR-PVR` sets remediation timeframes as a matrix of **certification class (A/B/C/D) × Potential Agency Impact N-rating (`VER-EVA-EPA`, N0–N5) × exploitability/reachability**, not a flat per-severity table — e.g. Class A/B at PAIN N5, internet-reachable and likely-exploitable, is 4 days; Class D at the same rating is 12 hours. Both `VDR-TFR-PVR` and the related `VER-TFR-EVU` ("evaluate within") are `SHOULD` (recommended) rules, not `MUST`; the one `MUST` number is `VER-TFR-MAV`: a vulnerability not fully mitigated or remediated within 192 days of evaluation must be categorized as an accepted vulnerability. The preset's `critical: 4d` is exactly the Class A/B PAIN-N5 cell; `high: 14d` is `VER-TFR-EVU`'s Class A evaluation window (a different rule, not a remediation cell); `medium: 30d`/`low: 90d` have no single matching cell and are now labelled as Rampart's own accelerated approximation of the matrix's lower-PAIN cells (which range 8–192 days by class). The YAML comment was rewritten to cite the exact rule IDs and this simplification rather than imply a literal one-to-one match, and `caps.maxDays: 90` is noted as intentionally tighter than `VER-TFR-MAV`'s 192-day mandatory ceiling.

Sources: PCI Security Standards Council, PCI DSS v4.0.1 (requirements 6.3.3, 11.3.1); CISA BOD 19-02 (https://www.cisa.gov/news-events/directives/bod-19-02-vulnerability-remediation-requirements-internet-accessible-systems) and BOD 22-01 (https://www.cisa.gov/known-exploited-vulnerabilities-catalog); FedRAMP continuous monitoring guidance (commonly cited 30/30/90/180-day legacy tiers); FedRAMP Consolidated Rules for 2026, rules `VDR-TFR-PVR`, `VER-TFR-EVU`, `VER-EVA-EPA`, `VER-TFR-MAV` (https://github.com/FedRAMP/rules, `fedramp-consolidated-rules.json`); FedRAMP Notice NTC-0014 (https://www.fedramp.gov/notices/0014).

## D64. `IdentityProvider`/`ClusterIdentityProvider`: built, with dynamic multi-IdP OIDC login (Phase 2, bullet 5)

D8 and D27 commit a real feature set for Phase 2: `IdentityProvider`/`ClusterIdentityProvider` CRDs, a domain-claim approval workflow (`status.domains[].approved`), a `ClusterIdentityProvider` tenant allowlist, and `AccessBinding` subjects qualified by `idp`. An earlier pass of this review found the two CRDs existed but `rampart apply` treated both kinds as a no-op that still reported success — recorded as an open gap, not a placeholder. **That gap is now closed**: `internal/domain/identity_provider.go` (the domain type and `Validate`/`IsTenantAllowed`/`IsDomainApproved`), `internal/store/identity_provider.go` (`SaveIdentityProvider`/`GetIdentityProvider`/`ListIdentityProviders`/`DeleteIdentityProvider`/`ApproveDomainClaim`, migration `00025_identity_provider.sql`, schema version 25), `internal/operator/reconciler.go`'s `IdentityProviderReconciler`/`ClusterIdentityProviderReconciler`, and `internal/auth/handlers.go`'s dynamic per-IdP OIDC login path (`login()`/`callback()` now resolve `idp=<name>` against a stored `IdentityProvider` instead of only ever accepting `idp=default`) are all built and tested (`internal/auth/oidc_flow_test.go`, `internal/domain/identity_provider_test.go`, `internal/operator/operator_test.go`, `internal/config/apply/apply_test.go`).

**Three real bugs were found and fixed during this review, before the feature was usable:**
- **Reconciling or re-applying an `IdentityProvider` silently reset every domain-claim approval to unapproved.** Both `apply.go`'s `identityprovider` case and `IdentityProviderReconciler.Reconcile` built a brand-new `Status.Domains` from the spec on every call — `SaveIdentityProvider`'s `ON CONFLICT ... DO UPDATE SET status = EXCLUDED.status` is a full column overwrite, not a merge, so a platform admin's earlier `ApproveDomainClaim` was silently undone by the next apply or periodic reconcile, re-locking out an already-approved domain. Fixed by loading the existing stored provider first and carrying forward any domain's approval that is still declared in the new spec, only appending a fresh unapproved entry for a domain that is genuinely new.
- **The domain-approval check was called with the full e-mail address, not the domain.** `IsDomainApproved(claims.Email)` compared `"alice@acme.com"` against declared domains like `"acme.com"` with `strings.EqualFold` — which can never match, so once `login.emailDomains` was set, *every* login failed with `domain_unverified`, including already-approved domains. Fixed by extracting the part after the last `@` (and trimming a stray leading `@` from either side of the comparison) before comparing, case-insensitively, against both the declared domains and the stored approvals.
- **A dynamic IdentityProvider's OIDC client was rebuilt from scratch on every single login and every callback**, each doing its own live `.well-known/openid-configuration` discovery round-trip to the external issuer — twice per login flow, for every request, for every dynamic IdP. Fixed with a cache on `Handlers` (`oidcPool map[string]*OIDCClient` behind a `sync.RWMutex`, plus a `singleflight.Group` so concurrent logins for the same not-yet-cached IdP coalesce into one discovery call instead of racing). The cache key is `idp.Name + Issuer + ClientID + redirectURL + sha256(ClientSecret)[:8] + IdentityProvider.UpdatedAt` — rotating the client secret, or any other spec edit that bumps `UpdatedAt`, produces a new key automatically rather than needing an explicit invalidation path, and inserting a new entry for an IdP evicts that IdP's older cached entries (keyed by the same `idp.Name + "|"` prefix) so a long-running process doesn't accumulate one stale `*OIDCClient` per rotation forever.

**One structural gap found and fixed**: migration `00025_identity_provider.sql` originally granted `rampart_app`/`rampart_ro` plain `SELECT` on `identity_provider` with no Row-Level Security at all — every other tenant-scoped table in this schema since migration `00013` (`access_binding`, `hierarchy_node`, …) enables and forces RLS with a `tenant_isolation` policy. The Go code only ever reads/writes this table as `rampart_system` (which bypasses RLS) and filters by `tenant_id` itself, so this was not a reachable cross-tenant leak through any code path reviewed, but it was a quiet regression of the project's belt-and-suspenders RLS discipline (ADR 0005). Fixed: `ENABLE`/`FORCE ROW LEVEL SECURITY` plus a `tenant_isolation` policy, with `OR tenant_id IS NULL` added to the predicate (unlike `hierarchy_node`'s) so a tenant session can still see cluster-wide `ClusterIdentityProvider` rows, which must be visible to every tenant by design.

**Still open, deliberately out of scope here**: SAML (`idpObj.Type != "oidc"` is refused with `501 Not Implemented` rather than silently mishandled — correct and intentional, not a bug); who may call `ApproveDomainClaim` over HTTP (no route was reviewed yet — confirm it is gated to a platform-admin role before exposing it); re-checking `IsTenantAllowed` inside `callback()` itself (currently relies on the tenant coming from the sealed `loginState` cookie set after `login()`'s own check already passed — not exploitable today, but not defense-in-depth either).

Sources: this engagement's own earlier research into multi-tenant OIDC caching patterns (a `sync.RWMutex`-guarded, config-version-keyed client cache, analogous to Pinniped's Supervisor and to `DBPolicy`'s existing TTL-cached risk/SLA policies in `internal/scoring/scoring.go`); the established RLS convention from ADR 0005 and migration `00013_access_binding.sql`/`00023_hierarchy.sql`.

## D65. CLI device login (RFC 8628), and two bugs this review found in it (Phase 2, bullet 5)

The CLI device flow (`internal/auth/device.go`, `internal/auth/handlers.go`) follows RFC 8628: `POST /auth/device/code` returns a `device_code`/`user_code` pair and a `verification_uri_complete` with the code pre-filled; the signed-in user visits `/auth/device`, confirms, and the CLI's poll of `POST /auth/device/token` returns `authorization_pending` until then, or `expired_token`/`access_denied`/`invalid_grant`. State is in-memory per replica (an approval on one replica is invisible to another), which is acceptable for a single-replica MVP deployment and is recorded here as a known limitation rather than a bug, pending a shared store (Postgres or Valkey) if Rampart ever runs multi-replica.

**Two real bugs found during this review, both fixed:**
- **Reflected XSS.** `GET /auth/device?user_code=…` reflected the query parameter into the page with `fmt.Fprintf(w, "…%s…", userCode)` — raw string interpolation into an HTML attribute (`value="…"`). A `user_code` of `"><script>…</script>` broke out of the attribute and ran as a signed-in victim, who reached the page by following a link or scanning a QR code the attacker supplied (the real CLI prints such a link with the user code pre-filled by design). Fixed by rendering through `html/template` (context-aware auto-escaping), plus a defense-in-depth filter (`sanitizeUserCodeForDisplay`) that keeps only the device user-code alphabet (`BCDFGHJKLMNPQRSTVWXZ23456789` and `-`, capped at 9 characters) before the value ever reaches the template, and `X-Content-Type-Options: nosniff` / a restrictive `Content-Security-Policy` on the response. Regression test: `TestDevicePageEscapesUntrustedInput`.
- **The issued token always carried every scope, regardless of what the CLI asked for.** `VerifyUserCode` hardcoded `scopes := []string{"ingest", "read", "triage", "admin"}` instead of consulting the device-code request's `Scope` field — a `scope=read` request from the CLI silently received an `admin`-scoped token. Scopes are not yet enforced anywhere in the API (only the role is), so this had no live-request consequence today, but it is the same shape of bug as a privilege-widening grant and would matter the moment scope enforcement is added. Fixed with `requestedScopes()`, which intersects the requested scope string (RFC 6749 section 3.3, space-separated) against the known scope list and falls back to every scope only when the request is empty or entirely unrecognized (so an older CLI that never sends `scope` keeps working). Regression test: `TestDeviceFlowHonoursRequestedScope`, table-driven over no scope, an unrecognized scope, one recognized scope and two.

Sources: RFC 8628 (OAuth 2.0 Device Authorization Grant); RFC 6749 section 3.3 (scope parameter syntax); OWASP Cross Site Scripting Prevention Cheat Sheet (context-aware output encoding; `html/template` is Go's implementation of that for HTML).

## D66. Ticket-on-critical automation placeholder (Phase 2, bullet 4)

The only built-in automation this phase ships is a placeholder: when a critical finding is upserted during a merge, `internal/ingest/merge.go` calls `ReserveAction(tenantID, PolicyTicketOnCriticalID, findingID, "create_ticket")` against `action_ledger`, whose unique constraint on `(tenant_id, policy_id, finding_id, action)` with `ON CONFLICT DO NOTHING` makes the reservation idempotent and permanent — a repeated or retried ingest of the same finding never re-fires it. `ReserveAction` runs inside the same per-batch transaction as the rest of the merge (confirmed via `InTenantTx`'s tx-bound store wrapper: `ReserveAction`'s own `withTenantTx` detects it is already inside a transaction and reuses it, rather than opening a second one the way D62's hierarchy bug did before the fix above). On first reservation, a `"ticket_created"` `FindingEvent` records "Ticket creation requested for critical finding (connector placeholder)" — no connector exists yet (that is Phase 3's Jira/GitHub Issues/Slack work, docs/09), so today this is only a durable, once-per-finding marker that a future connector can act on.

Sources: docs/09-roadmap.md Phase 2 bullet 4 and Phase 3 (connectors); D25 (the `action_ledger` idempotency pattern this reuses unchanged).

## D67. `rampart findings`, the OpenAPI document and the canonical JSON Schemas (P0, outside the Phase 2 bullets)

Three Phase 0/G6/G7 items landed with this batch, reviewed and found to match their commitments:
- **`rampart findings list` / `rampart findings set-state`** (`cmd/rampart/cli.go`) are thin HTTP client wrappers over the existing query API: filtering is the server-side `?q=` grammar (already reviewed and fixed for silent-field-drop and prefix-boundary bugs earlier in this engagement), not reimplemented client-side, so there is nothing for the CLI to get wrong independently of the API it calls.
- **The OpenAPI document** (`internal/query/openapi.go`) is a `//go:embed` of a static spec served as-is; nothing to review beyond "does it serve."
- **The canonical JSON Schemas** (`schemas/*.v1.json`, promised in Phase 0 / doc 19) gained `issuedraft`, `message`, `rawfinding`, `upstreamproject`; `schemas/schemas_test.go` validates each schema file is well-formed JSON Schema and (where a corresponding Go type exists) round-trips a sample value.

Sources: docs/09-roadmap.md P0 rows (G6 OpenAPI, G7 CLI); docs/19-integration-sdk.md (canonical schemas, Phase 0 commitment).

## D68. The manual upload screen, and an inconsistent fallback path found behind it (Phase 2, bullet 8)

The Workbench gained an upload dialog (`web/src/routes/ingestion/UploadDialog.tsx`, wired into `IngestionRoute.tsx`): drag-and-drop or browse for a report file, pick an application and track, submit. It is plain JSX throughout — no `dangerouslySetInnerHTML`, no raw HTML interpolation of the filename or any other field the server or the user supplies — so untrusted strings (a report's filename, an application slug) render as text and React escapes them the same as everywhere else in the app; no XSS was found here.

**Flagged, not fixed: `internal/query/uploads.go`'s handlers only run their own, independent logic when `a.gw` (the `ingest.Gateway`) is `nil`** — every production wiring (`internal/targets/runner.go`) calls `SetGateway` unconditionally, so in practice only `TestQueryAPI_UploadEndpoints` exercises this path, deliberately, by never calling `SetGateway`. Within that fallback, `handleDirectUpload` never parses the uploaded report at all: it fabricates `Status: RunCompleted` and `Stats.Parsed: 1` without running any parser, so a caller on this path is told a scan completed and found results when nothing was read. `handleCreateUpload`'s fallback also generates a brand-new, unrelated `ScanSourceID` when the caller's `source` isn't already a valid UUID, instead of resolving or creating a named scan source the way the gateway's real path does. Whether this fallback is meant to be a genuine second upload path (e.g. for a deployment mode without a wired ingest gateway) or should simply fail loudly when `a.gw` is `nil` is a scope decision, not a one-line fix, so it is recorded here for the user to decide rather than silently picked.

Sources: none beyond the code itself; this is a correctness/design finding, not a standards question.

## D69. Connector model for Phase 3

- **In-process, configured by a resource.** Jira, GitHub Issues, Slack, Teams, email, signed webhooks and Dependency-Track are Go code in the one binary, run by the `notify` and `sync` targets (docs/02, docs/15). A `Connector` resource is configuration only (type, address, a reference to a Secret); no workload is deployed per connector. The gRPC plugin service of docs/19 is for third-party plugins and is Phase 5.
- **One outbound client.** Every connector call goes through a single HTTP client that resolves the host, refuses private, loopback and link-local addresses (SSRF), limits redirects, response size and time, and retries only idempotent calls with exponential backoff and jitter, honouring `Retry-After` (Jira documents 429 with `Retry-After`). Creating a ticket is made idempotent by the `action_ledger` reservation (D25, D66) plus a label that carries the finding id.
- **Secrets.** Read from `secret_material` at the moment of the call, never logged, never in status. A connector reads only the Secret its resource names.
- **Inbound webhooks are public endpoints.** Signature first (Jira `X-Hub-Signature`, GitHub `X-Hub-Signature-256`, Slack `v0` signature with a five-minute timestamp window), then size limit, then parsing. An unsigned delivery is refused. A delivery id (`X-Atlassian-Webhook-Identifier`, `X-GitHub-Delivery`) deduplicates retries.
- **No loops.** Jira documents no flag for a change made by the caller. A change is ours when its actor is our own account and the state it leaves equals the hash of what we last pushed for that `(finding, ticket)` (D23). GitHub: compare `sender.login` with the app's own login.
- **A ticket never decides (D27).** A resolution mapped to `risk_accepted` or `not_affected` creates a request in the approval workflow.
- **Targets.** Slack uses `chat.postMessage` (a channel per call, returns `ts`) rather than incoming webhooks, which are bound to one channel and return no `ts`. Teams uses the Workflows webhook (Microsoft 365 connectors are being retired); digests are truncated with a link at about 28 KB. Jira's REST-registered webhooks expire after 30 days, so the connector's periodic `Check()` refreshes them and says so in status when it cannot.
- **Direction and connector types.** Every connector declares its direction (`direction: outbound | inbound | bidirectional`). Notifiers (Slack, Teams, Email, Webhook) and Trackers (Jira, GitHub Issues) are outbound, with inbound webhook endpoints for resolution updates and callbacks. Source connectors (`dependencytrack`, `sonarqube`) represent inbound ingestion integrations where Rampart pulls or receives external scans.
- **Platform SSRF allowlist for in-cluster and on-premise integrations.** Strictly requiring public HTTPS would prevent running Dependency-Track inside the same Kubernetes cluster (`http://dtrack.dtrack.svc:8080`) or integrating with internal Jira Data Center / GitLab instances. A platform administrator (operator/server level, not per-tenant) can configure an allowlist of permitted CIDRs (e.g. cluster pod/service networks) and internal host patterns (`*.svc`, `*.internal`). For allowed hosts, internal HTTP is permitted if explicitly enabled. Tenant-configured public connectors remain strictly bounded by public HTTPS and anti-SSRF protections.
- **Reconcile-time DNS resolution policy.** If DNS resolution fails during resource reconciliation (e.g. split-horizon DNS or transient network partition), the connector is not immediately failed with `UnsafeAddress` because strict dial-time SSRF guards in `SafeClient` inspect resolved socket addresses before any TCP handshake.
- **Notification routing filters & deep links.** To prevent notification fatigue (>20 findings), connectors can define routing rules (`minSeverity`, `applications`, `events`). All notification deep links are constructed as absolute HTTPS URLs (`https://<publicUrl>/t/<tenant>/findings/<id>` and `/t/<tenant>/applications/<appName>`) matching the UI routing, preventing Slack and Teams from rejecting invalid relative button URLs.
- **SMTP encryption modes & deadline.** Email SMTP enforces `tlsMode`: `starttls` (mandatory default on port 587/25; fails if server lacks STARTTLS extension), `implicit` (SMTPS direct TLS on port 465), or explicit `insecure` (internal/testing only). The entire SMTP conversation runs under a 30-second context deadline to prevent hanging goroutines on slow servers. Finding summaries in emails are bounded to 16 KiB.
- **Verified and recorded for implementation (with vendor sources, read 2026-11-13):**
  - **Jira Cloud** (Atlassian Developer Docs, `POST /rest/api/3/issue`, read 2026-11-13): `description` formatted strictly in Atlassian Document Format (ADF) JSON (`type: doc, version: 1, content: [...]`), `priority` as an object (`{"name": "High"}`), and `labels` as an array of strings. This will be verified against the first live API call or fixture.
  - **Microsoft Teams** (Microsoft Learn, `m365-custom-connectors`, rollout 18–22 May 2026, read 2026-11-13): Office 365 connectors retired; Teams notifier targets Power Automate Workflows webhooks with Adaptive Cards payload.
  - **GitHub Actions OIDC** (GitHub Docs, `reference/security/oidc`, read 2026-11-13): Token lifetime is not documented as a fixed constant on GitHub's reference page; relying code must read `exp` directly from the token claims and exchange it for a Rampart token (15 minutes).
  - **Dependency-Track** (Dependency-Track 4.x / docs, read 2026-11-13): Pagination offset/1-based indexing is not firmly guaranteed across all versions; the client loops until returning fewer items than `pageSize` and validates against `X-Total-Count`. Webhook publisher supports Basic, Bearer, or custom header authentication configured by administrator. Settle detection remains to be confirmed against a running instance in 3.4.

Sources: docs/20-phase-3-plan.md names each vendor page read on 2026-11-13.

### Spike 6 measurement results and limitations (Phase −1 spike 6 / Milestone 3.0)

Executed on 2026-11-13 (`internal/integrations/spike_test.go`): streaming path selection with CEL expression evaluation across 100,000 synthetic records:
- **Observed throughput**: 100,000 records processed in ~1.15–1.3 seconds (~75,000–86,000 records/sec).
- **Observed memory footprint**: HeapAlloc delta of ~0.2–1.8 MiB, total system memory ~18 MiB.
- **Key architectural takeaway**: Computational cost of CEL evaluation and JSON streaming token walking is minimal and will not be the ingestion bottleneck (PostgreSQL writes, indexing, and deduplication are the primary throughput determinants).
- **Explicit limitations of this spike (not a full benchmark)**:
  1. **Expression simplicity**: Evaluated a single title derivation expression (`rec.id + " in " + dep.name`) rather than a full multi-field mapping AST with regexes and severity transforms.
  2. **Record size**: Tested on small synthetic JSON payloads rather than a real-world 500 MiB report with deeply nested arrays.
  3. **No WebAssembly runtime**: Tier 2 `wazero` sandbox execution was not evaluated here (deferred to Phase 4).
  4. Real-world validation of streaming token walk on giant files remains an ongoing exit check during milestone 3.5.



## D70. Trackers, inbound webhooks and the ticket outbox (Phase 3, milestone 3.2), and what in it is known to need redesign

Written after a review of the first 3.2 code (the Jira and GitHub trackers, the inbound webhook handler, the ticket-on-critical automation) and the fixes that followed. Part A is what was decided and built. Part B is the list of decisions that are **known to be wrong or too small** and that will need a redesign; they are recorded here so they are not mistaken for finished work. Sources: D22, D23, D25, D27, D66, D69; Jira, GitHub and Slack documentation as read in docs/20 section 4.

### A. Decided and built

1. **An inbound webhook is acted on only when the sender is proven, and in this order: size, signature, duplicates, payload.** The first version accepted a delivery with no signature whenever the connector had no secret, or the secret could not be read, and remembered delivery ids before checking the signature. That let anyone who knew a tenant id, a connector name and a finding id ask for a risk acceptance, and, on a tenant with approval switched off (D39), have it granted. Now: a connector with no webhook secret answers 503 and acts on nothing; a body over 1 MiB is refused (413), not cut; the signature is checked (Jira `X-Hub-Signature` with the declared method, GitHub `X-Hub-Signature-256`); only then is the delivery id looked up, in a cache that is bounded and expires, keyed by tenant and connector.
2. **The webhook secret is its own secret.** `webhookSecretRef` on Jira and GitHub connectors (stored as `connector:<name>:webhook:<key>`), separate from the API credential. A token that can call Jira must not also be written into Jira's webhook settings. `twoWaySync` without a `webhookSecretRef` is refused at validation. The operator syncs it and reports `WebhookSecretNotFound` when it is missing.
3. **A ticket is tied to its finding by a record Rampart wrote when it opened the ticket, not by a label.** Anyone who can edit a Jira ticket can add `rampart-finding-<uuid>`; trusting it let a user ask for an acceptance on any finding. The ticket reference is now stored in the ledger row (`result.ticket_id`) and the webhook is acted on only if the ticket in the payload is the one recorded for that finding. The label stays, as a hint for people, shortened to `rampart-f-<32 hex>` (42 characters; the old form was 52 and GitHub's limit for a label is 50). Without a verifier the handler acts on nothing.
4. **Only a change of resolution or status decides, and not Rampart's own.** `jira:issue_updated` with a `resolution` or `status` item in its changelog; a comment, a label edit or a change by the account Rampart uses (`accountId`) decides nothing. GitHub: `closed` with `state_reason: not_planned`, on the configured repository.
5. **A ticket never decides (D27), and a false positive asks a person to look.** "Won't Do" asks for a risk acceptance that follows the tenant's workflow, ending in 90 days or sooner if the tenant allows less (the first version ignored `riskAcceptanceMaxDays`). "False Positive" used to ask for a 90-day acceptance, which would reopen the finding after three months; it now creates an in-app notification and changes nothing.
6. **The ticket is opened outside the merge transaction (the outbox).** The first version called the tracker inside the transaction that holds the finding rows (up to 40 s per ticket), marked the ticket as reserved before knowing it succeeded, and never tried again after a failure. Now the merge only reserves the ticket in `action_ledger` (status `reserved`, migration `00027_ticket_outbox.sql`) and records `ticket_requested`. A sweeper (`connectors.RunTicketSweeper`, every minute, one replica at a time by an advisory lock, started only with the system database role because row-level security hides other tenants from the application role) opens the tickets that are due: one call per attempt; on failure it waits 1, 2, 4 ... minutes up to six hours; after 8 attempts it gives up, records `ticket_failed` and notifies the tenant. A reservation with no tracker waits 10 minutes at a time and is closed after 24 hours, so adding a tracker later does not open a ticket for every critical finding ever seen. A finding that is no longer open gets no ticket.
7. **Tracker requests are bounded and honest.** Creating an issue is not retried inside one call. Summaries are cut to 255 characters and titles to 256 on a character boundary (the findings of an Arabic-speaking team are not ASCII); descriptions are cut. Custom fields cannot replace `project`, `issuetype`, `summary`, `description`, `labels` or `reporter`, and the placeholders docs/04 documents (`{{ finding.risk_score }}` and a few more) are filled, a lone placeholder keeping its type. There is no default project: a Jira connector without `defaultProject` is refused. An error from the tracker reports its status, never its body (a body can echo a finding's text). Text from a scanner goes into a GitHub issue only inside a code fence longer than any backtick run in it, or a code span, so it cannot mention a person, load an image or close an issue. A tracker whose credentials cannot be read is an error, not a reason to send the ticket to another connector. Links use the tenant's slug.
8. **Verified by tests:** unsigned, wrongly signed, API-token-signed and no-secret deliveries are refused and remember nothing; a forged label and a ticket for another finding decide nothing; a comment and an edit of a closed ticket decide nothing; an acceptance never runs past the tenant's limit; an oversize body is refused; PostgreSQL tests cover the outbox (one reservation, the system role sees it and the application role does not, deferral, grace period, backoff and giving up with one notification, a ticket belongs only to its finding, no second ticket, a fixed finding gets none).

### B. Known to be wrong or too small: needs redesign

| # | What | Why it is not enough | Redesign |
|---|---|---|---|
| 1 | **One ticket per finding, kept in the ledger.** The outbox row *is* the ticket record (`action_ledger` has one row per tenant, policy, finding and action). | It cannot hold two trackers for one finding, a ticket for a group of findings (3.6 "one ticket per correlation group"), a new ticket when a fixed finding comes back, or the ticket's state. The ledger is an idempotency device, not a data model. | A `ticket` table: `(tenant, id, connector, external_ref, url, state, created_at)` and a link table to findings (many to many). The ledger keeps only "was it requested". Do this before 3.6. |
| 2 | **A lost answer can still open two tickets.** Not retrying inside one call does not help: when a call times out the sweeper tries again, and Jira may already have created the ticket. | Whether a timed-out or 5xx call created the ticket is unknown, and the retry cannot tell. | Look the ticket up by its label before any attempt after the first. GitHub: list issues filtered by label (documented). Jira: a search by label; the search endpoint changed in 2025 and its current form was **not verified**, so this is not built. Until then a duplicate is possible after an ambiguous failure, and the "no retry within a call" rule is only a partial measure. |
| 3 | **Every critical finding opens a ticket on the first Jira or GitHub connector that is not failing.** No opt-in, no choice of which connector, no limit. | Connecting Jira for two-way sync or for a manual workflow makes it the target of automatic tickets; the first import of a project with 300 critical findings opens 300 tickets in minutes; one tenant can starve the sweeper (50 tickets a pass, oldest first, no fairness). Two trackers are not distinguished. | An explicit `ticketing` policy on the connector (`onCritical: true`, minimum band, project per application), a rate cap per connector and per hour with the rest folded into one summary ticket, and a fair order across tenants. |
| 4 | **4xx answers are retried eight times.** | A wrong project, a missing field or a bad token will not heal; eight attempts over hours only delay the message to a person and waste the tracker's quota. | Classify: 400, 401, 403, 404, 422 give up at once and set the connector's `Connected` to false with the reason; 408, 429 and 5xx retry. |
| 5 | **A false positive only notifies.** D27 says an inbound transition to `risk_accepted` or `not_affected` creates a request. | The workflow has a request only for risk acceptance. A "not affected" request needs a VEX justification, an impact statement and an approver, none of which a Jira resolution carries. | Add a `not_affected` request type to the workflow (with justification chosen by the approver), then let the webhook create it. |
| 6 | **`accountId` is typed by the administrator.** | It is easy to get wrong, and a wrong value means Rampart's own changes are read as decisions. | `Check()` calls `GET /rest/api/3/myself`, stores the account id in the connector status, and the handler reads it from there. |
| 7 | **The inbound endpoint is public and has no rate limit.** The path carries the tenant id, and an unsigned request still costs a connector lookup, a secret read and a signature computation. | A flood of unsigned requests is cheap to send and not free to answer. | Per-address and per-connector limits (the quotas of 3.3), and a cheap check before the secret read. |
| 8 | **The delivery cache is in memory, per process.** | With more than one replica a repeated delivery can reach another replica. The workflow refuses a second acceptance for a finding already covered, which limits the harm. | A table of delivery ids with an expiry, shared by the replicas. |
| 9 | **Jira Data Center and Server are not supported.** The tracker speaks REST v3 and `Check()` calls `/rest/api/3/myself`; Data Center offers v2. | The docs and the tracker's first comment said Data Center. | Either an `apiVersion` setting with a v2 body (plain-text description) or an explicit statement that only Jira Cloud is supported. |
| 10 | **`priority` and `labels` are sent without asking the project.** | A project whose screen has no priority field answers 400 for the whole issue. | At `Check()`, read the project's create metadata and send only what it accepts. |
| 11 | **The ticket sweeper exists only where the process has the system database role.** Without `database.systemUrl` it is not started (and says so). | A deployment with only the application role gets reservations and no tickets. | Either require the system role for the `notify` target, or give the application role a narrow security-definer function that lists the due reservations. |
| 12 | **The migration marks every earlier ledger row `skipped`.** | Correct for the placeholder rows that existed (nothing was ever opened), but it would be wrong for any other kind of action recorded later. | Record the action kind in the status, or never reuse `action_ledger` for anything but tickets. |

### C. Not built
Jira's webhook registration and its 30-day refresh (milestone 3.2 continues), GitHub's secondary rate limits (a 403 with `Retry-After`), updating or closing a ticket when its finding is fixed, and the unmapped-state handling for a ticket reopened in Jira.


## D71. Mass-close guard settings, held-close management and confirmation (Phase 3, milestone 3.3)

Decision D22 introduced the mass-close safety guard (`CloseScopeStepWithGuard`) with built-in default constants (holding close when absent findings exceed 50% and 20 findings). D71 formalizes user configuration, persistence of held closes, review and confirmation API/UI, and safe execution semantics.

### 1. Context and Problems
When a scanner misbehaves (e.g., scanner configuration error, misconfigured branch, scanner crash mid-run, or broken rule set), an empty or truncated scan output would otherwise cause Rampart to mark previously open findings as `fixed` (rescan close). D22 prevented mass unintended closure by holding the close step. However:
1. Fixed constants (50% and 20) were hardcoded and could not be tuned per scanner or application.
2. The findings that were held were not stored anywhere, so the user had no way to inspect or confirm the close without re-running the pipeline.
3. No API or UI existed to view, confirm, or discard held mass-closes.

### 2. Decision and Implementation
1. **Configurable Ingestion Policy on ScanSource:**
   `ScanSourceSpec.IngestionPolicy` (`ingestionPolicy`) allows setting:
   - `maxClosePercent`: percentage threshold (1–100, default 50).
   - `minHeldClose`: minimum absolute count of absent findings before the threshold triggers (min 1, default 20).
   Validated on CRD admission, store persistence, and operator reconciliation.
2. **Table `held_close` and Migration 00029:**
   `held_close (id UUID PRIMARY KEY, tenant_id UUID NOT NULL, ingest_run_id UUID NOT NULL, scope JSONB NOT NULL, finding_ids UUID[] NOT NULL, created_at TIMESTAMPTZ, decided_at TIMESTAMPTZ, decided_by VARCHAR, decision VARCHAR)` with row-level security, tenant isolation, and indexes on `(tenant_id, created_at DESC)` and `(tenant_id, ingest_run_id)`.
3. **Ingest Processor Holding Logic & Notification:**
   When `closeScope` detects that absent findings exceed the policy thresholds, it returns `HeldForConfirmation: true` and the list of `HeldFindingIDs`. The ingest processor persists the `held_close` record, generates an in-app notification `close_held` (`NotifyCloseHeld`), and marks the run status as `completed_with_errors` with reason `close_held`. Errors in notification creation are logged (`slog.Warn`) rather than failing the run.
4. **Safe Confirmation with Scope Lock & Staleness Check:**
   When a maintainer confirms a held close (`POST /api/v1/held-closes/{id}/confirm`):
   - An advisory lock is acquired on the scope hash (`pg_advisory_xact_lock`) to serialize concurrent rescans.
   - For each held finding ID, Rampart queries if newer runs for the same scope have re-detected the finding. If a finding came back between the held run and the confirmation, it is **not** closed.
   - Remaining open absent findings are transitioned to `StateFixed`, `ResolutionFixed`, `DetectionAbsent`, and a `closed_by_rescan` event is appended.
   - The held close is marked `decision = 'confirmed'`, `decided_by = caller`, `decided_at = now()`.
5. **Discard API:**
   `POST /api/v1/held-closes/{id}/discard` marks `decision = 'discarded'` without modifying finding states.
6. **Authorization and Audit:**
   Listing held closes requires `viewer` role; confirming or discarding requires `maintainer` role on the application (`scope.allows`). All confirmation and discard operations record structured audit log entries (`action = "held_close.confirm"` / `"held_close.discard"`).
7. **UI:**
   The Workflow page provides a dedicated "Held Closes" tab with a table of held close scopes, finding counts, and timestamps. Selecting a row opens a detail drawer with the list of affected findings and "Confirm Close" / "Discard" actions for maintainers. The Ingest Run Inspector provides a deep link directly to the held close in Workflow.


## D72. CI OIDC federation and RFC 8693 token exchange (Phase 3, milestone 3.3)

Decision D22 defined the architectural principles for keyless CI pipeline authentication via OIDC federation. D72 specifies the protocol implementation, security controls, schema, and validation semantics.

### 1. Protocol and Endpoint
- Standard OAuth 2.0 Token Exchange (RFC 8693) implemented at `POST /ingest/v1/t/{tenant}/token`.
- Accepts form-encoded requests:
  - `grant_type = urn:ietf:params:oauth:grant-type:token-exchange`
  - `subject_token = <JWT>`
  - `subject_token_type = urn:ietf:params:oauth:token-type:jwt`
  - optional `audience`, `scope`
- Responds with JSON:
  - `access_token = rpt_<random_hex>`
  - `issued_token_type = urn:ietf:params:oauth:token-type:access_token`
  - `token_type = Bearer`
  - `expires_in = 900` (15 minutes)

### 2. Trust Rules and Verification Pipeline
1. **Trust Rules on ScanSource (`source_trust` table, migration 00030):**
   - Each `ScanSource` CRD can declare `trustRules[]` containing: `issuer`, `provider` (`github` or `gitlab`), immutable IDs (`repository_id` and `repository_owner_id` for GitHub; `project_id` and `namespace_id` for GitLab), and optional display name `repository`.
   - Stored in table `source_trust (id UUID PRIMARY KEY, tenant_id UUID, scan_source_id UUID, issuer VARCHAR, provider VARCHAR, repository_id VARCHAR, repository_owner_id VARCHAR, project_id VARCHAR, namespace_id VARCHAR, repository VARCHAR, created_at TIMESTAMPTZ)` with tenant RLS.
2. **Step-by-Step JWT Verification:**
   - **Size Limit:** Max request size capped at 64 KiB.
   - **Algorithm Whitelist:** Only asymmetric signatures (`RS256`, `ES256`) allowed. Insecure algorithms (`none`) and symmetric algorithms (`HS256`, etc.) are rejected immediately.
   - **Issuer Allowlist:** The token's unverified `iss` is extracted and matched against configured trust rules for the specified tenant. If no trust rule exists for the issuer, the request is rejected without contacting external networks.
   - **SSRF-Guarded OIDC Discovery & JWKS Fetching:**
     - Key sets are retrieved via `connectors.SafeClient` using the issuer's `/.well-known/openid-configuration` and `jwks_uri`.
     - Private IP ranges, loopback, metadata addresses (e.g. AWS/GCP `169.254.169.254`), and multicast are blocked at dial time.
     - JWKS responses are cached in memory (1 hour TTL) and automatically refreshed on unknown `kid`.
   - **Signature Verification:** The JWT signature is verified against the fetched key set.
   - **Standard Claims Check:** `exp` (with 1-minute clock skew allowance), `nbf` (with 1-minute skew allowance), and required `jti`.
   - **Audience Enforcement:** The token's audience must match `rampart:<public-host>:<tenant.Slug>` (or explicit tenant UUID).
   - **Immutable ID Matching:**
     - For GitHub: token `repository_id` must match `rule.RepositoryID`, and if set, `repository_owner_id` must match `rule.RepositoryOwnerID`.
     - For GitLab: token `project_id` must match `rule.ProjectID`, and if set, `namespace_id` must match `rule.NamespaceID`.
     - Mutable display strings (e.g. `repository`) alone are never sufficient to authorize an exchange, preventing repository takeover/renaming attacks.

### 3. Global Replay Prevention
- Table `federation_jti (issuer VARCHAR, jti VARCHAR, expires_at TIMESTAMPTZ, PRIMARY KEY (issuer, jti))` in migration 00030.
- Because `jti` uniqueness is guaranteed per-issuer (RFC 7519 §4.1.7), the primary key is `(issuer, jti)`.
- Replay check uses `INSERT INTO federation_jti` during the exchange; a unique constraint violation returns 400 (`invalid_grant: token has already been exchanged`).
- Unexpired JTI records are retained until `exp + 1m skew`.

### 4. Downscoped Ingest Token Issuance and Option Tightening
- The issued token has `role = "ingest"` (rank 5, below `viewer` rank 10), granting access solely to report uploads and ingest runs.
- Token is bound to the matched `scan_source_id`.
- Claims context (repository, git ref, commit SHA) is bound to the token as scopes and enforced on every upload (D80). (This line said a `token_context` column held it; no such column was ever built.)
- **Tighten, Never Loosen (D22):** The client may pass query/scope parameters to raise `minimum_severity` (e.g. `high` instead of `medium`) or disable closing (`close_old_findings=false`). It can never lower severity below the ScanSource setting or turn closing on when disabled on the source.
- Structured audit event `federation.token_exchange` is logged on every successful exchange.


## D73. Rate limiting, replica-shared quotas and RFC 9457 throttling (Phase 3, milestone 3.3)

Milestone 3.3 Section 3.4 introduces systematic request rate limiting, payload size controls, and replica-shared usage quotas across API, ingestion, and webhook endpoints.

### 1. In-Memory Token Bucket Limiter (`internal/ratelimit`)
- High-performance, concurrent token bucket implementation in `internal/ratelimit`.
- Evaluates caller identity:
  - For authenticated API tokens: `api:tok:<tenant_id>:<subject>`.
  - For unauthenticated or address-bound callers: `api:ip:<client_ip>`.
- Token-level configuration:
  - Columns `rate_limit INT` and `quota BIGINT` on table `api_token` (migration `00031_rate_limiting.sql`).
  - When configured on `api_token`, custom limits override global defaults.
  - Global defaults from `limits` config block (`limits.apiPerSecond`, default 50 req/sec; burst `max(10, rate)`).
- **Zero-DB Fast Path (Benchmark Verified):**
  - Requests exceeding the in-memory token bucket are rejected in sub-microsecond time (~760 ns/op) without executing database queries or touching connection pools.
- Standard headers on every response:
  - `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`.
  - On 429: `Retry-After: <seconds>` header.

### 2. Replica-Shared Quotas (`quota_usage` table)
- Quotas that must hold across horizontally scaled instances (e.g. hourly uploads per tenant) are persisted in PostgreSQL table `quota_usage`:
  - `(tenant_id UUID, key TEXT, window_start TIMESTAMPTZ, used BIGINT, PRIMARY KEY (tenant_id, key, window_start))`
  - Row Level Security (RLS) enforced with tenant isolation policy.
  - Increments use atomic upsert:
    `INSERT INTO quota_usage ... ON CONFLICT (tenant_id, key, window_start) DO UPDATE SET used = quota_usage.used + EXCLUDED.used RETURNING used;`
- Ingest upload limits:
  - Evaluated on report uploads (`POST /ingest/v1/reports`, `/uploads`, `/sbom`).
  - Window: 1 hour (`time.Hour`). Limit from `token.Quota` or `limits.ingestPerHour` (default 1000/hour).
  - Exceeding the quota returns 429 Too Many Requests with `Retry-After` computed until the next window boundary.

### 3. Payload Size Bounds
- `limits.reportBytes` (default 50 MiB) enforces maximum request body size on direct report and SBOM uploads.
- Excessively large payloads return HTTP 413 (`payload-too-large`).

### 4. Public Inbound Connector Webhooks
- Specialized rate limiter in `InboundWebhookHandler` on `POST /hooks/{type}/{connectorId}` (moved there by D78; it was `/api/v1/t/{tenant}/connectors/{name}/webhook`):
  - Keyed by `webhook:<client_ip>:<connector_name>`.
  - Configurable via `limits.webhookPerMinute` (default 60 req/min, burst 5).
  - Evaluated immediately before reading the request body, connector lookups, or secret resolution, protecting Rampart from webhook amplification floods.

### 5. RFC 9457 Problem Details
- All 429 responses return `Content-Type: application/problem+json` with:
  - `type: "https://rampart.aspm.dev/problems/rate-limit-exceeded"` for burst/token rate limits.
  - `type: "https://rampart.aspm.dev/problems/quota-exceeded"` for tenant hourly upload quotas.
  - `status: 429`, `title`, `detail`, and `retry_after`.


## D74. Dependency-Track integration (Phase 3, milestone 3.4)

Milestone 3.4 implements the production integration with OWASP Dependency-Track as an upstream SCA source (Flows B & C, triage mode `import`, FPF parser, trailing-edge debounce, and CI gate linking per docs/10 and D23).

### 1. Division of Responsibility & Scoping
- Dependency-Track manages SBOMs, component graphs, and continuous vulnerability matching against NVD, GHSA, and OSV.
- Rampart correlates Dependency-Track SCA findings with SAST, DAST, secrets, and IaC, manages risk policies, SLAs, and gating.
- v1.0 ships Flow B (webhooks) and Flow C (pull findings & portfolio) with triage mode `import`. Write-back and SBOM forwarding are deferred post-v1.0.

### 2. Streaming FPF Parser (`internal/parsers/dependencytrack`)
- Implements `parsers.Parser` contract streaming records one by one without buffering full reports in heap (D15).
- Accepts both FPF export documents (FPF 1.0 to 1.4: `{"version": "1.4", "findings": [...]}`) and direct finding endpoints (`[...]`).
- Maps `component`, `vulnerability`, `analysis`, `attribution`, and `matrix` to `domain.RawFinding`.
- Normalizes severity (UNASSIGNED maps to `domain.SeverityInfo` per doc 10 §4 until enrichment), CVSS vectors (v3, v4, v2 fallback), and CWE IDs.
- Maps Dependency-Track analysis states (`NOT_SET`, `IN_TRIAGE`, `EXPLOITABLE`, `NOT_AFFECTED`, `FALSE_POSITIVE`, `RESOLVED`, `isSuppressed`) to standard OpenVEX statements and justifications.
- Tolerates malformed finding records via `pc.RecordError` without failing the surrounding report (D51).
- Registered in the default integrations registry (`internal/integrations/default.go`).

### 3. Hardened Safe REST Client & Capability Probe (`internal/upstream/dependencytrack/client`)
- Authenticates using `X-Api-Key` header.
- SSRF-safe: supports private network / in-cluster Dependency-Track installations (e.g. `http://dtrack.dtrack.svc:8080`) through platform SSRF allowlists (`domain.PlatformSSRFAllowlist`).
- Probes required capabilities (`VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`) via `/api/v1/team/self`, with automatic fallback to endpoint probing if team self is unavailable.
- Integrated into `DefaultChecker.Check` in `internal/connectors/checker.go`.

### 4. Webhook Receiver with Trailing-Edge Debounce (`internal/upstream/dependencytrack/webhook`)
- Mounted at `POST /hooks/dependency-track/{id}` where `{id}` is the opaque `ScanSource` UUID.
- Authentication verifies `Authorization: Bearer <secret>` in constant time against stored credentials (`scansource:<name>:webhook` or `scansource:<id>:webhook`).
- **Thin event, fat fetch**: treated as an untrusted hint, extracting only project UUIDs from `notification.subject.project.uuid` or `affectedProjects[].uuid`. Acknowledges immediately with HTTP 202 Accepted.
- **Trailing-edge debounce**: Persisted in PostgreSQL table `dtrack_sync (tenant_id, project_uuid, state, dirty, last_sync_at)`. An event during a running sync sets `dirty = true`. Upon completion, if dirty, exactly one trailing sync pass is executed. A burst of 50 events triggers at most two sync runs.
- `BOM_PROCESSING_FAILED` and `BOM_VALIDATION_FAILED` are logged and mark associated ingest runs failed.

### 5. Settle Verification & Identity Mapping Engine (`internal/upstream/dependencytrack/sync`)
- **Settled analysis check**: Reads findings twice separated by backoff or verifies `ProjectMetrics.lastOccurrence > lastBomImport`. If identical or newer, analysis is treated as settled.
- **7-step identity mapping engine**:
  1. Project property: `group=integrations`, `name=rampart.application`.
  2. Project tag prefix: `rampart-app:<slug>`.
  3. Existing asset link: `dtrack_project_uuid` on asset.
  4. purl or repository match against known asset keys.
  5. Parent rule: root parent project name is the application.
  6. CEL rule: expression over project (`name`, `tags`, `classifier`, `purl`).
  7. Fallback: default application, or listed as unmapped in `dtrack_project` table with reason.
- Mapped projects create or link an asset of type `sbom_project` (`dtrack://<sourceID>/<projectUUID>`) and merge findings using `ingest.Merge` under tenant RLS transaction.
- Mass-close guard (D22/D71) prevents dropping findings when zero vulnerabilities are returned.

### 6. CI Gate Integration (`internal/query/gate.go`)
- The CI gate matches `dependency-track` and `dtrack` scanner families.
- When a pipeline uploads an SBOM with `expect: ["sbom"]`, the gate automatically detects any linked Dependency-Track sync run for that build.
- If the sync is still in progress, the gate returns waiting (`"waiting for dependency-track: the linked sync run is <status>"`).
- Once terminal, the findings from the sync run are evaluated against `failOn`, and the run ID is appended to `resp.Runs`.


## D75. Integration SDK, declarative mapping engine, and Wave 2 parsers (Phase 3, milestone 3.5)

Milestone 3.5 implements the Integration SDK extension framework, declarative parser mapping engine, conformance kit, and Wave 2 scanner parsers per docs/19, docs/21 §5, and D15.

### 1. Contracts & Unified Registry (`internal/integrations`)
- Standardized extension contracts:
  - `ParserContract`: streaming ingest (`Detect`, `Parse` via `iter.Seq2[domain.RawFinding, error]`).
  - `SourceContract`, `TrackerContract` and `NotifierContract`. **Superseded by D96:** no real connector ever implemented them, and they were removed.
- The `Descriptor` carries metadata and JSON Schema (`ConfigSchema`, `Secrets`, `Egress`, `Capabilities`), allowing dynamic UI configuration forms and server-side validation without hardcoding forms.
- ~~All built-in connectors are adapted to the contracts and pre-loaded in `DefaultRegistry()`.~~ This was never true (docs/23 K1, K2): the adapters were placeholders, removed by D82, and the contracts by D96.

### 2. Tier 1 Declarative Mapping Engine (`internal/integrations/mapping`)
- Declarative YAML specification (`runtime: mapping`) allows defining streaming parsers without writing Go code.
- **Streaming selector**: walks JSON tokens one record at a time matching JSON path selectors (e.g. `$.dependencies[*].vulns[*]`). Only a single record and its parent context are in heap at any moment. Strict limits enforced: `maxDepth: 64`, `maxRecords: 500,000`.
- **CEL Environment**: expressions compiled once with a cost limit per record (`cel.CostLimit(50,000)`). Standard helper functions: `lowerAscii`, `trim`, `split`, `regexExtract`, `parseCvss`, `toInt`, `firstNonEmpty`, `sha256`. Missing fields evaluate to empty strings/zero rather than panicking.
- **Record Error Isolation**: bad records or evaluation failures are reported through `pc.RecordError` (D51) and skipped, allowing the report to complete.
- **Memory Boundedness**: streaming 50,000 synthetic records operates in < 10 MB heap, verified by automated memory benchmarks.

### 3. Conformance Kit (`internal/integrations/conformance`)
- Test harness `RunSuite` verifies any parser contract:
  - Detection confidence scoring.
  - Parse execution and record error isolation.
  - Secret leakage prevention (D42): asserts raw secrets never leak into `Title`, `Description`, or `Location`.
  - Deterministic idempotency: guarantees identical findings count and keys across repeated runs and reordered inputs.

### 4. Wave 2 Scanner Parsers (`internal/parsers/`)
- Eight new scanners implemented and registered in `DefaultRegistry`:
  1. **Checkov** (`internal/parsers/checkov`): IaC scanner (Terraform, CloudFormation, K8s, Dockerfile) mapping to `domain.CategoryIaC`.
  2. **Bandit** (`internal/parsers/bandit`): Python SAST scanner mapping to `domain.CategorySAST` with CWE extraction.
  3. **Nuclei** (`internal/parsers/nuclei`): DAST template scanner parsing line-delimited JSON (JSONL) with web locations and CVSS vectors.
  4. **OWASP ZAP** (`internal/parsers/zap`): DAST scanner parsing JSON alert trees into web locations.
  5. **OWASP Dependency-Check** (`internal/parsers/dependencycheck`): SCA scanner extracting purls, packages, and vulnerabilities.
  6. **Snyk** (`internal/parsers/snyk`): SCA scanner parsing vulnerabilities, purls, fixed versions, and CVSSv3.
  7. **kube-bench** (`internal/parsers/kubebench`): CIS Kubernetes benchmark scanner filtering failed/warning checks to `domain.CategoryCompliance`.
  8. **Prowler** (`internal/parsers/prowler`): Cloud security and compliance scanner mapping to `domain.CategoryCSPM`.
- Added scanner families to `compliance.FamilyCategories` (`bandit`, `dependency-check`, `snyk`, `kube-bench`) for compliance matrix evaluation.

## D76. Groups, saved views, streaming exports, live updates SSE, and operational dashboards (Phase 3, milestone 3.6)

Milestone 3.6 implements finding groups, saved views, streaming exports, live updates via Server-Sent Events, threat intelligence & CODEOWNERS ownership, and operational monitoring per docs/20, docs/21 §6, and D16/D59.

### 1. Finding Groups & Correlation Group Ticketing (`internal/domain`, `internal/store`)
- **Finding Groups**: User-defined campaign groups (e.g. "Log4j remediation", "Q4 compliance drive").
  - Table `finding_group` (`id`, `tenant_id`, `name`, `description`, `owner`, `created_at`, `updated_at`) and `finding_group_member` (`tenant_id`, `group_id`, `finding_id`) with strict PostgreSQL Row-Level Security (RLS) tenant isolation.
  - API endpoints: `GET /api/v1/groups`, `POST /api/v1/groups`, `GET /api/v1/groups/{id}`, `DELETE /api/v1/groups/{id}`, `POST /api/v1/groups/{id}/members`, `DELETE /api/v1/groups/{id}/members`.
  - Links to ticketing: a finding group or correlation group (`correlation_key`, D24, D37) can be tracked by a single outbound ticket in `ticket_finding` instead of opening N redundant tickets.

### 2. Saved Views with EBNF Grammar Validation (`internal/query/groups_views.go`)
- Table `saved_view` (`id`, `tenant_id`, `owner`, `name`, `query`, `sort`, `scope`, `created_at`, `updated_at`).
- **Scope protection**: Supports `user` (visible only to the owner) and `tenant` (shared across the tenant). A view never widens what the caller is authorized to view.
- **Strict Grammar Re-Validation (D16, D59)**: Stored query text is parsed and validated using `grammar.Parse` on creation and retrieval. Queries containing unknown fields or malformed expressions are rejected with 400 Bad Request to prevent inadvertent broad matches during bulk operations.

### 3. Streaming Query Exports (`internal/query/exports.go`)
- `GET /api/v1/findings/export?format=csv|json|ocsf&q=<query>`:
  - **Memory-bounded streaming**: Writes findings directly to the response writer without holding the complete dataset in memory; capped at 50,000 records.
  - **Proxy Buffering Disabled**: Emits `X-Accel-Buffering: no` so reverse proxies (Nginx, Envoy) flush records immediately.
  - **CSV Export**: Standardized headers (`id`, `rule_id`, `scanner_family`, `title`, `severity`, `category`, `state`, `location`, `risk_score`, `first_seen`, `last_seen`).
  - **JSON Export**: Full JSON array of domain findings.
  - **OCSF Export**: Conforms to OCSF Class 2001 (Security Finding) with normalized `activity_id`, `category_uid`, `class_uid: 2001`, `severity_id` (1–5), and vendor metadata.

### 4. Live Updates via Server-Sent Events (`internal/query/events_sse.go`)
- `GET /api/v1/events`:
  - Real-time event stream for tenant notifications (`run_finished`, `finding_changed`, `held_close_pending`, `ticket_dispatched`).
  - **15-second Keep-Alive**: Emits periodic `: ping\n\n` comments to prevent intermediary proxies, load balancers, and browser timeouts from dropping idle connections.
  - Web client invalidates TanStack Query cache keys on incoming events, eliminating aggressive polling.

### 5. Threat Intelligence (NVD) & CODEOWNERS (`internal/enrich/nvd.go`, `internal/domain/codeowners.go`)
- **NVD API 2.0 Feed Parser (`internal/enrich/nvd.go`)**: Ingests CVE vulnerabilities, CVSS v3.1/v4.0 metrics, and CWE mappings into the persistent `feed_state` store.
- **CODEOWNERS Resolver (`internal/domain/codeowners.go`)**: Parses GitHub/GitLab `CODEOWNERS` rules; matches finding source file paths against glob patterns with last-rule-wins semantics. Only tenant members can be assigned as finding owners (D59).

### 6. Operational Dashboards & Prometheus Alerts (`deploy/helm/rampart`)
- **Prometheus Metrics (`internal/telemetry/metrics.go`)**:
  - `rampart_ticket_outbox_depth` & `rampart_ticket_dispatches_total`: Outbox lag and dispatch success/retry rates.
  - `rampart_connector_status`: Health probe state per connector (1=healthy, 0=disconnected).
  - `rampart_held_close_pending`: Count of held mass-close batches awaiting maintainer review.
  - `rampart_feed_syncs_total`: Threat feed synchronization outcomes.
- **Grafana Sidecar ConfigMaps (`deploy/helm/rampart/templates/dashboards-configmap.yaml`)**:
  - Curated dashboards for "Ingest & Security Overview" and "Operations & Connectors".
- **PrometheusRule (`deploy/helm/rampart/templates/prometheusrule.yaml`)**:
  - Alert rules for stalled ticket outbox (>1 hour), disconnected connectors (>15m), pending held closes (>1h), failing feed syncs, and elevated ingest error rates (>10%).

## D77. The SSRF allowlist is scoped to tenants and connector types (docs/23 C1)

D69 let a platform administrator allow private CIDRs and internal host patterns (an in-cluster Dependency-Track, an on-premise Jira) for **every** connector of **every** tenant. On a shared install that let any tenant admin point a webhook connector at `kubernetes.default.svc`, the bundled object store or any other internal endpoint the exception covered: the always-blocked list (metadata, loopback, link-local) does not include cluster service ranges.

- **The exception names its scope.** `connectors.ssrfAllowlist.tenants` (tenant ids from `Tenant.status.tenantId`, or `"*"`) and `connectors.ssrfAllowlist.connectorTypes` (`dependencyTrack`, `jira`, …, or `"*"`); env `RAMPART_CONNECTORS_SSRF_ALLOWLIST_TENANTS` and `…_CONNECTOR_TYPES`. Both are required whenever CIDRs, hosts or internal HTTP are set; an allowlist without them, a tenant that is not an id, or an unknown connector type is **refused at startup** with the reason, not guessed at (the same rule as D41 and D53). `"*"` must be written explicitly. Tenant ids rather than slugs because a slug can be renamed and the dial-time check only knows the id.
- **Applied where the connector is known.** `PlatformSSRFAllowlist.ScopedTo(tenant, type)` returns the allowlist as it applies to one connector; out of scope it grants nothing (only the test switch `AllowLoopback` survives). The operator validates a `Connector` against its scoped allowlist; the checker, the notifiers (Slack, Teams, webhook) and the trackers (Jira, GitHub) use `SafeClient.Scoped(tenant, type)`; the Dependency-Track probe uses the checker's scoped client.
- **Checked before sending and at dial time.** A scoped client puts its allowlist on each request; the dialer and the redirect check read it from there. A request is also checked just before it is sent (`domain.ValidateOutboundURL`, which refuses a name that does not resolve), because a pooled connection is reused without a new dial: without it a request outside the scope could ride a connection an in-scope connector opened. An unscoped client (for example CI federation key fetching, D72) gets the default policy: public addresses only.
- **Unchanged:** the always-blocked addresses are never allowed; internal HTTP is still allowed only for allow-listed host names, not for IP literals (D69); e-mail keeps refusing internal SMTP hosts.
- **Upgrade note.** An existing configuration with CIDRs or hosts and no scope now fails to start and says what to add. That is deliberate: the previous behaviour was the hole.
- **Not built:** several rules with different hosts for different tenants (one rule today; a list of rules is the next step if needed); an issuer of CI federation on a private network.
- **Tested:** `TestSSRFAllowlistScopedTo` (in scope, other tenant, other type, no tenant, `"*"`, nil, loopback switch), `TestValidateOutboundURLRefusesUnresolvableHost`, `TestSafeClientScopedAllowlist` (unscoped, other tenant and other type refused before any connection; in scope passes the guard), and the configuration refusals in `TestConnectorsSSRFAllowlistConfig`.

Sources: OWASP Server-Side Request Forgery Prevention Cheat Sheet (allow-list per use case; deny internal networks for user-supplied URLs), https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html ; docs/23 C1.

## D78. Inbound webhooks are `/hooks/{type}/{connectorId}` on the ingest gateway (docs/23 C2)

D70 and D73 put the Jira and GitHub callbacks at `POST /api/v1/t/{tenant}/connectors/{name}/webhook`, on the query API. Docs 04 (`status.webhookURL: …/hooks/jira/…`), 11 (the `/hooks` table) and 15 (the route split) put public callbacks under `/hooks` on `ingest-gateway`. The `/api/v1` form had three faults: in distributed mode the Ingress sends `/api` to `query-api`, the read path; it put unauthenticated routes inside the prefix whose rule is "session or API token"; and its URL carried the tenant id and a connector name anyone could guess.

- **The path.** `POST /hooks/jira/{connectorId}` and `POST /hooks/github/{connectorId}`, mounted with the ingest-gateway routes. `{connectorId}` is the connector row's id (UUIDv7, stable across re-applies: `ON CONFLICT` keeps it, and the operator and `rampart apply` read it back before writing the URL). The old route is removed, not kept as an alias: its shape was the problem.
- **The tenant comes from the row, never the path.** The caller is not signed in, so the request has no tenant and row-level security hides every connector from the application role. Migration `00035_connector_webhook_lookup.sql` (schema version 35, chart `minSchemaVersion` 35) adds one `SELECT` policy, `webhook_lookup`, that shows the single row whose id the handler sets in `app.webhook_connector_id` for the lookup transaction only (`set_config(…, true)`). `Store.GetConnectorByID` is the only reader. A security-definer function was not used: the connector table forces row-level security, so even its owner would see nothing without a tenant.
- **A wrong type answers like a missing connector** (404), so the path cannot be used to learn what a connector is. An outbound connector still refuses any delivery (400). The D70 order is unchanged: rate limit (now keyed by address and connector id), size, signature with that tenant's webhook secret, duplicates, payload.
- **Which connectors get a URL.** `domain.InboundWebhookPath`: only Jira and GitHub with two-way sync, the only ones that are called back. The generic `webhook` connector, which only sends, no longer shows a callback URL in its status.
- **Upgrade note.** A Jira or GitHub webhook registered against the old URL stops being delivered: copy the new `status.webhookURL` into Jira or GitHub. The registration itself is still done by hand (D70 part C).
- **Not built here:** Dependency-Track's `/hooks/dependency-track/{id}` (docs/23 K5, its own slice; its `LookupScanSource` reads `scan_source` without a tenant and needs the same kind of policy); a per-connector cap independent of the address (docs/23 C3).
- **Tested:** `TestInbound_PathIsTheConnectorIDAndType` (wrong type, unknown id, the old tenant path, a name instead of an id: all refused and nothing acted on; the right path works), the existing inbound tests on the new path, `TestInboundWebhookPath`, `TestApply_Connector`, and on PostgreSQL `TestGetConnectorByID_OnPostgreSQL` (the application role finds the row and its tenant by id, an unknown id finds nothing, and afterwards another tenant still sees none of the connectors).

Sources: docs 04 §4, 11 (Hooks), 15 (route split); D27 (`ingest-gateway` serves the write path), D70, D73; docs/23 C2.

## D79. A token can only tighten the platform's limits, and the limits in one table (docs/23 C4)

D73 let `api_token.rate_limit` and `api_token.quota` **override** the global defaults, so a token with `rate_limit: 1000` or `quota: 1000000` lifted its tenant above the platform's limit, and whoever can create a token could do it. The hourly upload quota was also counted on one tenant counter but compared with the token's own number, so one token's quota decided for the whole tenant.

- **Tighten, never loosen** (the rule D22 applies to upload options). A token's rate applies only when it is lower than `limits.apiPerSecond`; its burst is then at most the platform's. A token's quota applies only when it is lower than `limits.ingestPerHour`.
- **Two counters.** The tenant counter (`ingest:uploads`) always applies, with the platform limit. A token with a lower quota is also counted on its own counter (`ingest:uploads:token:<subject>`), so it is held to its number without changing what the tenant's other tokens may do. The token counter is checked first; an upload refused by the tenant counter after passing the token counter is counted once on the token, which errs on the strict side.
- **Unchanged from D73:** a failure of the quota store does not block ingest (the in-memory limiter still applies); the limits are per replica in memory (docs/23 C3 is separate).
- **Removed:** the middleware's skip for `/connectors/…/webhook` paths, dead since D78 moved webhooks to `/hooks`.

**The limits, in one place.** Every document that names a limit should point here.

| Limit | Where it is set | Default | Enforced |
|---|---|---|---|
| Requests per second to `/api/v1` and `/ingest/v1` | `limits.apiPerSecond`; a token may lower it | 50 (burst 50, at least 10) | yes, per replica (D73) |
| Uploads per hour per tenant | `limits.ingestPerHour`; a token may lower it for itself | 1000 | yes, shared across replicas in `quota_usage` |
| Request body of a direct upload (`Content-Length`) | `limits.reportBytes` | 50 MiB | yes, at the middleware |
| Direct multipart upload (`POST /reports`) | constant | 32 MiB | yes, in the handler (docs/11) |
| Declared size of a presigned upload | `ingest.maxReportBytes` | 512 MiB | yes, at create and signed into the URL (D9, D34) |
| Webhook deliveries per address and connector | `limits.webhookPerMinute` | 60 a minute, burst 5 | yes (D73, D78) |
| `Tenant.spec.quotas` (`maxIngestsPerHour`, `maxReportBytes`) | docs/04 | — | **not built**: the resource field is not read. When built it joins the same rule: the smallest of platform, tenant, source and token wins |
| `ScanSource.ingestionPolicy.maxReportBytes` | docs/04, stored | — | **not built**: stored, not enforced |

- **Tested:** `TestTokenCannotRaiseLimits` (a token asking for rate 1000 and quota 1,000,000 is held to the platform's 5 a second and 2 an hour) and `TestTokenQuotaTightensOnItsOwnCounter` (a token with quota 1 gets one upload while another token of the tenant keeps the tenant's quota); the D73 tests unchanged.

Sources: D22 ("clients may tighten, never loosen"); D73; docs/23 C4.

## D80. A federated upload's repository, branch and commit are the token's (docs/23 H2)

D22 says the exchanged token is "bound to the source and the derived context", and D72 said the context was kept in `token_context`. No such column existed, and nothing compared the context: both upload paths took `repository`, `branch` and `commit` from the request (D30). Closing happens only for tracked refs (D10, D22), and the request named the ref, so a CI run on a feature branch could upload with `branch=main` and close `main`'s findings, or write into another repository's asset.

- **The binding.** At the exchange the token gets scopes from the verified claims: `bind:repo:<url>`, `bind:ref:<ref>` and, when the claim is present, `bind:sha:<sha>`. GitHub: `repository` (under `https://github.com` for the public issuer, or the host of a GitHub Enterprise Server issuer `https://HOST/_services/token`; under any other issuer the repository is bound by `owner/repo` alone), `ref`, `sha`. GitLab: the issuer plus `project_path`, `ref` (as `refs/tags/<ref>` when `ref_type` is `tag`), `sha`. Scopes are stored with the token, so every replica and both paths read the same binding.
- **The rule, on both paths** (`POST /ingest/v1/reports` and `/sbom`, and `POST /ingest/v1/uploads`, whose context the parse worker uses later). `BindUploadContext`: a field the request leaves empty is filled from the token; a field it states must agree, or the upload is refused with 403 and the reason. Repositories compare by their normalized key (D56), so `git@github.com:Acme/shop.git` and `https://github.com/acme/shop` agree. `refs/heads/main` and `main` agree; a pull-request or tag ref is kept whole, so a pull-request run stays ephemeral (D10). A commit may be given abbreviated (7 or more characters of the bound sha) and is then stored in full.
- **Tokens without a binding** (personal API tokens, device-login tokens, the UI's uploads) are unchanged: whoever holds them is trusted to state the context, as before.
- **Defence in depth in the exchange.** A trust rule without its immutable ids (`repository_id` and `repository_owner_id`, or `project_id` and `namespace_id`) now matches nothing. Validation already refused such a rule; this keeps a bad stored row from matching every repository of an issuer.
- **Not bound:** `imageRef` and `imageDigest` (no CI claim carries them; an image-scan upload still states them), `environment`, `service`. Optional trust-rule conditions on `ref`, `ref_protected` and `environment` (docs/23 H2 item 3) are not built. Items 1 and 2 are settled in D81.
- **Found while building it:** the tightening scopes `min_sev` and `no_close` reached the direct path only. Fixed in D81.
- **Tested:** `TestFederation_UploadContextIsTheTokens` (exchange, then: a feature-branch token claiming `main`, another repository and another commit are refused on the direct path; the presigned create with `main` is refused; nothing stated, the same values in other spellings, the long ref and the URL form are accepted), `TestFederationBindings` (public GitHub, GitHub Enterprise Server, an unknown issuer, GitLab tags), `TestBindUploadContext` (filling, pull-request ref kept, mismatches, a too-short sha, an unbound token untouched); the existing federation tests and the PostgreSQL token tests.

Sources: GitHub, OpenID Connect reference (claims `repository`, `ref`, `sha`; issuer of GitHub Enterprise Server), https://docs.github.com/en/actions/reference/security/oidc ; GitLab, ID token authentication (claims `project_path`, `ref`, `ref_type`, `sha`), https://docs.gitlab.com/ci/secrets/id_token_authentication/ ; D10, D22, D30, D56, D72; docs/23 H2.

## D81. An ingest token reaches only uploads and the gate; its options reach the presigned path (docs/23 H2)

Two defects found while building D80, and one item of docs/23 H2 that was already built.

- **A CI ingest token could read the whole tenant.** Role `ingest` (D72) is below `viewer`, and `RequireRole(viewer)` refuses it, but most `/api/v1` read routes check only that the caller belongs to the tenant (`resolveTenant`), not the role. A 15-minute federated token, or any API token with role `ingest`, could therefore list every finding, application, risk acceptance, run and export of its tenant. **Now** every route the query API registers passes through one guard: a caller whose role is `ingest` gets 403 everywhere except `POST /api/v1/gate`, which `rampart gate` calls from the pipeline with the token it uploaded with (D26, D37). The guard wraps the routes at registration, so a route added later is covered without remembering to. Callers with no credentials or another role pass through untouched; `/api/v1/me` and the sign-in routes are registered by the auth handlers and stay reachable (they tell a token who it is, nothing about the tenant's data). This is docs/23 H2 item 1: the fix is not to change the rank but to make the write-only role write-only.
- **The presigned path ignored the tightening options.** `min_sev:<severity>` and `no_close`, which a client may ask for at the exchange (D22), were read on the direct path only; the parse worker of a presigned upload never saw the token. **Now** `POST /ingest/v1/uploads` stores them in `upload.options` (a JSONB column the first migration created and nothing used; no migration needed) as `{min_severity, no_close}`, and the worker applies them. `TokenOptions` reads them the same way on both paths.
- **Already built, not documented:** refetching an issuer's keys on an unknown `kid` is limited to once per 15 seconds per issuer (`JWKSCache.GetKeySet`, with `TestFederation_JWKSCacheRateLimiting`). docs/23 H2 item 2 asked for it from the documents alone; the code had it.
- **Tested:** `TestIngestTokenReachesOnlyTheGate` (an ingest token gets 403 on findings, applications, risk acceptances, runs and exports, and is not refused by the gate; a viewer still reads); on PostgreSQL `TestPresignedUpload_AppliesTheTokensOptions` (a token with `min_sev:critical` and `no_close` uploads through a presigned URL; the upload keeps the options and the worker skips the findings below critical). The whole test suite passes.

Sources: D22, D26, D37, D72, D80; docs/23 H2.

## D82. Connectors are created only as resources; the UI lists, describes and validates them (docs/23 C5, K1, K7)

**Decision (user, 2026-11-16):** a `Connector` is created, changed and deleted only as a Kubernetes resource (kubectl, GitOps) or, without Kubernetes, with `rampart apply -f` (D3). The API has no route that writes a connector, and no secret value ever passes through the API or the browser. docs/20 §9.3 item 8 left this open; docs/22 part 3 planned a dialog that took URLs and credentials.

**Why.**
- **Configuration is Kubernetes, data is PostgreSQL** (ADR 0001, docs/02 §1). The same rule already governs `SLAPolicy`, `RiskPolicy`, `IdentityProvider` and `ScanSource`; a second write path for one kind would make two sources of truth.
- **A connector carries secrets.** D1 makes the operator the only reader of Kubernetes Secrets, which it copies, encrypted, into `secret_material`. A UI path would send the secret through the browser and `query-api` into the database, outside the Secret that is its source of truth, and would need its own roles, audit, write-only fields, rotation and the `NameTakenByUI` conflict (D21), all to duplicate what `kubectl apply` already does.
- **It is the product's distinguishing property.** "Configured as code" is one of the four claims of docs/24, and none of the competing products reviewed there documents it. A UI write path would weaken it for the one kind that matters most to an auditor.
- doc 13 §4 allows objects created in the UI in general; for connectors this decision narrows it.

**What was built.**
- `GET /api/v1/connectors`: the tenant's connectors with their spec (secret references only) and the status the operator wrote after its `Check` (D69), `managed_by: resource`.
- `GET /api/v1/connectors/catalogue`: the connector types of this build. Each has its kind, directions, description, the secrets it reads and what they must hold, a config schema **generated by reflection from the Go config struct the server decodes** (so the form cannot drift from the server; a field without `omitempty` is marked required; the server's validation remains the authority), and an example made of a `Connector` and a `Secret` template with placeholders. `TestConnectorCatalogueExamplesApply` applies every example through `internal/config/apply`, the library the operator uses, so an example the server would refuse fails the build.
- `POST /api/v1/connectors/validate`: a dry run. The body is the resource in YAML or JSON, or `{"resource": "<yaml>"}` from the UI. It runs `Connector.ValidateWithAllowlist` with the SSRF allowlist scoped to the caller's tenant and the connector's type (D77), as the operator does, stores nothing, and answers 200 with `{valid, reason, error}`, where `reason` is the one the operator would write (`InvalidSpec`, `NotSupported`, `UnsafeAddress`). A body whose first document is not a `Connector` (for example a `Secret`) is refused.
- **The UI** (`ConnectorCatalogueDialog`, `IntegrationsRoute`): the catalogue comes from the API; choosing a type shows what its secrets must hold and an editable resource; **Validate** calls the dry run and shows the server's answer; **Copy YAML** copies it for `kubectl apply`. Removed: the "Test connection" that waited 700 ms and printed "HTTP 200 OK with valid credentials" without calling anything; "Save", which added a row marked connected to the browser's state only; the YAML that the CRD refused; the four invented connectors the page showed when the list failed; the "Check" button that read the status already on the page. A connector's state is now the operator's `Connected` condition: connected, failing, or not checked yet.
- **The API Tokens tab** was also invented: tokens kept in browser state and a random string presented as a secret. There is no token API. The tab now says how tokens are issued: CI federation (D72, D80) and `rampart login` (D65). A token-management API is not built.
- **Registry placeholders removed (docs/23 K1).** `internal/integrations/builtin_adapters.go` registered a Jira "tracker" returning `RAMPART-101`, a GitHub one returning issue 42, notifiers that sent nothing and a Dependency-Track "source" yielding an invented CVE; nothing but their own test called them. They are deleted; the contract test now asserts that no tracker, notifier or source is registered until real implementations are (docs/23 §6).
- **Dev mock:** the catalogue and the dry run are served for local development.

**Tested:** `TestConnectorsAPI_ReadDescribeValidate` (list, catalogue of seven types, a catalogue example and its JSON form validate; a missing field, a private address, a `Secret` first and an unsupported type are refused with the reason; `POST /api/v1/connectors` does not exist); `TestConnectorCatalogueExamplesApply`; Vitest with axe: the list shows the server's rows and "Not checked yet" for an unchecked connector, the dialog validates against the server twice and never saves or asks for a secret, the tokens tab invents nothing. The Go suite, typecheck, lint, the 138 web tests and the build pass.

Sources: ADR 0001; docs/02 §1; D1, D3, D21, D69, D77; docs/13 §4; docs/23 C5, K1, K7; docs/24 §3–5.

## D83. A held close is superseded by a newer run, and never closes what another source still reports (docs/23 H1)

D71's confirm walks the held findings, skips one that a later run of the same scope saw again, marks the scope's occurrences not present and moves the rest to `fixed`. Reading the code corrected part of docs/23 H1: step 1 of D13 (the scope's occurrences become `present = false`) **was** done. Two defects remained.

- **Another source.** D13 keeps a finding open while any source still reports it. The confirm closed a held finding whatever other scanners said. **Now**, after this scope's occurrences are marked not present, the finding is closed only if no occurrence of any source is still present; otherwise it stays in its state, with its detection still present.
- **Nothing superseded a hold.** After a newer run of the scope, an old hold described a state that no longer existed, and stayed pending for ever: confirming it applied a stale list, and the "held close pending" alert (D76) never cleared. **Now** a hold has a fourth decision, `superseded` (next to confirmed and discarded):
  - On confirm, if a run of the same scope (source, scanner family, asset, track; read from `ingest_run_scope`) completed after the held run, the hold is marked `superseded`, nothing is closed, and the API answers 409 with the reason.
  - When a run's close step runs for a scope, held or not, every older pending hold of that scope is marked `superseded` (`decided_by = system:run:<id>`). A new hold therefore replaces the previous one instead of piling up.
- **Unchanged:** the advisory lock on the scope, the check that a held finding came back in a later run, the audit entry, D71's roles.
- **Kept as it is, for a later decision:** a held run still ends `completed_with_errors` with reason `close_held` (D22). docs/23 H1 suggested `completed` with a flag; the gate and the run page read the status, so changing it is a decision of its own.
- **Tested on PostgreSQL** (`TestHeldClose_SupersededAndOtherSources`): 30 findings, one also reported by another source; a run reporting nothing is held; confirming closes 29 and leaves the one still reported open; a second hold older than a completed run of the scope is superseded and closes nothing; a close step supersedes an older pending hold of its scope and leaves another scope's alone. `TestHeldClose_PostgresScenarios` (D71) unchanged and passing.

Sources: D13, D22, D71, D76; docs/23 H1.

## D84. Exports, the client address, and the Dependency-Track reads (docs/23 E1, C3, K6, DT1)

- **CSV export defuses formulas (E1).** Rule ids, scanner families, titles and paths come from scanners; a cell starting with `=`, `+`, `-`, `@`, a tab or a CR is prefixed with `'`, the same `csvSafe` the audit export uses (D46; CWE-1236, OWASP CSV Injection).
- **A cut export says so (E1).** The export reads one row more than its limit (50,000); when there are more, it answers with `X-Export-Truncated: true` and `X-Export-Limit`. The asynchronous export to object storage that docs 02, 11 and 13 describe for large exports is not built.
- **OCSF class: open, not changed (E1).** The export writes class 2001 (Security Finding), deprecated in favour of 2002, 2003 and 2004; ADR 0003 chose 2007. Reading the OCSF 1.3.0 schema showed that Vulnerability Finding (2002) requires `cloud` and `osint` objects, which an application finding does not naturally have. The class and version are therefore a decision to take with a test against the official schema, not a constant to swap. Until then the output keeps saying what it is ("Security Finding (OCSF 2001)").
- **The client address behind a proxy (C3, first part).** `server.trustedProxies` (env `RAMPART_SERVER_TRUSTED_PROXIES`, CIDRs, validated at startup). `X-Forwarded-For` is read only when the direct peer is one of them, from the right, skipping the trusted proxies; the first other address is the client. Without the setting, or from any other peer, the header is ignored, because anyone can send it (RFC 7239 describes the same chain). Before, the peer address was used always, so behind an ingress every caller shared one rate-limit bucket. Not built from C3: limits shared across replicas (Valkey) and a per-connector cap independent of address.
- **Dependency-Track responses are never cut (K6).** The client read each response through a 10 MiB limit and kept what fit, with no error; a cut finding list would read as findings that disappeared. Now the cap is 64 MiB and a larger response is an error (`ErrResponseTooLarge`), so the run fails and closes nothing (docs/10 §5, D35's rule of refusing rather than cutting).
- **"Settled" is read from the project (DT1).** `CheckSettled` waits until `project.lastVulnerabilityAnalysis >= project.lastBomImport`, read from `GET /api/v1/project/{uuid}`, then reads the findings once. Dependency-Track 4.14.6 sets that field at the end of every analysis, including the one a BOM upload starts, and sends `BOM_PROCESSED` before it (docs/23 DT1, from the sources). The two earlier signals are gone: `ProjectMetrics.lastOccurrence`, which moves only on periodic analysis, and two identical reads, which are also identical before the analysis starts. At the bound the findings are read and the result is "not settled". Still to verify against a running Dependency-Track (docs/23 DT7). The Dependency-Track sync itself is still not wired into the server (K5).
- **Found: NVD is not synced.** D76 lists an NVD API 2.0 parser; `enrich.LoadNVD` exists, but nothing in production calls it and `SyncAll` fetches KEV, EPSS and OSV only. What Rampart syncs is KEV, EPSS and OSV (D35); detection itself comes from the scanners and Dependency-Track (D39).
- **Tested:** `TestExportCSVDefusesFormulas`, `TestClientIPTrustsOnlyConfiguredProxies` (no proxy configured, behind the ingress, a forged leftmost entry, an untrusted peer), the settle tests rewritten for the verified signal (`TestSettleChecker_ImmediateSettle`, `_NeverSettles_Timeout`, `_SettlesWhenTheAnalysisEnds`).

Sources: OWASP, CSV Injection; RFC 7239; OCSF schema 1.3.0, Vulnerability Finding (https://schema.ocsf.io/1.3.0/classes/vulnerability_finding); Dependency-Track 4.14.6 sources (docs/23 §3); D35, D39, D46, D76.

## D85. How D70 part B was resolved, as the code does it (docs/23 C7)

D70 part B listed twelve redesigns; docs/21 marked them done without recording the choices here. Each item, as read in the code on 2026-11-16:

| # | Outcome | Where |
|---|---|---|
| B1 ticket table | `ticket` and `ticket_finding` (many to many); the ledger stays as "was it requested" | migration 28 |
| B2 look up before retry | before a retry, the tracker searches by the finding label (`FindIssueByLabel`) and records what it finds instead of creating a second issue | `connectors/tickets.go` |
| B3 ticketing policy | `spec.ticketing {onCritical, minBand, project, projects, maxPerHour}`; the resolver takes the connector with `onCritical: true`; the hourly cap is enforced per connector; due reservations are taken round-robin across tenants. **Not built:** the summary ticket for findings over the cap (they wait for the next hour) | `domain/connector.go`, `connectors/trackers.go`, `tickets.go` |
| B4 errors that will not heal | 400, 401, 403, 404 and 422 give up at once (`TrackerError`, `IsFatalTrackerError`); 408, 429 and 5xx retry | `domain/connector.go` |
| B5 not_affected request | a webhook mapped to `not_affected` creates a workflow request with its justification | docs/21 §2.4 |
| B6 accountId from /myself | built in D87: the Check reads `/rest/api/3/myself` and the operator stores `status.accountId`, which the inbound handler reads; the spec value stays as a fallback | `connectors/check_trackers.go` |
| B7 public endpoint limits | per address and connector (D73), moved to `/hooks` with the connector id (D78); a per-connector cap independent of address is not built | D73, D78 |
| B8 shared delivery cache | `webhook_delivery` table next to the in-memory cache | migration 28 |
| B9 Jira Data Center | **Jira Cloud only** (REST v3); the tracker's comment still names Data Center and should not | `connectors/trackers.go` |
| B10 project create metadata | built in D87: the Check reads the create metadata of the project and issue type; the tracker sends `priority` and `labels` only when accepted | `connectors/check_trackers.go`, `trackers.go` |
| B11 system role | the sweeper runs only with `database.systemUrl` and the server says so in the log when it is missing; no security-definer function was added | `targets/runner.go` |
| B12 the migration's blanket `skipped` | kept: only rows reserved before the outbox, with an empty result, were marked `skipped` | migration 27 |

D70 part C: closing and commenting on a ticket when its finding is fixed, and notifying on a reopened ticket, were built (docs/21 §2.3, §2.4); Jira webhook registration and its 30-day refresh are not.

Sources: the code paths in the table; D70; docs/21 §1, §2.

## D86. Detection comes from the tools; intelligence about what they report comes from feeds: OCSF 2007, the NVD sync and `ClusterFeedMirror`

**Two jobs, kept apart.** *Detection*, which package or code has which weakness, comes only from the scanners and from Dependency-Track (D39); Rampart has no matcher and never decides by itself that something is vulnerable. *Intelligence* about an identifier a tool already reported (is the CVE exploited, how likely is exploitation, which other ids name it, its CVSS and CWE) comes from public feeds into the global tables, written only by the system role from official sources (D19). Feeds never create a finding; they enrich one. This is the design of docs/00 §4 and docs/01 D2/D3, and D35 built KEV, EPSS and OSV. The two were found to be confused in conversation on 2026-11-16, so the line is written here.

**OCSF export is class 2007 (ADR 0003, docs/01 G4).** D76 wrote class 2001, deprecated; D84 left the class open. The design had already chosen 2007, Application Security Posture Finding. Built against the required attributes read from schema.ocsf.io 1.5.0: `activity_id` 1 (Create), `category_uid` 2, `class_uid` 2007, `type_uid` 200701, `severity_id` 1–5, `time`, `cloud{provider}` (stated as `unknown`: Rampart does not know where an application runs and does not guess), `finding_info{uid, title, desc, types, created_time, first_seen_time, last_seen_time}`, `metadata{version 1.5.0, product}`, and `application{uid}` with `vulnerabilities[]` (the CVE and each CWE) to satisfy "at least one of application, compliance, remediation, vulnerabilities". `status_id`: open 1, under investigation and affected 2, decided (accepted, not affected, out of scope, duplicate) 3, fixed 4. `TestOCSFExportIsClass2007WithRequiredAttributes` checks every required attribute.

**NVD is synced (docs/01 D3, D14).** D76 listed it as built; nothing called it (D84). Now `SyncAll` reads the NVD CVE API 2.0:
- paged by 2,000; the first sync reads every CVE, later syncs only what changed since the last success (`lastModStartDate`/`lastModEndDate`, cursor in `feed_state`), and a gap over 120 days (the API's limit) falls back to a full read;
- paced to NIST's limits: 6 s between requests without a key (5 per 30 s), 0.7 s with one (50 per 30 s); the key is a file (`feeds.nvdApiKeyFile`, sent as the `apiKey` header);
- writes, per CVE: the English description when none is stored, the CWEs, every CVSS metric as `{version, vector, score, source}`, and the best: NVD's **primary** score in the newest version (4.0, 3.1, 3.0), a secondary (CNA) score only when no version has a primary one (a bug found by the test: a secondary 4.0 had beaten a primary 3.1). KEV and EPSS columns are never touched;
- a page over 64 MiB is refused, not cut; on by default, `feeds.nvdDisabled` turns it off, `feeds.nvdUrl` points it at a mirror.
- **What it changes today:** CVSS and CWE on the vulnerability record. The stored risk score still uses severity, KEV and EPSS (D40); computing from the CVSS vector is P1 (docs/01 D4, D54).

**`ClusterFeedMirror` (docs/04; inside v1.0 by D29).** Feed endpoints were configuration-file settings only. Now they are a cluster-scoped resource, kept with the other cluster-wide configuration (`cluster_policy`, kind `feeds`, migration `00036_cluster_feed_mirror.sql`, schema version 36), reconciled by the operator with the policy reconciler and applied by `rampart apply` (one library, D3). The one named `default` is in force, else the first by name (the rule of D41). The sync reads it at the start of every round: each listed feed is read from its mirror; with `egress: deny`, a feed without a mirror is not read at all (air-gapped installs). Refused with the reason, not accepted and ignored (D41): a per-feed `schedule` (every feed runs every `feeds.interval`) and the `cwe` feed (not synced). A mirror change does not flag a re-score (it changes where feeds come from, not a score). CRD in both `crds` folders, operator RBAC in both places, `helm lint` clean.

**Why feeds are not plugins.** Plugins (docs/19) translate a tool's data into findings for one tenant. Feeds write the global tables every tenant reads; a plugin able to write them could change every tenant's severities and scores, which D19 exists to prevent. The feed code stays in the core; the resource decides where it reads from.

**Tested:** the OCSF test above; on PostgreSQL `TestFeeds_NVDSync` (full paged read, CWE and the primary 3.1 score chosen over a secondary 4.0, KEV and EPSS untouched, the API key sent, the second sync incremental) and `TestClusterFeedMirror_OnPostgreSQL` (default wins, a refused spec is never in force); `TestParseFeedMirrorSpec`, `TestApplyMirror` (mirror replaces URLs; deny skips the rest), `TestApply_ClusterFeedMirror`.

Sources: OCSF schema 1.5.0, class Application Security Posture Finding and the objects cloud, finding_info, metadata, application (https://schema.ocsf.io/1.5.0/classes/application_security_posture_finding); NIST, NVD CVE API 2.0 and its rate limits (https://nvd.nist.gov/developers/vulnerabilities, https://nvd.nist.gov/developers/start-here); ADR 0003; docs/00 §4, docs/01 D2–D4, G4; D19, D29, D35, D39, D40, D41.

## D87. The Jira and GitHub Checks call the tracker; the account and the accepted fields come from them (D70 B6, B10)

Two defects found while building B6 and B10:
- **Jira's Check did not call Jira.** `checkJira` validated the address against the SSRF policy and returned; the operator then wrote `Connected=True, AuthOK, "Connector verified successfully"` for credentials nothing had tried.
- **GitHub had no Check.** The switch had no GitHub case, so every GitHub connector answered "unsupported connector type for check" and showed `Connected=False`.

**Now:**
- **Jira:** (1) `GET /rest/api/3/myself` proves the credentials (401 or 403 fails the Check with that reason) and gives the `accountId` Rampart acts as; the operator stores it in `status.accountId`, which the inbound handler already reads to recognise Rampart's own changes (D70 B6; the spec's typed value stays as a fallback). (2) `GET /rest/api/3/issue/createmeta/{project}/issuetypes` must list the configured issue type (default `Bug`), or the Check fails with the reason. (3) `GET /rest/api/3/issue/createmeta/{project}/issuetypes/{id}` gives the fields that screen accepts; the operator stores them in `status.acceptedFields`, and the tracker sends `priority` and `labels` only when they are accepted (D70 B10), because Jira refuses the whole issue for one field its screen lacks. When the fields are unknown (no Check yet), everything is sent as before. A project whose screen lacks `labels` loses the lookup before a retry (D70 B2), which needs the label.
- **GitHub:** `GET /repos/{owner}/{repo}` with the token; the Check fails unless the repository is visible and `permissions.push` is true, because without push access GitHub creates the issue and silently drops labels and assignees (docs/20 §4).
- The checker's results travel in `domain.ConnectorCheckInfo` (`CheckDetailed`); `Check` keeps its signature.
- **Tested:** `TestJiraCheckLearnsAccountAndFields` (account and fields read; refused credentials and a missing issue type fail), `TestGitHubCheckNeedsPushAccess` (push, no push, an invisible repository), `TestJiraCreateSendsOnlyAcceptedFields`.

Sources: Atlassian, Jira Cloud REST API v3, "Get current user" and "Get create metadata issue types for a project" / "Get create field metadata for a project and issue type id" (https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/); GitHub REST API, "Get a repository" (permissions) and docs/20 §4; D70.

## D88. Every vulnerability database, free or licensed, as exploitation intelligence through `ClusterFeedMirror`

**The request (2026-11-16):** cover every vulnerability database, including paid ones. D86 already had KEV, EPSS, NVD and OSV. What was missing is the intelligence that separates a CVE someone is exploiting from one nobody is: exploitation reported outside CISA KEV, and whether public exploit code exists. That is what the market's paid feeds sell (VulnCheck, VulnDB/Flashpoint, Recorded Future, Mandiant). The design line of D86 still holds: these sources enrich a CVE a tool reported; none creates a finding (D39), and the code stays in the core because it writes global tables (D19).

**Sources built (optional; a block in the `ClusterFeedMirror` switches each on, `url` makes it a mirror, `tokenFile` is a mounted Secret):**

| Source | Licence | What it gives | How it is read |
|---|---|---|---|
| CISA Vulnrichment (`vulnrichment`) | CC0 | SSVC (stored in `vulnerability.ssvc`); Exploitation `active` means exploited, `poc` means public code; CISA's CVSS and CWEs where NVD has none | the repository archive, every `CVE-*.json`, the ADP container `CISA-ADP` |
| Exploit Database (`exploitdb`) | public (OffSec) | public exploit code: maturity `poc` | `files_exploits.csv`, CVE ids in `codes` |
| Metasploit (`metasploit`) | BSD | an `exploit` module: maturity `weaponized` (auxiliary modules do not count) | `db/modules_metadata_base.json` |
| ENISA EUVD (`euvd`) | public | exploited per ENISA; EUVD ids become aliases of the CVEs Rampart knows | `GET /api/vulnerabilities?exploited=true`, paged by 100, 1 s between pages |
| VulnCheck KEV (`vulncheckKev`) | community (free, token) or commercial | exploited (~80 % more than CISA KEV, per VulnCheck); an XDB exploit gives maturity `poc` | `GET /v3/backup/vulncheck-kev` (Bearer), signed link, archive SHA-256 checked, the token not sent to the storage host |
| Any licensed or in-house feed (`custom[]`) | the customer's licence | exploited and maturity, or full OSV advisories | format `intel-jsonl` (one `{"id","exploited","maturity","reportedAt","evidence"}` per line; a bad line refuses the whole file) or `osv-zip` |

**Why licensed feeds come in through a format, not built-in clients.** VulnDB, Recorded Future, Mandiant, Flashpoint and Snyk require a contract. Their terms restrict redistribution, and we cannot test their APIs without accounts. A client nobody can test is the "claimed but not wired" defect this review keeps finding. The customer who holds the licence exports or proxies the feed into `intel-jsonl` or OSV, the formats the free sources already prove. A custom feed cannot take a built-in feed's name, so licensed data never passes for CISA's or NIST's. The licensed data stays inside the installation; Rampart's exports carry findings, not feed records.

**Storage.** A new table, `vulnerability_exploitation (vulnerability_id, source, exploited, maturity none|poc|weaponized, reported_at, evidence_url)`, is added in migration `00037`, schema version 37, written only by the system role. There is no foreign key, because a source may name a CVE before NVD has it. Each sync **replaces** the source's rows in one transaction, because every source publishes its full list; a CVE a source withdraws therefore stops counting. Rows of a source switched off are deleted at the next round. A source that fails keeps its last good rows. With `egress: deny`, a source without its own `url` is off.

**Precedence.**
- CISA KEV stays in its own columns: `vuln.kev` is still only CISA's, and its due date alone caps SLAs (docs/06 §4).
- Exploitation is the OR over sources; maturity is the highest.
- For CVSS and CWE: NVD's primary score first (D86), then CISA ADP when NVD has nothing. The NVD write still replaces its own values on each sync.

**Risk (docs/06 §2).**
- The CEL environment gains `vuln.exploited`, `vuln.exploited_sources`, and `vuln.exploit_maturity`.
- Built-in factors:
  - `EXPLOITED_REPORTED` (`vuln.exploited && !vuln.kev`, +300, the KEV weight, because SSVC treats active exploitation the same whoever reports it, and KEV is not counted twice);
  - `EXPLOIT_WEAPONIZED` (+120, the "functional/weaponized" row docs/06 already had).
- A finding with no evidence scores exactly as before, so the built-in numbers do not move. A sync round re-scores through `OnSynced` (D28).

**Not built, and why.** These are left out with reasons, not silently:
- CVE List V5: Vulnrichment carries the CISA part we need.
- GitHub Advisory Database: already read through OSV.
- Nuclei templates: detection templates, not exploits.
- VulnCheck's paid indexes (NVD++ and others): through `custom`.

**Tested:**
- `TestParseSources`: each published format, auxiliary modules ignored, intel-jsonl refusals, the SSVC `active` decision, EUVD aliases.
- `TestParseFeedMirrorSpec_OptionalSources`: VulnCheck without a token, a relative or unclean token path, an unknown format, a custom feed named `nvd`, and duplicates are refused.
- `TestBuiltinExploitationFactors`: +420 for exploited and weaponized; KEV plus another source counts once.

Sources:
- CISA Vulnrichment (https://github.com/cisagov/vulnrichment).
- Exploit Database (https://gitlab.com/exploit-database/exploitdb).
- Metasploit Framework `db/modules_metadata_base.json`.
- ENISA EUVD API (https://euvd.enisa.europa.eu/apidoc, base https://euvdservices.enisa.europa.eu). The paths were read from a published OpenAPI description, because the page did not load; they are to be re-checked against ENISA in CI.
- VulnCheck docs, "VulnCheck KEV schema" and "Backup" (https://docs.vulncheck.com).
- VulnDB licensing (vuldb.com/kb/softwarelicense): commercial use requires a contract.
- docs/06 §2–3; D19, D28, D39, D86.

## D89. A vulnerability database can be added as a plugin: a container that fetches, and a format that Rampart loads

**Question (from the owner).** Can each vulnerability database be a plugin, its own container with its own code that fetches and updates, so that anyone can add a new one without changing Rampart?

**Decision: yes, with one boundary. A feed plugin fetches and translates. It never writes to the database.**

```
[feed plugin container]   fetches from its source (public API, licensed feed, in-house list), any language
        │  produces one file in a published format: intel-jsonl or osv-zip (D88)
        ▼
  serves it at a URL (pull)  — or —  posts it to the feed ingest endpoint (push, to build)
        ▼
[Rampart feed loader]      validates the whole file, refuses it on one bad record, writes as rampart_system (D19)
```

**Why the boundary.** The `vulnerability` and `vulnerability_exploitation` tables are global: every tenant's score and SLA read them. A plugin holding database credentials could, through a bug or a compromise, rewrite them for all tenants, and every plugin pod would carry a connection string. D19 keeps one writer for global tables. The contract between a plugin and Rampart is therefore a data format, not code, and not SQL.

**Why it is right.** It is how the established tools split the work:
- OpenCTI connectors are separate containers that talk to the platform's API, never to its database.
- Anchore splits vunnel, which fetches and normalises each provider into files, from grype-db, which builds the database.
- Dependency-Track and Trivy keep their built-in mirrors, which is why the core feeds below stay built in.

**How it differs from a connector (docs/19, docs/23 §6).** A connector is per tenant (namespaced, the tenant's own tracker or source). A feed is global intelligence, so a feed plugin is:
- registered in the cluster-scoped `ClusterFeedMirror`, by a platform administrator only, never by a tenant;
- named with the rule of D88: it cannot take a built-in feed's name, so a plugin's data never passes for CISA's or NIST's;
- detection-free: it only enriches what scanners and Dependency-Track already reported (D39, D86).

**What exists today.** The pull form already works: `ClusterFeedMirror.spec.custom[]` takes `{name, url, format, tokenFile}` (D88). Any container that serves `intel-jsonl` or `osv-zip` at a URL inside the cluster is a feed plugin now.

**What stays built in, and why.** KEV, EPSS, OSV and NVD. The risk score and the KEV due date depend on them, they must work on a fresh install with nothing extra deployed, and they are mirrored for air-gapped installs. The optional sources of D88 (Vulnrichment, ExploitDB, Metasploit, EUVD, VulnCheck KEV) stay in-process for now: they are written and tested, and moving them out is churn with no gain for users. New sources from here on are added as plugins.

**To build (tracked under the plugin design, docs/23 §6):**
1. Push mode: `POST /api/v1/feeds/{name}` with a per-plugin token that can reach that one feed and nothing else. Same validation as pull.
2. A Helm template per plugin: a CronJob or Deployment with its own secret, no database credentials, egress limited to its source.
3. A contract document with the two formats and a small reference plugin, so a licensed-feed customer can write one without touching Rampart.
4. Optional integrity: a `sha256` alongside the file, or a cosign signature checked against a key named in the mirror spec.

Refs: D19, D39, D86, D88; docs/19; docs/23 §6.

## D90. Finding groups belong to an application, and a group or a correlation group gets one ticket (docs/23 C8)

**Found.** The group endpoints (D76) checked nothing but a login. Anyone in the tenant could create or delete any group and put any application's findings in it. A group had no application, so docs 03, 07 and 12, which give it one, could not be applied. "One ticket per correlation group" (D24) and `POST /groups/{id}/ticket` (doc 11) did not exist.

**Decision.**
- **Scope.** `finding_group.application_id` (migration 38). Null means a tenant-wide group, which only an admin may create or delete. Otherwise:

  | Action | Needs |
  |---|---|
  | read | viewer |
  | create, delete | maintainer on the group's application |
  | add a finding | triager on the finding's application; the finding must exist and belong to the group's application (422 otherwise) |
  | remove a finding | triager on its application; a finding that no longer exists needs the group's own role |
  | `POST /groups/{id}/ticket` | maintainer on every application in the group |

  One call adds or removes at most 500 findings.
- **Group ticket.** `POST /groups/{id}/ticket` answers 202. It reserves the ticket on the group row (`ticket_status = reserved`); a second request answers 409 until the first fails. The ticket sweeper opens it: the tracker is never called inside a request (D70).
  - The issue's ID is the group's, so the retry's label search (`FindingLabel`) finds the group's issue, never a member's own.
  - Severity is the worst member's; the body lists the members, worst first, at most 50.
  - On success the ticket is linked to every member in `ticket_finding`, and each member's timeline gets a `ticket_created` event.
  - Retries, backoff, giving up, and treating a 4xx as fatal are the same as for single tickets. A group with no open finding, or a tenant with no tracker, fails at once with the reason stored on the group (`ticket.error`) and may be requested again.
- **One ticket per correlation group.** Before opening a ticket for a reserved finding, the sweeper asks for an open ticket on the same tracker. That ticket must already track another finding with the same `correlation_key` in the same application. If there is one, the finding is linked to it (event status `linked_correlated`). Two tools reporting the same issue therefore make one ticket. The key is read by the store query, because `GetFinding` does not load it.

**Why maintainer for the ticket, and on every application.** Opening an external ticket speaks for the team that owns the code (doc 07 gives groups to the scope's maintainer). A group that spans applications must not let the owner of one open a ticket on another team's behalf.

**Limits, stated:**
- A webhook about a group ticket carries the group's label, so `ticketBelongs` ignores it (`ignored_unknown_ticket`). Closing a group's issue in the tracker does not change its members; members still close one by one, by a rescan or by triage.
- The GitHub issue body links to `/findings/{id}` with the group's id. The group page is the right target; this is to correct when the tracker contract carries a link (docs/23 §6.2).
- Reads are not narrowed per application, as for findings (D48 "not built: restricting reads").

**Tested:**
- `TestFindingGroups_ScopedByApplication`: every row of the table, the 409, and an empty group.
- `TestGroupAndCorrelationTickets_OnPostgreSQL`:
  - two correlated findings make one tracker call, and both are linked;
  - a group makes one call and both members are linked;
  - the application role cannot read the outbox across tenants;
  - a done ticket is not opened again.

Refs: docs 03, 07, 11, 12; D24, D48, D70, D76; docs/23 C8.

## D91. Live updates: one stream, fed by triggers, fanned out by a poller on each replica (docs/23 S1)

**Found.** `GET /api/v1/events` (D76) sent a `connected` message and heartbeats, and nothing else; no code produced an event. Docs 11 and 13 name `GET /stream?topics=`. Nothing filtered by scope, capped streams, or resumed after a drop.

**Decision.**
- **One path:** `GET /api/v1/stream?topics=ingests,findings,operations` (all topics when omitted; an unknown topic is 400). `/api/v1/events` is removed, and the UI moved with it.
- **Producer: statement-level triggers write `live_event`** (migration 39):
  - `finding` insert or update → topic `findings`, with the application;
  - `ingest_run` insert or update → `ingests`, with the application;
  - `held_close`, `risk_acceptance` and `finding_group` changes, and a new `notification` → `operations`.

  A trigger writes at most one row per (tenant, topic, application) per transaction: a merge that upserts 100k findings one statement at a time writes one row per application. Rows are coalesced only within the writer's own transaction (`xact = pg_current_xact_id()`). Coalescing with another transaction's row would hide a change committed after the client had refetched for that row.

  **Why triggers.** Every writer is covered, including ones added later, VEX imports, sweepers and the rescore after a feed sync. No handler has to remember to publish.
- **Fan-out: each replica polls once for all its streams** (`LiveHub`, every 2 s, as the system role).
  - **Why not LISTEN/NOTIFY.** It needs a direct connection (D4) and does not pass through PgBouncer in transaction mode. A poll costs one indexed query per replica every 2 s, whatever the number of streams.
  - **Out-of-order commits.** Ids come from a sequence, so a row can commit below one already seen. The hub's cursor advances only over a run with no hole, and rows above a hole are remembered so they are not delivered twice. A hole still open after 2 minutes is taken as a rolled-back transaction and skipped.
  - Rows older than 1 hour are pruned.
- **What a stream sends:** one message per (topic, application) per poll, carrying the topic and application id and no data. The client refetches with its own permissions, so a message cannot leak what the caller may not read.
  - Rows of other tenants never reach the stream.
  - Rows for an application the caller's scope does not reach are dropped (`scope.allows`, D48). Today every member reads every application, so this is the hook for when reads are narrowed.
- **Resuming.**
  - The SSE id is `<row id>.<unix time>`.
  - On reconnect, `Last-Event-ID` (or `last_event_id` in the query, for a client reconnecting by hand) replays the tenant's rows after it, under row-level security.
  - An id older than the retention, or a replay of 1000 rows or more, gets `event: reset`: the client refetches everything instead of trusting a gap.
  - A stream that falls 64 polls behind also gets `reset`.
- **Limits.**
  - At most 5 streams per user per replica (429 with `Retry-After`).
  - Every write has a 10 s deadline through `http.ResponseController`. This also lifts any server `WriteTimeout` for the stream, so a long stream is not cut. A stuck client is dropped.
  - A stream ends after 30 minutes with `event: reconnect`, so a revoked session or token stops receiving at the next reconnect.
  - A heartbeat comment is sent every 15 s.
- **Without the system role** no hub runs and `/stream` answers 503 with `Retry-After`. The UI then polls every 30 s (docs/13 §3) and stops polling when the stream opens.

**Limits, stated:**
- The per-user cap is per replica, not global. Five streams on each of N replicas is bounded by N, and rate limiting covers opening them.
- `live_event` RLS is enabled but not forced, so a migration run by the owner that touches findings does not fail on the trigger. The application and system roles are bound as everywhere.

**Tested:**
- `TestLiveStream`: 503 without a hub; the old path is gone; unknown topic; another tenant's rows and an unsubscribed topic not sent; two rows coalesced into one message with the newest id; an expired `Last-Event-ID` gets `reset`; the sixth stream gets 429.
- `TestLiveHubOutOfOrderIDs`: ids 1, 3, then 2 are each delivered once; a hole is skipped after the wait.
- `TestLiveEvents_OnPostgreSQL`: 50 findings in one transaction write one row; a tenant replays only its own rows; pruning.
- Vitest `useLiveEvents.test.ts`: the path, and what each topic invalidates.

Refs: docs 11, 13 §3; D4, D48, D76; docs/23 S1.

## D92. Dependency-Track runs in the server: River jobs, a schedule, the webhook, one asset key, decisions as requests (docs/23 K5, K6, DT1–DT6)

**Found.** Nothing outside `internal/upstream/dependencytrack` used the sync or the webhook (K5). In detail:
- The webhook was never mounted.
- `LookupScanSource` ran with no tenant, so row-level security hid every row.
- The `ScanSource` could not name a connector.
- The syncer's `MergeEngine` interface did not match `ingest.Engine`, so it could not have been wired as written.
- A sync wrote occurrences under a run id that had no `ingest_run` row, which the foreign key refuses.
- Syncs were bare goroutines.
- The asset key was `dtrack://<sourceID>/<projectUUID>` (DT3).
- DT's analysis on a finding was dropped.
- A hand mapping was overwritten by the next sync.

**Decision.**
- **Configuration (doc 10 §8).** `ScanSource.spec` gains `connector`, `schedule` and `dependencyTrack` (migration 40: `scan_source.connector`, `dtrack_spec`, `schedule_seconds`).
  - The operator and `rampart apply` share one check (`domain.DTrackSourceInput.Check`).
  - The block is decoded strictly. The doc 10 §8 fields this version does not build are refused **by name, with the reason**: `policyViolations`, `sbom`, `manage`, `allowedCIDRs`, `authority`, `sbomForwarding`, `initialSync`, `closeOnInactive`, and triage modes `export` and `bidirectional`. A configuration therefore never claims what the server does not do.
  - `schedule` is a duration or `*/N * * * *`: default 30 min, at least 5 min. Other cron forms are refused rather than misread.
  - The CRD keeps the block as `x-kubernetes-preserve-unknown-fields`, because the operator validates it and its errors name the field.
- **Jobs (K6, ADR 0002, D25).** A sync is a `dtrack_sync` job on the `dtrack-sync` River queue: 4 workers, 5 attempts, 15 min timeout. It survives restarts, its number is bounded, and it takes its turn.
  - The `dtrack_sync` debounce row lets one sync of a project run at a time and turns a burst of events into one trailing job. River is not asked for uniqueness, because its uniqueness covers running jobs and would drop that trailing job.
  - A row still `syncing` an hour after its last touch (a worker that died) is taken as idle.
- **Schedule.** Every minute, one replica (advisory lock) enqueues the portfolio sync of each source whose schedule has passed. This is v1, not a fallback, because DT sends nothing when an analysis ends (DT1). The portfolio sync records every project with its mapping and enqueues the mapped ones; the debounce keeps one job per project.
- **Webhook.**
  - `POST /hooks/dependency-track/{scanSourceId}` is on the gateway like D78's hooks. It answers only when the source has `webhook.enabled`.
  - The source is found through the `webhook_lookup` policy on `scan_source`: `app.webhook_scan_source_id` is set for the one transaction, as D78 does for connectors.
  - The bearer secret is the source's `secretRef` with key `webhook`, compared in constant time.
  - A body over 512 KiB is refused, not cut.
  - The webhook only enqueues ("thin event, fat fetch").
- **The client** is built per job from the Connector: URL, and the API key from `connector:<name>:apiKey`. It goes through the SSRF-safe client scoped to the tenant and the type (D77).
- **Asset key (DT3, D10):** `dtrack://<connector>/<project name>`.
  - With `versions: latest` (default) only the project version DT marks `isLatest` is synced, on track `main`. A DT older than 4.12 does not send `isLatest`, so its projects are recorded as filtered out with that reason: use `versions: all`, where each version is a track.
  - Filters: `onlyActive`, `tags`, `nameRegex` and `classifiers`. A filtered project is recorded with the reason, not silently skipped.
- **Settle (DT1).**
  - A job waits up to 2 min for `lastVulnerabilityAnalysis >= lastBomImport`.
  - If not settled, it reschedules itself in 5 min instead of holding a worker.
  - Once the import is 30 min old, it reads anyway and the run ends `completed_with_errors` / `analysis_unsettled`. The mass-close guard always applies.
- **Reading findings (DT2).** The list is read once, with a cap that fails rather than cuts (D84). The count parsed must equal `X-Total-Count`, and a record that does not parse fails the run. Otherwise the run fails before anything is merged or closed (`ErrCountMismatch`).
- **A sync is an ingest run.** It creates `ingest_run` (`scanner_family dependency-track`, format `dependency-track/api`), merges with the scorer, and closes with the mass-close guard. A held close becomes a `held_close` row as for uploads (D22). The run appears on the Runs page.
- **Mapping.**
  - The seven rules of doc 10 §3 come from the block.
  - A project mapped by hand (`POST /sources/{id}/map`) keeps that mapping across syncs: rule 3 reads it and the upsert never overwrites it.
  - Rule 4 matches an asset whose key is the project's purl.
- **Decisions (DT5).** With `triageSync.mode: import` (default), DT's analysis on a finding is stored in `dtrack_decision`.
  - It is written to the finding's timeline (`upstream_decision`) once, when it first appears or changes.
  - By default it is a **request**: listed as pending at `GET /sources/{id}/decisions`, and applied only when a person decides the finding.
  - With `trustUpstreamDecisions: true` it is applied as a triage decision by `dependency-track:<connector>`. The exception is `risk_accepted`, which needs an owner and an expiry (docs/01 C5) and so always stays a request.
  - `mode: off` ignores DT's analysis.
- **API (DT6).**
  - `GET /sources`: Dependency-Track sources with real state, namely last portfolio sync and error, project, unmapped and pending-decision counts, and the last project error.
  - `GET /sources/{id}/unmapped`.
  - `POST /sources/{id}/map {project_uuid, application_id}`: needs maintainer on the application; only that source's unmapped projects; enqueues a sync of the project.
  - `GET /sources/{id}/decisions`.
  - The `/api/v1/dtrack/...` routes are removed.
- **Gate (DT4, option b).** In this version the gate does not wait for Dependency-Track. `expect: [dependency-track]` answers with that reason instead of waiting: a DT sync run is started by DT's schedule or webhook, not by the build, and carries no commit. Flow A (Rampart uploads the BOM and holds DT's token) is what can tie a sync to a build; it is Phase 5.

**Still to test against a running DT** (DT7, CI with testcontainers): that `lastVulnerabilityAnalysis` moves after an upload with a read-only key, the `BOM_PROCESSED` field names, whether project paging starts at 0 or 1, and DT 5.x.

**Tested:**
- `TestParseDTrackSourceSpec`: what is accepted; every not-built field refused by name; schedules.
- `TestSyncer_SyncProject_MappedAndUnmapped`:
  - the DT3 key;
  - an older version filtered out;
  - a short read against `X-Total-Count` merges and closes nothing;
  - the close step runs with the guard.
- Settle tests: not settled reads nothing; `ReadAnyway`.
- `TestDue`: the schedule.
- Webhook tests: enqueue, not goroutines.
- `TestDTrackAPI_UnmappedProjectsAndMapping`: the source routes; viewer refused; another source's project 404.
- `TestDTrackWiring_OnPostgreSQL`:
  - the webhook lookup with no tenant;
  - the block round-trips;
  - the system role lists all sources;
  - a hand mapping survives an upsert;
  - a decision is new once, and new again when changed;
  - debounce, and a sync stuck for two hours is taken as idle.

Refs: docs 10 §3, §5, §8, §9; D10, D22, D23, D25, D74, D77, D78, D84; docs/23 K5, K6, DT1–DT7.

## D93. Charts for applications: what the market shows, drawn in the workbench's own rules

**Asked.** Charts for the applications that show the vulnerabilities clearly. The owner asked that they follow the best charts in the market.

**What the market converges on** (searched 2026-11-16; vendor docs and guides). Invicti, Checkmarx, Mend, JupiterOne, GitLab's dashboard epic, Apiiro, and the AppSec metrics guides all show the same charts:
1. open findings over time, by severity;
2. time to fix by severity (Metabase recommends the median);
3. SLA compliance by band;
4. velocity: new against fixed, to show whether fixing keeps up (GitLab);
5. the age of what is open, with past 90 days as its own problem;
6. the riskiest applications.

They also agree that trends say more than snapshots.

**Decision.** The application page gains numbers 1, 4 and 5. Numbers 2 and 3 become bars, and number 6 is the list's own bar. The data comes from `GET /api/v1/applications/{id}/trend?days=30|90|180`, which returns, per day: open findings by band, new, and fixed, plus the age buckets of what is open. `AppBandTrend` and `AppAging` compute these from the finding table.

| Chart | Form, and why |
|---|---|
| Open findings over time | **Small multiples**, one panel per band, sharing the day axis and the hover. The validator (dataviz skill) fails the band colours as a categorical set: critical and high are ΔE 9.5 apart in dark mode, and low reads grey. Four coloured lines on one plot would ask the reader to tell them apart by colour. A panel names its band with its shape, its count today, the change over the period and its peak. Pointing at a day in any panel reads that day for all four in one line; arrow keys do the same. The numbers are in a table under the chart. |
| Arriving and fixed | Weekly bars: new above the line in ink, fixed below in the resolved teal. Position carries the meaning, not colour. The caption says whether fixing keeps up ("23 more arrived than were fixed"). |
| How long open findings have waited | Four bars: under 30, 30–90, 90–180 and over 180 days. The two past 90 are set darker, because they are the backlog, not the flow. |
| Time to fix | One bar per band on a shared scale, named with its shape and its value in words. |
| Deadlines | One bar: resolved in time, resolved late, still open past the deadline. These are not risk bands, so they are ink from light to dark, each part named below. |
| Applications list | The "open findings" cell is a bar of the bands, worst first, on **one scale for every row** so the rows compare. Segments are separated by a 2 px gap, and the counts are written under the bar. |

**Rules kept** (docs/13 §6):
- colour only for risk;
- no tiles, cards or pills;
- sentence case;
- every chart's numbers readable as text;
- light and dark checked in a browser (Chromium screenshots against the dev mock).

The hover marker is drawn in HTML, so the stretched plot does not squash it.

**Limit, stated.** A finding is counted in the band it has today. Bands are not stored per day, so a re-scored finding moves its whole history. The chart says so under it. The `trend_daily` read model of docs/12 would keep each day's band.

**Tested:**
- `TestAppBandTrend_OnPostgreSQL`: counts by band per day; a fixed finding leaves the count; new per day; age buckets.
- Vitest `overview.test.tsx`: the page shows the panels' sentence, the velocity caption, the age rows and the named parts of the bars, with axe clean.

Sources:
- appsecsanta.com/aspm-tools/appsec-metrics-guide
- invicti.com/blog/web-security/appsec-kpis-that-matter
- docs.invicti.com/appsec/dashboard
- gitlab.com/groups/gitlab-org/-/epics/16517
- docs.checkmarx.com (Vulnerabilities Dashboard)
- docs.jupiterone.io/features/vulnerability-management/executive-dashboard
- metabase.com/dashboards/vulnerability-management
- apiiro.com/blog/5-top-appsec-metrics-new-dashboards

## D94. Plugins, slice one: a notifier installed as data, and feed plugins that push (docs/23 §6, D89)

**Asked.** Any tool should be addable as a plugin, and vulnerability databases should be plugins too (D89). The full design (docs/23 §6.8) has seven steps. This decision builds the slice that passes its acceptance test, and the feed half of D89. The remaining steps are listed with what replaces them for now.

**Built:**
1. **`IntegrationPackage`, namespaced, data only** (CRD; migration 41 `integration_package`; operator reconciler; `rampart apply`).
   - `runtime: declarative`, `kind: notifier`: a templated HTTP request, the secrets it needs, the hosts it may reach, and a CEL `expect`. The engine is `internal/integrations/declarative`.
   - **Refused, by name:** `tracker`, `source` and `parser` kinds (their engines are not built), and `wasm` and `grpc` runtimes (code is tier 2, and never allowed in a tenant namespace).
   - A package that does not validate is stored with its error and never used, so the UI can say why.
2. **Templates are logic-free.** `{{ message.x }}`, `{{ config.x }}` and `{{ secrets.x }}`, with no filters or loops (docs/19 §6). A field that does not exist is refused at apply time. JSON bodies are rendered by walking the decoded document and re-encoding it, so a value cannot escape its string. Message text is refused in headers.
3. **Egress is enforced twice.** The rendered URL must be https, and its host must be in `egress` (names or `*.domain`; IP addresses refused). The request then goes through the SSRF-safe client scoped to the tenant (D77). A declared host that resolves to a private address is still refused, and so are cross-host redirects (docs/19 §11). `localhost` is accepted as a name: reaching it still needs the platform's loopback allowance.
4. **`Connector.spec.type: plugin`** with `plugin: {name, config, secrets}`.
   - The operator checks the package exists and validates, and checks `config` against its `configSchema`.
   - It requires every declared secret and refuses undeclared ones, and syncs each as `connector:<name>:<secret>`. The secret names come from the descriptor, not from per-type code (§6.4).
   - `Connected` stays `Unknown`/`NotProbed`: a declarative notifier has no check request, and claiming "connected" would be false.
   - The router builds the notifier from the package, so routing rules apply as for built-ins.
5. **Catalogue and UI.**
   - The connector catalogue gains "Installed package", with a complete, applied-in-test example.
   - `GET /api/v1/integration-packages` lists packages with what they may reach, what they need, which connectors use them, and their error.
   - The Integrations page shows them. A plugin connector reads "Package <name>".
   - The connector status pills were replaced by plain words (docs/13 §6).
6. **Feed plugins push** (D89).
   - A `ClusterFeedMirror` custom feed takes `pushTokenFile` instead of `url` (intel-jsonl only; an OSV zip is pulled).
   - `POST /api/v1/feeds/{name}` compares the bearer with that file in constant time. It gives one answer for an unknown feed and a wrong token. It parses the whole file and refuses it whole on one bad line (422), and stages it in `feed_push` (migration 42, max 64 MiB).
   - The feed syncer loads it as the system role on its next round. The API never writes the intelligence tables (D19); a test proves the application role cannot.
   - The Helm chart's `feeds.plugins[]` creates one CronJob per plugin. The CronJob has no database credentials and no service account token, and gets only `RAMPART_FEED_PUSH_URL` and `RAMPART_FEED_TOKEN`. The chart mounts the token into Rampart at `/var/run/rampart/feeds/<name>/token` and, with network policies on, allows the plugin's pods to the API port.
7. **The contract** for authors is docs/25 (both formats, every field, the answers, what is not built).

**Not built in this slice (docs/23 §6.8), and what stands in for them:**
- Step 1, one contract per kind: the built-in notifiers still implement `connectors.Notifier`. A plugin notifier implements the same interface, so the router has one dispatch path.
- Step 3, notifications as River jobs: delivery is still inline (K4).
- `/hooks/{integration}/{id}` for packages.
- Declarative trackers and sources.
- `GET /api/v1/integrations` across all kinds: parsers stay at `GET /api/v1/parsers`.
- Tier 2 (gRPC, WebAssembly, OCI packages with cosign).

**Why a tenant may install a package.** It is data: it can reach only the hosts it declares and those the tenant's allowlist permits. It reads only its own connector's secrets. It cannot run code. This is the tier docs/19 §2 gives to tenant administrators.

**Tested:**
- `TestDeclarativeNotifier`: doc 19's Google Chat example sends; a title with quotes and a brace is escaped; a 500 fails `expect`; a secret pointing at an undeclared host sends nothing; a missing secret is refused.
- `TestParseRefusals`: twelve refusals, by name; config schema checks.
- `TestIntegrationPackageAndPluginConnector`: install; a code runtime refused; a connector `Ready` with its secret synced under its name; `UnknownIntegration`, `PackageInvalid`, and a missing declared secret.
- **`TestPluginNotifierDeliversThroughThePackage`, the acceptance test of §6.8:** a message reaches a fake receiver through a package with no tool-specific code; an undeclared host gets nothing.
- `TestListIntegrationPackages`: the API, with tenant isolation.
- `TestFeedPush`: token, unknown feed, a bad line refused whole, a good file staged.
- `TestFeedPush_OnPostgreSQL`: the application role stages, the syncer loads; the application role cannot write the exploitation table.
- Catalogue examples apply.
- Vitest: the Integrations page lists packages, their reach, their user, and an error.
- `helm template` (offline) renders with and without a plugin; `helm lint` passes.

Refs: docs/19 §2, §6, §7, §11; docs/23 §6; docs/25; D19, D39, D77, D82, D88, D89.

## D95. SBOM export: CycloneDX 1.6 and SPDX 2.3, per asset and merged per application (docs/09 Phase 3.6)

Rampart stores the SBOM each upload carries (D15); until now it could show one and draw its graph, but not give it back as a document another tool reads. Customers hand SBOMs to auditors, to their own customers (the EU Cyber Resilience Act asks a manufacturer to keep one per product) and to tools such as Dependency-Track.

- `GET /api/v1/assets/{id}/sbom?format=cyclonedx|spdx` returns the asset's latest SBOM as a standard document. Without `format` the endpoint keeps its JSON view, so the UI is unchanged.
- `GET /api/v1/applications/{id}/sbom?format=…` merges the latest SBOM of every asset of the application into one document whose subject is the application. Components are merged by purl (else name and version), so a library used by two services appears once and names both assets it came from. It needs PostgreSQL, and answers 404 when no asset has an SBOM yet.
- **CycloneDX 1.6 JSON** (`application/vnd.cyclonedx+json; version=1.6`) and **SPDX 2.3 JSON** (`application/spdx+json`). Both are the versions the OWASP and Linux Foundation tools read today; SPDX 3.0 is not yet read by most of them.
- The SPDX `documentNamespace` is unique per export under `https://spdx.rampart.aspm.dev/`; SPDX 2.3 §6.5 asks only that it be unique, not fetchable.
- The download is an attachment named after the application (or `asset-<id>`), and needs the viewer role, as the SBOM view does. The application route used to read the application id as an asset id and found nothing; it now does what doc 11 says.
- Not built: VEX inside the CycloneDX export (VEX is its own endpoint, D47), signing the document.

Code: `internal/sbomexport`, `internal/query/sbom_export.go`.

Sources: CycloneDX 1.6 specification; SPDX 2.3 specification §6; EU Cyber Resilience Act Annex I part II.

## D96. The tracker, notifier and source contracts are removed; only the parser contract stays (docs/23 C6, K1, K2)

D75 defined one contract per integration kind (docs/19 §3) and said the built-in connectors were adapted to them. They never were: the real trackers implement `domain.Tracker`, the notifiers `connectors.Notifier`, and Dependency-Track is its own syncer (D92). The only implementations of the contracts were placeholder adapters, which D82 deleted. After that the three contracts had no implementation and no caller; only their own test used them.

**Decision.** Remove `SourceContract`, `TrackerContract`, `NotifierContract`, their types, their registry functions, and the unused canonical documents in `internal/domain/canonical.go`. The registry holds parsers only. The working list of what was removed is docs/26.

**Why not migrate the connectors onto them instead (docs/23 §6.2).** A shared contract earns its keep when a second implementation needs the same shape. Today:
- the only second notifier is the declarative package (D94), and it already plugs into `connectors.Notifier`;
- there is one tracker family (Jira, GitHub) behind one interface already;
- there is one source.

Migrating would rewrite working code to fit an interface nothing else uses. The contracts for code plugins (gRPC, WebAssembly, docs/19 §7) are written when that tier is built, from the code that exists then.

**Kept:** `ParserContract`, the parser registry and the conformance kit: the ingest gateway, the processor and parser packages (D98) use them.

## D97. Notifications are one River job per connector and message (docs/23 K4)

**Before.** The ingest worker called the router, which sent to every connector and waited. A slow chat service held the ingest worker, and a failed send was logged and lost. When the new findings could not be read back, the processor made up stand-in findings with random ids, whose links led nowhere.

**Now.**
- The router decides as before: routing rules, the digest above 20 findings (D25), skipping connectors that are not ready. It then queues one `notify_delivery` job per (connector, message) on the `notify` queue instead of sending.
- The job carries the tenant, the connector's name and the message. It carries no secret: the worker loads the connector and resolves its secrets when it sends, so a rotated secret is used.
- A failed send is retried by River, 8 attempts in all as for tickets (D70 A6). A job that runs out stays in River's table as discarded, with its last error.
- A connector deleted since the message was queued ends the job without a retry.
- Without PostgreSQL (the in-memory mode) the router sends inline, as before.
- The stand-in findings are gone: if the findings cannot be read, nothing is sent and the run logs why.
- The enrich, policy and notify job kinds, which had no handler and no caller, are removed.

**Not done:** the jobs are inserted after the merge commits, not inside its transaction. A crash between the two loses that run's notifications; it no longer loses them on every failed send. Inserting in the merge transaction needs the merge to return the routed messages, a larger change to the engine.

Code: `internal/jobs/notify.go`, `internal/connectors/router.go` (`SetDeliveryQueue`, `Deliver`), `internal/targets/runner.go`.

Sources: ADR 0002 (outbox); D25; D70 A6; River's retry policy.

## D98. A parser installed as data; GitLab and Generic JSON parsers (docs/19 §4, docs/09 Phase 3.5)

**Parser packages.** An `IntegrationPackage` with `kind: parser` and `runtime: mapping` describes a report format: how to recognise it, where its records are, and a CEL expression for each field (docs/19 §4). It needs no release, which was the point of the mapping engine D75 built and never connected.
- The package is checked when it is applied, as a notifier package is: the fields are decoded strictly (a misspelled field is refused, not ignored), every CEL expression is compiled, `ruleId` and `title` are required, and so is a way to detect the format.
- A package belongs to its tenant. It parses only that tenant's uploads, chosen by name (`--format pip-audit`) or by detection over the first 64 KiB, in competition with the built-in parsers.
- A built-in parser owns its name and wins a tie, so a package cannot take over a format Rampart already reads.
- Each record runs under the engine's limits: a CEL cost limit per expression, a maximum record count and depth. A bad record is reported as an unreadable record (D51), not a failed run.
- A `Connector` of type `plugin` that names a parser package is refused: a parser is used by uploads, not by a connector.
- The Integrations page lists parser packages with the notifiers.

**GitLab security reports.** One parser reads GitLab's five report types (SAST, secret detection, dependency scanning, container scanning, DAST), schema v14 and v15. Each type is its own scanner family (`gitlab-sast`, …): the close step works per family, and one family would let a SAST upload close the dependency findings of the same pipeline. Secrets are hashed and redacted from the stored record, and authorization and cookie headers are redacted from DAST evidence.

**Generic JSON.** A documented format for tools with no parser, a superset of DefectDojo's Generic Findings Import, so a DefectDojo user's existing exports load unchanged. It is detected only with low confidence unless the file carries `"format": "rampart-generic/v1"`, so it never takes a report another parser reads. The format is specified in `internal/parsers/genericjson`.

The format hint `generic` names it, as docs/04 does.

**Declarative trackers and sources move to Phase 4.** A tracker is not one request: it creates, finds by label, comments, closes, and takes a webhook back, with state between them (D70). A source pages through projects with a cursor and settles (D92). One templated request, which is what a declarative notifier is, describes neither, and an engine that does would be a small programming language. There is also no second tracker or source asking for it yet (D96's rule). Until then a new tracker is built in Go, and a tool that only needs to be told about findings uses a notifier package or the webhook connector.

Sources: docs/19 §4; GitLab security report schemas v15 (gitlab-org/security-products/security-report-schemas); DefectDojo Generic Findings Import documentation.

## D99. Housekeeping for the tables nothing cleaned (docs/23 R1)

Each retention sweep, under its advisory lock and as `rampart_system`, also removes:
- federation token ids (`federation_jti`) and inbound webhook delivery ids (`webhook_delivery`) past their expiry: they exist only to refuse a replay inside that window;
- hourly quota windows (`quota_usage`) older than 48 hours: the limiter reads only the current hour;
- held closes decided more than 90 days ago.

It runs even when retention is off: these rows are bookkeeping, not tenant data a policy keeps. The live events (D91) are pruned by their own poller; `feed_push` and `dtrack_sync` hold one row per feed or project and do not grow; River removes its own finished jobs.

Code: `internal/store/housekeeping.go`, `internal/retention`.

## D100. Outbound webhooks are signed the Standard Webhooks way; `sonarqube` is no longer a connector type (docs/23 C9, C10)

**Signature.** Docs 04 and 11 named two different headers, and the signature covered only the body. A webhook connector now sends:
- `webhook-id`: the message id, the same on every retry, so a receiver can drop a duplicate;
- `webhook-timestamp`: Unix seconds;
- `webhook-signature`: `v1,` + base64 of HMAC-SHA256 over `id.timestamp.body` with the connector's secret.

This is the Standard Webhooks specification, which Svix, Zapier and others verify with ready libraries. A receiver refuses a timestamp more than five minutes old. The old `X-Rampart-Signature-256` and `X-Rampart-Timestamp` headers are no longer sent; no release shipped them. A cross-host redirect of a signed request is refused, as for any credential.

**`sonarqube`.** It was a connector type with no implementation, refused at validation, and the CRD's enum did not allow it. docs/20 §9.3 removed unbuilt types; this one was left behind. It is removed. GitLab, Azure Boards and ServiceNow stay as named refusals: they are planned trackers, and their refusal says so.

Sources: Standard Webhooks specification (standardwebhooks.com, v1).

## D101. Scan coverage on the application page, by kind of testing, instead of a radar

ASPM products often draw an application's testing coverage as a radar: one axis per kind of testing (code, dependencies, secrets, infrastructure as code, images, running application, cloud). The question it answers is a good one: which kinds of testing does this application have, which is it missing, and what did each leave open. The radar answers it badly:
- its shape depends on the order of the axes, so the same data looks different when two axes swap;
- its area grows with the square of a value, so a doubling looks four times as large;
- values cannot be read off it, and two radars side by side cannot be compared.

**Decision.** The application page draws the radar, held to the rules that make it readable, and puts the exact table under it.
- **The radar.** The spokes are always in the table's order, so the shape of one application compares with another's. The distance from the centre is the number of open findings, on a linear scale with its rings numbered; the area is never the measure. The line is neutral ink, because colour is for risk (docs/13 §6). A kind never scanned is a dashed spoke labelled "not scanned", not a point at zero. Every spoke carries its name and its count, and each point names itself on hover.
- **The table** under it is the exact reading: one row per kind of testing, always in the same order (SAST, SCA, secrets, IaC, container images, DAST, cloud and cluster), then any other category something produced.
- **Scanned by** names the scanner families and the last completed scan. A kind with no scan reads "Not scanned", in words: a gap is not a clean result.
- A scan older than 30 days reads "stale".
- **Open findings** is the risk mix bar of the applications list (D93), on one scale shared by every row, with the counts in words beside it. Colour is only the risk of the open findings (docs/13 §6).
- A sentence above the table says how many kinds ran and names the missing and stale ones, so the table need not be read to learn the gaps.
- The per-asset, per-scanner table that was the old "Coverage" section stays, folded, under "By asset and scanner".

**Where the data comes from.** A scanner family counts for the categories `compliance.FamilyCategories` gives it, so this page and the compliance page agree on what was assessed. A family the map does not know (a SARIF tool such as CodeQL, a Generic JSON upload, a parser package) counts for the categories of the findings it produced; a run of such a tool that found nothing is not counted. D102 extends this: a parser id counts as its tool, and a parser package counts for the category it declares, here and on the Compliance page alike.

Code: `internal/query/scan_coverage.go`, `internal/store/aggregates.go` (`OpenByCategory`, `FamilyCategories`), `web/src/routes/applications/ScanCoverage.tsx`.

## D102. Compliance frameworks are resources; a status says why; exceptions, attestations and history are kept

**What a review found (2026-11-16).** D52 built six frameworks as data compiled into the binary, with three honest states (open, clear, not assessed). The review found:
1. A tenant could not add a framework of its own (an internal policy, SOC 2, CIS) without a release. D52 listed this as not built.
2. "Clear" said too much:
   - tenant-wide, one application's scan made a control clear for every application, including those never scanned;
   - a control matched by CWE was "assessed" by a dependency or image scan, so a Trivy scan cleared "Injection" for code no SAST ever read.
3. A risk-accepted finding vanished from its control: the control read "clear", and an auditor could not see the exception or who approved it.
4. Nothing was kept, so "what did 6.3.3 read on 30 June?" had no answer.
5. Scanners missing from the family-to-category map never counted as evidence:
   - CodeQL, OSV-Scanner, Generic JSON and parser packages;
   - and any clean run, which is recorded under its parser's id (`builtin:semgrep`), not the tool's name.
6. `complianceScope`, shown in the Application example of docs/04, was not in the CRD, so Kubernetes dropped it.
7. A control matched by CWE and by category gave a findings link that counted something other than the control.

**Decision.**

1. **Two resources**, the pattern of `RiskPolicy` and `ClusterRiskPolicy`:
   - `ComplianceFramework`, in a tenant's namespace, read by that tenant;
   - `ClusterComplianceFramework`, read by every tenant.

   Both are applied with `kubectl` or `rampart apply`. Details:
   - The spec is checked strictly, as a parser package is (D98): a misspelled field is refused, and every refusal names the control.
   - A name equal to a built-in framework's id is refused.
   - A spec that does not validate is stored with its reason. The last valid one stays in force, and the Compliance page lists the broken one under "Not applied".
   - A tenant framework with the name of a platform one replaces it for that tenant.
   - The six built-in frameworks are unchanged.
2. **A control** says how it is read:
   - **match** by `cwes`, `categories`, or scanner `rules` (`ruleId` may end in `*`), optionally only from `minSeverity` up;
   - **evidence**, the kinds of scan that must have run for it to be read at all;
   - or **manual**, attested by a person.
3. **When a control is assessed:**
   - A control matched by CWE alone needs a code scan, SAST or DAST. A dependency or image scan finds CWEs in other people's code; it does not assess the application's own.
   - Evidence the control names replaces the default.
   - Rules are evidenced by their own scanners.
4. **"Clear" needs evidence everywhere it applies.** Tenant-wide, a control is clear only if every application in the framework's scope had an evidencing scan in the window. Otherwise it reads "not assessed" and says "assessed in 2 of 3 applications".
5. **Scope.**
   - `Application.complianceScope` is a list of labels, such as `pci`, in the CRD and stored.
   - A framework with `appliesTo.complianceScope: pci` reads only the applications that list it.
   - A framework without one reads all of them.
6. **Every status has a sentence** that says why, in words a reader acts on. For example: "Assessed in 2 of 3 applications. The other one had no dependency (SCA) scan in the last 30 days." The same sentence is in the CSV export.
7. **Exceptions.**
   - A risk-accepted finding is counted apart as an approved exception. It does not make a control open.
   - It is always named in the sentence, linked to the findings, and in the CSV.
8. **Attestations.**
   - A maintainer or above (the people who approve risk acceptances, docs/07) records whether a manual control is met: what was checked, an optional https link to the evidence, and an expiry (one year by default, at most three).
   - Attestations are never changed or removed; the newest is the reading.
   - An expired one reads "not assessed".
   - An attestation may be for one application or for the whole tenant.
   - Recording one, and exporting the CSV, are audited.
9. **History.**
   - Every six hours, under an advisory lock, one replica keeps the day's reading of every framework of every tenant, whole and as shown.
   - `?at=2026-06-30` returns the day's kept reading, and the page offers the kept days.
   - Readings are kept 400 days (an annual audit plus a month) and removed by housekeeping (D99).
   - Only the whole-tenant reading is kept; a per-application past reading is not.
10. **Scanner families.**
    - The map gains CodeQL, OSV-Scanner, hadolint, Scorecard, CycloneDX and SPDX.
    - A parser id (`builtin:semgrep`) counts as its tool.
    - A parser package counts for the category it declares.
    - Any other family counts for the categories of the findings it produced.
11. **The findings link of a control** says when it lists only part of the count: "See part of the findings". The query language has no "or" across fields.

**Not built:**
- per-application history;
- CEL conditions in a control (a condition must run in SQL to count findings, and CEL does not);
- OSCAL import and export;
- signing the CSV;
- a stored mapping from a scanner's own control ids, such as kube-bench's CIS ids, other than `rules`.

**Why resources and not a screen to edit frameworks.** Frameworks are policy, like RiskPolicy. Kept in Git and applied by the operator, a change is reviewed, versioned and audited the same way as the rest of the configuration (D69, D82).

Code:
- `internal/compliance` (`spec.go`, `CategoriesOf`, `EvidenceCategories`);
- `internal/query/compliance.go` and `compliance_snapshots.go`;
- `internal/store/compliance.go` and `compliance_frameworks.go`;
- migrations 43 and 44;
- `deploy/crds/complianceframework.yaml` and `clustercomplianceframework.yaml`;
- `web/src/routes/compliance`.

The guide for authors is docs/27.

Sources: PCI DSS v4.0.1 requirement 6 and 12.5.2 (scope); SOC 2 Trust Services Criteria CC7.1, CC8.1 (evidence over a period); ISO/IEC 27001:2022 Annex A 8.25–8.29; NIST SP 800-218 (SSDF); Wiz, DefectDojo, Drata and Secureframe documentation on custom frameworks and controls.

## D103 to D111: decisions of the QA session of 2026-11-17

The test, the bugs and the evaluation of earlier decisions are in docs/28. These are the decisions it made.

| # | Decision | Why |
|---|---|---|
| D103 | **A parser the client names must match the file.** When the named parser scores 0 on the first 64 KiB and another parser recognises it with confidence 40 or more, the upload is refused (HTTP 400 `format-mismatch`; for a presigned upload the permanent error `format_mismatch`). A parser that scores above 0, or no better parser, is not refused. Checkov's `Detect` refuses SARIF | A JSON parser reads a foreign file as an empty scan, and the close step then closes the real findings of the scope |
| D104 | **NUL is replaced at ingest and refused at the API.** The ingest stream is scrubbed (0x00 to a space, `\u0000` to `�`, same length). The query API answers 400 for a NUL in a query parameter or a body that is not a file upload | PostgreSQL stores no NUL in text or jsonb; the result was HTTP 500 for a bad request |
| D105 | **A CVE is described by the feeds, not only by its report.** `GET /api/v1/vulnerabilities/{id}` (record by id or alias; 200 with `known: false` and the public links when no feed has it) and `/{id}/impact` (applications and assets of the tenant, by id or alias, at most 5000 findings) | docs/11; a finding from a report that carried only an id was undescribed |
| D106 | **Inventory is read from the database.** `GET /api/v1/inventory` (assets with open findings) and `/inventory/components?q=&limit=` (packages of the latest SBOM of each asset, default 500, at most 2000) | The page asked for routes that did not exist |
| D107 | **SARIF carries what it can.** A rule id that is a vulnerability id becomes `VulnIDs`; Trivy's `Package:`, `Installed Version:` and `Fixed Version:` lines become the package, with a generic purl; Trivy's category follows the rule tags; a multi-line message does not become the title | KEV, EPSS, the CVE page, the impact and the fingerprint all need the id and the package |
| D108 | **With `versions: latest`, a DT name that has no flagged version reads its newest BOM.** When DT flags one, that one wins | DT sets `isLatest` only on an upload with `isLatest=true`; the default skipped the whole portfolio |
| D109 | **A policy change is recomputed within 30 seconds**, by its own ticker; the breach sweep keeps its interval | The list and the inspector disagreed for up to 15 minutes |
| D110 | **`/readyz` is false until the runner says the server is ready** | Traffic reached a pod that was still migrating |
| D111 | **The mapping runtime fills the fields the built-in parsers fill**: `map.cwes`, `map.cvssVector`, `map.category` (per record, validated), `location.package.manifestPath`, and `PurlBase` derived from the purl. A direct upload answers with the application it was filed under and a warning when it differs from the one named (D10 is unchanged). Triage: a change to the justification or impact statement alone is a decision (`justification_changed`) | See docs/28 §2 and §4 |

Open, from the same session: the `kevDueDate` cap for non-federal use, `extends: default` for a tenant `RiskPolicy`, reads per application (D48, D90), the OpenAPI spec generated from the route table (D54), and the stored raw report of a direct upload. See docs/28 §3 and §5.

## D112 and D113: compliance per application, and framework marks

| # | Decision | Why |
|---|---|---|
| D112 | **An application page says what it meets today.** `GET /api/v1/applications/{id}/compliance` returns, for each framework that reads the application, its controls clear, open and not read, and a verdict (`meets`, `gaps`, `partial`). A framework with a scope reads only the applications that list it, and the others are named. It is the reading of the Compliance page, narrowed to one application: no second set of rules | docs/27 reads a framework for one application; nothing answered "which frameworks does this application meet" |
| D113 | **A framework may carry a logo, read by the server.** `spec.logoUrl` (https, at most 2048 characters) is fetched once by the server with an SSRF-safe client, checked by its bytes (PNG, JPEG, WebP, plain SVG), kept a day, and served from `/api/v1/taxonomies/{id}/logo` with `nosniff` and a sandbox policy; the browser never contacts the address and the CSP stays `img-src 'self' data:`. **Official logos are not bundled**: they are trademarks and recolouring them is an alteration. Built-in frameworks get a mark of Rampart's own (indigo; teal for a framework the organisation installed) | See docs/28 §9 |

## D114 to D116: applications from uploads, SBOM per track, schema version

| # | Decision | Why |
|---|---|---|
| D114 | **Creating an application from an upload is explicit.** `createApplication=true` makes a missing one (maintainer, admin or CI token; a triager gets 403); `=false` answers 404 `application-not-found` and makes nothing; without it the old behaviour stays, with a warning. The answer has `applicationCreated`. The upload dialog offers "New application..." to a maintainer and sends `false` for a listed one. An asset that already belongs to an application keeps it (D10) and the answer says so | DefectDojo, Veracode and Snyk create on purpose and by permission; a typo made an empty application |
| D115 | **An SBOM belongs to a track of an asset** (migration 45, `sbom.track`, default `default`). The inventory lists the newest SBOM of each track; the asset's single SBOM (export, graph) is the primary track's (`main`, then `default`, else the newest); an ephemeral run saves no SBOM (D10) | One slot per asset let branches replace one another, and a pull request replace the real SBOM |
| D116 | **The schema version is checked by a test.** `CurrentExpectedSchemaVersion` and the chart's `minSchemaVersion` equal the latest migration (45) | docs/21 asked for it; it was forgotten for 43 and 44 |

Open at the time: `ScanSource.spec.trackedRefs` (docs/04, D10) was not built; see D117.

## D117: `ScanSource.spec.trackedRefs`

`spec.trackedRefs` (docs/04) decides which refs of a source change the inventory: an exact name, a prefix ending in `*`, or `*`. The list replaces the defaults (`main`, `master`, `default`, `release/*`, `prod`, `production`); a pull request is always ephemeral; no list keeps the defaults. It is stored in the source's ingestion policy and read at the direct upload, the presigned upload and the runs list (`IsEphemeralFor`; a policy that cannot be read falls back to the defaults, so a read failure never makes a tracked run ephemeral). Validated by the CRD, `rampart apply` and the operator. `SaveScanSource` now overwrites the stored policy, so a list removed from the resource is removed from the source. The match is on the branch; an upload with an `environment` and no `branch` is tracked. docs/28 §10.

## D118: a person's Dependency-Track mapping is read, and the asset follows the mapping

In `SyncProject` and the portfolio sync the order is: the project's stored manual mapping (`manual_ui_mapping`), which bypasses the rules and the project filters; then the seven rules (D92); then the filters. A Dependency-Track asset moves, with its findings, to the application its mapping names when that changes (an upload's asset keeps its application, D10; the mapping is the declared truth for this kind of asset). `POST /sources/{id}/map` accepts any project of the source, and `GET /sources/{id}/projects` lists the mapped ones with the rule that put each there. `domain.DTrackManualMapping` is the rule name. Where `defaultApplication` is set, it takes every project no other rule claimed (docs/10 rule 7): leave it empty on a Dependency-Track that serves several teams. docs/28 §11.

## D119: what changed in an application

`GET /api/v1/applications/{id}/changes?from=&to=` answers which findings appeared, were closed (and how), came back, and were open at the end of a range of days (both included, UTC, at most 366, default 30), with exact counts, the counts of the range of equal length before it, and a count per day. A finding is "new" by `first_seen`, "closed" by `resolved_at` (any resolution), "came back" by a `reactivated` event, "open at an instant" when first seen before it and not closed by it. Lists are cut at 1,000 and the cut is named. No schema change. docs/28 §12.

## D120: a control is out of compliance only past a deadline; the finding page shows its controls

**Before.** Any open finding that bore on a control made the control `open` ("Not met"). That is stricter than the standards. PCI DSS 6.3.3 gives a month for critical patches and leaves the rest to the entity's own risk ranking; Vanta and Drata mark an item overdue only after its SLA, and an SLA miss can be acknowledged; CISA BOD 22-01 sets a due date per KEV entry (federal agencies only).

**Now.**
- `compliance.Control.Breaks` decides whether a finding counts against a control. The same rule exists in SQL (`controlBreaksSQL`); `TestControlBreaks_GoAndSQLAgree_OnPostgreSQL` runs both on the same data so they cannot drift.
- A control with open findings none of which is past its deadline has the new status `at_risk` ("At risk"), with the date the first falls due. Only a finding past its deadline makes the control `open` ("Not met"). The deadline is the finding's SLA due date, or `caps.kevDueDate` where it is earlier (D40/D41).
- At application level `AppFramework` has `at_risk`, `overdue_findings`, `earliest_due`; the verdict is `meets`, `at_risk`, `gaps` or `partial`.
- `GET /api/v1/findings/{id}` returns `controls`: the controls of every installed framework that the finding bears on, with status and deadline. The inspector shows them in a Compliance section (nothing is drawn until loaded; overdue is counted in whole days).
- The application page orders frameworks: pinned, then gaps, then at risk by nearest due date, then partial, then meets; shows 3 and "Show N more". Pins are kept in the browser (`rampart.pinnedFrameworks`).

**No deadline, no clock.** A finding with no deadline at all (no SLA policy applies) cannot be "inside" one, so a control whose open findings have none stays "Not met", as before.

**Known simplification.** The clock starts at `firstSeen` (`startFrom: firstSeen`), not at the release date of the patch as PCI DSS 6.3.3 reads. Rampart has no reliable patch date for every ecosystem; recorded as a limitation.

## D121: threat intelligence feeds as declarative Custom Resources and dedicated UI tab

**Problem.** Threat intelligence feeds (NVD, OSV, CISA KEV, FIRST EPSS) were historically perceived as built-in background processes, with `ClusterFeedMirror` only conceived as a mirror override. Operators need full declarative visibility: feeds should be explicit CRD instances in the Helm chart, inspectable via kubectl, customizable for airgap internal mirrors or private feeds, and removable cleanly.

**Resolution.**
- The Helm chart renders a default `ClusterFeed` / `ClusterFeedMirror` resource (`feeds.defaultMirror.enabled: true`), establishing declared upstream URLs, egress rules, and optional/custom feed endpoints.
- The CRD schema and operator support both `ClusterFeed` and `ClusterFeedMirror` kinds with shortNames (`cfm`, `feed`, `feeds`, `clusterfeed`, `clusterfeeds`), ensuring backward and forward compatibility.
- `GET /api/v1/feeds` queries active mirror configuration and correlated feed states (`records`, `last_sync`, `status`, `error`).
- A dedicated "Vulnerability Feeds" tab in the Integrations page surfaces feed health, synced record counts, egress policies, and an interactive Declarative CRD specification dialog with copyable manifests and kubectl commands.


## D121: a feed sync is run by the system role, and ends as a notification and a Kubernetes Event

**What was wrong (found on dev, 2026-11-17).** The Sync buttons on the Vulnerability Feeds page ran the sync inside the query API with the application pool. That role cannot write the global tables or `feed_state` (D19), the error was dropped, and the API answered 202 whatever happened. So Sync "succeeded", the status never changed, and a failed feed (NVD) stayed on "Error" with the old message. The button also ignored its `feed` parameter, did not use the scheduler's configuration (NVD key, OSV ecosystems, re-score after the sync), and any tenant could trigger a sync that is global.

**Now.**
- `enrich.OnDemand` runs it with the system pool and the scheduler's `FeedConfig`, under the same advisory lock (`ErrSyncBusy` → 409). `Only` limits a round to one feed. The feeds are marked `syncing` before the API answers, so the page sees it at once; a feed that no step ran is put back to `idle`; a `syncing` left by a restart is set to `error` ("interrupted") by the next round that holds the lock.
- Only an administrator may start a sync. A server without `database.systemUrl` or with feeds off answers 501, not 202.
- **Every round ends in one notification per tenant** (`feed_sync` or `feed_sync_failed`, one message for the round, linking to Integrations) **and one Kubernetes Event** in the operator's namespace (`FeedSynced` Normal, `FeedSyncFailed` Warning, about the ClusterFeed). This holds for the scheduled round and for the one asked for on the page. The rule going forward: what tenants are told about the platform's own work is also an Event in the namespace. Notifiers (Slack, webhooks) receive it through the same router as other notifications.
- The page follows the server: it polls every 2 s while a feed says `syncing`, shows the whole error, and when a Test answers but the sync failed it says so (the address is fine; the failure is in the sync).

**Known limits.** A scheduled round every 6 h with all feeds well is a notification every 6 h; there is no setting yet to send failures only. The Event is about `ClusterFeed/default`, in the operator namespace, so `kubectl describe clusterfeed` (which reads the `default` namespace) does not show it; `kubectl get events -n <namespace>` does. Outside a cluster there is no Event.

## D122: the application page's attestation section attests real manual controls

The section sent made-up control ids (`SEC-REVIEW`, `<framework>-APP-ATTEST`) and a framework-wide "sign-off". D102 allows an attestation only of a control the framework marks `manual`, and the API refuses any other (404 or 409), so no button on that section could ever succeed. It also repeated the framework table the Compliance section already shows. Now it lists the manual controls of the frameworks the application is in, with the reading, the date it is in force until, and Attest / Attest again for a maintainer, for that control and this application. With no manual control it says so.

## D123: attestations: decided where the caller may decide, the right one reads, an owner, reminders before the end

Checked against Drata (an evidence owner of its own; a renewal date, one year by default; past it the evidence is outdated and the control may not be audit-ready) and Vanta (document tests with a renewal date and reminders before it). D102's model matched: a person's reading of a manual control, a note, an https link, one year by default (three at most), append-only, audited, expired reads "not assessed". Four things did not.

1. **Where the caller may decide (D48).** The API's door was the tenant role alone, so a maintainer on one application, who is offered the button, was answered 403. The door is now the highest role held anywhere, and the decision is checked against the application the attestation is for (`maintainer` on it, a binding or the tenant role); an attestation for the whole tenant needs the tenant role. No privilege was widened; one was missing.
2. **Which attestation reads.** One for the application wins over one for the whole tenant, but only while it is in force. An expired application attestation used to hide a tenant-wide one that still held and the control read "not assessed". When none is in force, the newest that applies is shown, so the reading says when it expired.
3. **Owner.** `owner` (optional, at most 200 characters) is who renews it; empty means the person who made it. Shown on the application page and in the reminder. Migration 00046 (D124 raised the version to 47).
4. **Reminders.** The sweep that warns of risk acceptances ending (D45) also warns of the current "passed" attestation of a manual control ending, at 14 days and again at 1 day, once each (`compliance_attestation_warning` keeps the smallest threshold sent). One notification per sweep per tenant, listing the controls, application and owner (kind `attestation_expiring`). A superseded or failed attestation is not announced. Notifiers receive it through the same router.

**Not built.** The reminder goes to the tenant, not to the owner alone (per-user routing is not built, D45). Renewal tickets: D124.

## D124: renewal tickets for attestations, and migrations are expand-only

**Renewal tickets (Vanta opens a Jira ticket, due on the renewal date, for the document's owner).** An attestation that ends within 14 days gets one ticket on the tenant's tracker, whichever it is (Jira or GitHub; a tenant has one, D70), and the ticket closes by itself when the attestation is renewed.
- It follows the group tickets (D90): the table `attestation_ticket` (migration 00047) is the outbox; the reservation is written before the tracker is called; a retry first looks the issue up by its label (`rampart-f-<attestation id>`) because a failed call may have created it; a failure is retried with backoff up to `MaxTicketAttempts`; the existing ticket sweeper (one replica, advisory lock) runs it.
- Only the current "passed" attestation of a control and application counts. A tenant with no tracker gets no ticket and nothing is reserved, so adding a tracker later opens tickets only for what ends within 14 days then, not a backlog.
- The ticket names the framework, control, application, end date and owner. The trackers show it as a **compliance notice**: `Finding.Notice` marks the stand-in finding, and Jira and GitHub then drop "vulnerability", the severity labels and the link to a finding page that does not exist (they link the Compliance page, labels `rampart`, `compliance`).
- A renewed attestation (a newer "passed" one in force) closes the ticket with a comment. One that simply expires is left open: that is overdue, not done.
- **Not built.** Assigning the ticket to the owner in the tracker (an owner is free text, not a Jira account or GitHub login); due dates on the issue; a declarative tracker may render the stand-in as an ordinary finding.

**Migrations are expand-only (from 46).** A release upgrades in this order: the migrate job (a pre-upgrade hook, D4), then the new pods, whose init container waits for `minSchemaVersion`. Until the new pods are ready, the old ones keep serving on the new schema. So the whole release must be rolled, which Helm does, and a migration must never break the previous binary: it may add tables, nullable or defaulted columns, indexes and policies, and must not drop, rename or tighten anything the old version reads. `TestMigrationsAreExpandOnly` fails on DROP, RENAME, `SET NOT NULL`, a column type change, TRUNCATE, REVOKE, or a NOT NULL column without a default, in the Up part of 46 and later. A change of that kind is made in two releases; the second migration carries a `-- contract:` comment. 46 and 47 only add a column with a default and two tables. `CurrentExpectedSchemaVersion` and the chart's `minSchemaVersion` are 47 (D116).

## D125: corrections after a review of D119–D124 (2026-11-17)

Three independent readers went through the code written in this session. What was confirmed and changed:

**Compliance (D120).**
- The finding page showed a deadline the control did not use: with no stored due date it invented one from the built-in policy ("Due in 12 days") while the control already counted the finding. It now shows the stored date, and says "No deadline is set, so it counts these controls as out of compliance now."
- A control with some findings that have a deadline and some that have none read "At risk" and the finding with none could never fail it. Any open finding with no deadline now keeps the control "Not met", and the reason says so. `ControlDeadline.NoDeadline` carries the count.
- The totals on the application page counted a finding once per control it bears on (a CWE-89 finding in four controls was four). `DistinctFindings` counts each once. Where a control fails for another reason (a manual control attested as not met) the sentence no longer says "0 findings are past their deadline".
- A CISA KEV due date is a day: a finding is late from the next midnight UTC, not from the first moment of that day (`SLAPolicy.Due`).
- `GET /taxonomies/{id}/status?application=` refuses an application outside the framework's complianceScope (it used to evaluate it).
- The CSV gains `overdue`, `earliest_due` and `attestation_owner` (appended). A control with `open > 0` and `overdue = 0` is "at_risk", not a failure. Daily readings kept before D120 still say "open" for such controls; the history steps on the day D120 was deployed.
- The inspector says "Overdue, by less than a day" instead of "1 day" for a finding hours past its deadline.

**Feeds (D121).**
- Feeds the server's configuration does not run (NVD switched off, OSV with no ecosystem) answer 409 `feed-off` instead of being marked syncing and silently reset.
- The round's announcement (notification and Event) runs after the sync lock is released; the sync itself uses the server's context, not the request's, cleans up with a context of its own after a timeout, and recovers from a panic; a failing `pg_advisory_unlock` closes the connection rather than returning a connection that still holds the lock to the pool.
- NVD's success and an EPSS file that cannot be unpacked now reach the round's summary; a round of one feed is announced too.
- The Event is about the Pod that runs the sync, in its own namespace. The API server refuses a core/v1 Event whose involved object is in another namespace (a cluster-scoped `ClusterFeed` only allows `default`), so the first version would have been rejected and only logged.
- The page: the CRD it prints shows only what the server has (printing the public defaults defeated `egress: deny` and switched on two optional sources); Test errors are shown; probe results are cleared when a sync starts; a switched-off feed is not "Unreachable" and offers neither Test nor Sync; Sync is offered to administrators only; "Healthy" is said only when every enabled feed synced.

**Attestations (D123, D124).**
- The renewal ticket looks the issue up by its label whenever the reservation already existed (a crash between creating the issue and recording it used to open a second one). A ticket opened on another tracker than the tenant has now is not closed through the wrong one.
- The reminder's message is written in the same transaction as its "announced" marker. A notification that mixes a 1-day and a 14-day item says so.
- `owner` is one line (no control characters), since it is written into notifications and tickets.
- The ticket sweeper starts from the attestations that end soon (`idx_compliance_attestation_expiry`) instead of ranking every attestation of every tenant each minute.
- The dialog offers only days the server accepts (tomorrow to three years), and the application's summary is refreshed after an attestation.

**Known problem, left as it is on purpose.**
- Any administrator of any tenant can start the global feed sync. There is no platform-administrator role and no cooldown, so in a multi-tenant installation one tenant's administrator can start upstream traffic, a re-key and a re-score of every tenant. The options were a platform role (GitLab keeps its Admin Area for instance administrators apart from group owners), moving the sync to the operator and a CronJob only, or a cooldown with an audit entry; none is built. It matters only where more than one tenant runs.

**Dealt with afterwards (D126).** The changes ledger, tickets that gave up, the SBOM "Scan Now" button, the history across D120, and reminders for covered attestations.

## D126: what was left open by D125, and was then done

**The changes ledger replays transitions (D119).** "Open at start/end", "closed" and "came back" used to be read from the finding as it is now, and `resolved_at` is cleared on reopening, so a finding closed on 1 Oct and reopened on 10 Oct was counted open on 5 Oct, and a manual reopen was not a return. The ledger now reads each finding's closings and returns from its events (closed by a rescan, a state change, a risk acceptance approved, expired or revoked, a reactivation), and from `resolved_at` for a finding without events (older than them, or than the events' retention). A closing counts only when the finding was open, a return only when it was closed (fixed to risk_accepted is one closing; open to under_investigation is no return), except that an event that is a return by its nature counts even when the closing before it was never recorded. The point-in-time reading follows the usual event-sourcing pattern (replay up to the instant). The first version did it in SQL with a lookup per finding and took a minute on 10,000 findings; the transitions are now read once and replayed in memory (0.4 s). The lists keep the most recent transitions when they are cut. Counts are of findings: a finding that cycles twice in the range is one.

**A ticket that gave up is announced, shown and can be sent back (D124).** A `ticket_failed` notification is written when a renewal ticket gives up; the attestation shows its ticket (link, "opening", or "could not be opened" with why); an administrator can send it back (`POST /api/v1/attestation-tickets/{attestation id}/retry`, migration 00048 grants the application role `UPDATE` on four columns of `attestation_ticket` and nothing else).

**"Scan Now" no longer pretends to scan.** Matching packages to vulnerabilities is Dependency-Track's work, per project. `POST /api/v1/inventory/components/scan` re-scores the tenant's findings and says so; it needs the triager role (it was open to any role). The application's SBOM section has "Refresh from Dependency-Track" (`POST /api/v1/applications/{id}/refresh-vulnerabilities`, triager on that application): it queues a sync of each Dependency-Track project mapped to the application. It pulls what Dependency-Track has analysed; asking Dependency-Track to re-analyse first needs a client call this version does not make (its API has an analyse endpoint for a project, which appears in published OpenAPI documents and not in its own documentation: check it against the running version first).

**The history says which rule made it.** A reading carries `model` (`d120-deadlines`). A kept reading without it was written before D120, when any open finding made a control not met; reading it by day now carries a note saying so. Kept readings are evidence and are not rewritten.

**Attestations covered by a whole-tenant one.** An attestation of one application whose control a newer whole-tenant "passed" attestation outlasts gets no reminder and no ticket: the reading falls back to the tenant-wide one when it ends.

## D127: Parsers as CRDs ("All Come In Front Door") and Multi-Runtime Support (Native, Lua, WASM, Mapping)

**Context and Principles.**
Rampart previously treated built-in parsers (21 Go parsers, ~7,400 LOC) as special components hardcoded in the Go binary, while custom parsers were isolated in `IntegrationPackage`. To enforce the core architectural principle **"All come in front door"** (docs/29):
1. No parser is privileged merely because it is compiled into the binary. Every parser is expressed as a Kubernetes Custom Resource (`ClusterParser` cluster-wide, or `Parser` tenant-scoped).
2. The Helm chart ships all 21 standard parsers as default CRD resources in `templates/clusterparsers.yaml`.
3. The two foundational promises (docs/29 §1) are strictly preserved:
   - **Zero finding key regression:** Output finding keys (SHA-256 hashes of location, secret values, snippets, web endpoints, resource keys) remain identical.
   - **Zero performance degradation:** Standard heavy formats (SARIF, CycloneDX, SPDX, Syft, Trivy) run through compiled streaming iterators with $O(1)$ memory.

**CRD Architecture and Database Storage.**
- `deploy/crds/clusterparser.yaml` (and synced `deploy/helm/rampart/crds/clusterparser.yaml`): Cluster-scoped `ClusterParser` resource.
- `deploy/crds/parser.yaml` (and synced `deploy/helm/rampart/crds/parser.yaml`): Namespaced `Parser` resource for tenant-specific parsers.
- **Database Migration 49 (`00049_cluster_parser.sql`):** Updates `cluster_policy` and `policy_object` check constraints to allow `kind = 'parser'`. `CurrentExpectedSchemaVersion` in `internal/store/migrate.go` and `minSchemaVersion` in `deploy/helm/rampart/values.yaml` bumped to 49.
- `domain.ParserStore`: Implemented on both `PostgresStore` (`SELECT 'cluster' ... FROM cluster_policy UNION ALL SELECT 'tenant' ... FROM policy_object`) and `MemoryConfigStore`.

**Supported Runtimes.**
1. **`runtime: native`:** Wraps the compiled streaming Go parsers (`sarif`, `cyclonedx`, `spdx`, `syft`, `openvex`, `trivy`, `grype`, `semgrep`, `gitleaks`, `trufflehog`, `dependencytrack`, `checkov`, `bandit`, `nuclei`, `zap`, `dependencycheck`, `snyk`, `kubebench`, `prowler`, `gitlab`, `genericjson`). Eliminates any risk of finding key mutation or allocation explosion on massive standard reports.
2. **`runtime: lua`:** Sandboxed in-memory runner (`internal/integrations/lua`) using `github.com/yuin/gopher-lua`. Only safe base libraries (base, table, string, math) are loaded; OS and filesystem access are disabled. Provides built-in `json.decode` and `json.encode` plus an `emit(table)` callback. Yields `domain.RawFinding` iteratively, with instant cancellation if iteration stops or context expires.
3. **`runtime: wasm`:** Sandboxed WebAssembly execution (`internal/integrations/wasm`) powered by `github.com/tetratelabs/wazero`.
   - **Air-Gapped / Offline Ready:** Zero Network Syscalls (WASI Preview 1 with stdin/stdout only, no network sockets, no host filesystem bindings). Wazero memory is strictly bounded via `limits.maxMemoryMB`.
   - Standard UNIX filter model: Input report streams into `stdin`, output findings stream out of `stdout` as newline-delimited JSON (`JSONL`).
4. **`runtime: mapping`:** Declarative CEL mapping expressions for lightweight JSON transformations.

**Ingestion Resolution Precedence (`internal/ingest/package_parsers.go`).**
During report uploads or format detection, parsers are resolved in strict order:
$$\text{Tenant Parser (Parser CRD)} \succ \text{Cluster Parser (ClusterParser CRD)} \succ \text{Embedded Built-in Defaults}$$
- Built-in scanner names (e.g. `trivy`, `sarif`) are reserved so an unprivileged package cannot inadvertently shadow or misroute standard scanners.
- Format detection evaluates confidence scores across all active parsers; built-in readers win ties over packages.

**Operator and Deployment Integration.**
- `internal/operator/manager.go`: Adds controller for `ClusterParser` managed alongside cluster policies.
- `internal/operator/reconciler.go`: Provides `NewClusterParserReconciler` and `NewParserReconciler` with `apply.ValidateParser` spec validation.
- `deploy/helm/rampart/templates/rbac.yaml` and `deploy/operator/rbac.yaml`: Grants the operator RBAC rights for `clusterparsers`, `clusterparsers/status`, and `clusterparsers/finalizers`.
- `internal/config/parsers/`: 21 default manifests embedded into the Go binary with `//go:embed` for out-of-the-box operation in Docker Compose and single-binary environments. **Superseded by D141: nothing is embedded any more.**
- `deploy/helm/rampart/templates/clusterparsers.yaml`: Deploys all 21 default `ClusterParser` resources when `parsers.defaultParsers.enabled: true` (the default). **Superseded by D141: the resources come from the `rampart-parsers` and `rampart-sbom-parsers` charts.**

**WASM OCI Publishing, Rigorous Testing & CI/CD Pipeline.**
- Standalone WASM parsers live in `parsers/wasm/<name>/` (`custom-scanner`, `gitleaks`, `sarif`, `semgrep`).
- **Equivalence Testing:** Automated tests verify bit-for-bit parity of finding keys and field extractions between native Go parsers and compiled WASM modules under `wazero`.
- **CI/CD Pipeline (`.github/workflows/wasm-parsers.yml`):** Automatically discovers modules in `parsers/wasm/*/`, compiles to `wasip1/wasm`, runs tests, packages as scratch OCI images, publishes to `ghcr.io/rampart/parsers/<name>`, signs keyless with Cosign, and attests SLSA Level 3 provenance.
- **OCI Status & Observability:** CRD printer column `SYNCED` reflects condition `Type: ArtifactSynced` (`Status: True/False`, `Reason: Pulled/PullFailed`). Record errors are logged with line numbers and raw snippets to `ingest_run_error`.

## D128: Native SBOM Architecture, Streaming WASM Parsers, Hardcoding Eradication, Dedicated Analyzer CRDs, and Frontend Observability

**1. Separation of Concerns: Findings vs. SBOMs vs. Analyzers.**
Rampart decomposes security telemetry into three distinct Kubernetes Custom Resource definitions:
1. `ClusterParser` / `Parser`: Ingests vulnerability and misconfiguration finding reports (SAST, DAST, Container Scanning, Secrets).
2. `ClusterSBOMParser` / `SBOMParser`: Ingests pure software inventory and dependency graphs (CycloneDX, SPDX, Syft).
3. `ClusterSBOMAnalyzer` / `SBOMAnalyzer`: Configures the native in-process vulnerability matching engine, enabling/disabling it and tuning matching thresholds.
4. `ClusterExternalAnalyzer` / `ExternalAnalyzer`: Connects Rampart to external containerized analysis engines over gRPC (`analyzer.proto`).

**2. Eradication of Hardcoding and Native Go Readers.**
Previous implementations retained in-tree Go readers (`internal/sbom/readers/`) and hardcoded `switch format` cases as a fallback. To uphold the architectural guarantee that any format can be introduced or modified without modifying or recompiling the Go host:
- The entire `internal/sbom/readers/` directory was completely purged.
- All format parsing logic for CycloneDX (both JSON and XML) and SPDX (JSON, JSON-LD, Tag-Value) resides exclusively inside sandboxed WASM modules (`parsers/wasm/sbom-cyclonedx/` and `parsers/wasm/sbom-spdx/`).
- The WASM module decodes documents and streams line-delimited JSON events (`metadata`, `component`, `edge`, `vulnerability`) to `stdout`.
- The Go host (`internal/sbom/parser.go`) executes the WASM bytecode in a memory-bounded Wazero runtime (< 15MB) with zero network egress, remaining 100% generic and agnostic of format syntax.

**3. Complete Eradication of Upstream Dependency-Track.**
- Deleted `internal/upstream/dependencytrack/` (`client`, `service`, `sync`, `webhook`) entirely.
- Decoupled `internal/targets/runner.go` from external sync loops and webhooks. Telemetry is ingested and analyzed immediately upon upload without eventual consistency lag or external JVM container dependencies.
- Updated `internal/connectors/checker.go` to use native HTTP probes without importing legacy upstream packages.

**4. Dedicated Native SBOM Analyzer CRD & Helm Packaging.**
- Created `deploy/crds/clustersbomanalyzer.yaml` and `deploy/crds/sbomanalyzer.yaml` (`rampart.aspm.dev/v1alpha1`).
- Created Helm chart template `deploy/helm/rampart/templates/clustersbomanalyzer.yaml` driven by `sbomAnalyzer` in `values.yaml` (`enabled: true`, `engine: hybrid`, `rules.minConfidence: 0.8`, `sources.osv: true`).

**5. Hybrid Matching Engine Architecture.**
- **In-Process Go Matcher (`internal/analyzer/matcher/`)**: Executes deterministic $O(1)$ lookup by canonical PURL base followed by semantic version range checking (`IsAffected(v, intro, fixed)`) in < 50ms against local PostgreSQL OSV/advisory tables.
- **External Analyzer Protocol (`pkg/api/analyzer/v1/analyzer.proto`)**: A standardized Protobuf/gRPC interface (`Analyze`, `GetMetadata`, `HealthCheck`) allowing teams to deploy commercial or proprietary scanner containers in-cluster.

**6. Frontend Observability & Governance Extensions.**
- **Application Header Metadata (Version Swap)**: In `ApplicationRoute.tsx`, swapped the primary header metadata badge next to `app.name` from `tag` to `version` (e.g. `v1.4.0`), providing instant build and release identification alongside application name. Secondary tags (`tags?: string[]`) remain supported as pill badges.
- **Dedicated Licenses Tab (`ApplicationLicensesSection.tsx`)**: Aggregates all packages by license with automatic legal risk classification:
  - *Permissive* (MIT, Apache-2.0, BSD, ISC)
  - *Copyleft / Restricted* (GPL, AGPL, LGPL, MPL)
  - *Unknown / Unspecified*
  Includes metric overview cards, search/filter controls, and an interactive package drilldown panel.
- **Dedicated Dependency Graph Tab (`ApplicationDependencyGraphSection.tsx`)**:
  - Connects to `GET /api/v1/applications/{id}/sbom/graph` to display direct vs. transitive dependency counts, hierarchy trees, and Mermaid diagrams.
  - Features an interactive **Root-Cause Dependency Tracer** connecting to `GET /api/v1/applications/{id}/sbom/path?target={purl}` to trace the shortest path from the root application to any downstream vulnerable package.
- **Enhanced SBOM Table**: Displays colored badges for license compliance in `ApplicationSBOMSection.tsx`.

## D129: Elimination of Legacy Scanner Family Hardcoding and Purge of Upstream Sync Remnants

**Context & Problem:**
Following the migration from monolithic hardcoded parsers to dynamic Kubernetes CRDs (`ClusterParser`, `ClusterSBOMParser`), several legacy artifacts remained embedded in the Go host and React frontend:
1. `internal/query/gate.go` contained legacy `ScannerFamily` equality checks, hardcoded lists of SBOM formats (`cyclonedx`, `spdx`, `syft`), and a polling wait loop for external Dependency-Track background synchronization.
2. `internal/ingest/gateway.go` hardcoded specific scanner names (`trivy`, `grype`, `cyclonedx`, `spdx`, `syft`, `gitleaks`, `trufflehog`) in `categoryOf` to map parsers to findings categories (SCA, Secret, SAST).
3. `internal/ingest/processor.go` hardcoded format checks (`strings.Contains(id, "cyclonedx") || strings.Contains(id, "spdx") || strings.Contains(id, "syft")`) in `selectParser` to determine whether an upload was an SBOM.
4. `web/src/routes/ingestion/ParsersView.tsx` contained static arrays of parser IDs to determine format labels and category badges.

**Decisions & Implementation:**
1. **Dynamic CRD Category Metadata on `integrations.Descriptor`:**
   - Extended `integrations.Descriptor` with `Category string json:"category,omitempty"`.
   - Propagated `Category` across all parser runtimes: built-in ClusterParsers, WASM parsers, Lua parsers, and SBOM parsers.
   - Refactored `gateway.go` (`categoryOf`) to derive the finding category strictly from `parser.Descriptor().Category` (mapping `"sbom"` to `domain.CategorySCA`, `"secrets"` to `domain.CategorySecret`, etc.) with zero scanner name matching.
2. **Contract-Based SBOM Detection in Ingestion Processor:**
   - Refactored `processor.go` (`selectParser`) to check whether the resolved parser implements `sbomParser` (`ParseSBOM(...)`) or specifies `Category: "sbom"` / `"sbom"` descriptor metadata.
   - Completely eliminated the hardcoded list of `cyclonedx`, `spdx`, and `syft`.
3. **Pure Format/Name Matching in CI/CD Gate:**
   - Purged all Dependency-Track waiting loops in `internal/query/gate.go`.
   - Streamlined `runMatches` to evaluate against the run's dynamic format (`r.Format`) and parser descriptor without relying on static scanner family assumptions.
4. **Dynamic Frontend Ingestion Catalog:**
   - Refactored `categorizeParser` and `parserFormat` in `ParsersView.tsx` to inspect parser metadata and tags dynamically.
   - Replaced legacy `IntegrationPackage` references with standard `ClusterParser` YAML definitions.

## D130: the CLI names the parser and never detects (2026-11-18)

**Context.** `rampart sbom graph` and `path` tried a hard-coded list of readers (`cyclonedx`, `spdx`, `syft`), and `upload` sent no name unless `--parser` was given. A format added to the server as a resource (a `ClusterParser` or `ClusterSBOMParser`) did not work in the CLI until the list was edited, and a CLI of an older version silently disagreed with the server.

**Decision (owner).**
1. `rampart upload` and `rampart sbom upload` require `--parser <name>` (`--format` is an alias). `--detect` is the explicit opt-in to let the server choose from the content; giving both is an error. `--require-parser` is still accepted and ignored, so no pipeline that passes it breaks.
2. The CLI holds no list of formats. `rampart sbom graph` and `path` read the file locally, so they need `--parser` too, and only a reader the CLI can load (`RAMPART_WASM_DIR`); for any other the error says so and points to the server. They cannot ask the server for the module list: reading locally needs the module on the machine, not its name.
3. The server keeps its content detection for API callers that send no name and for `--detect`. A name it does not know is refused (400) with the names it does know, taken from the built-in, cluster and tenant parsers installed, not from a list kept by hand. The upload response now carries `parser` (the name a client sends) and `detected` (true when the server chose it), and the CLI prints them.
4. `rampart sbom upload` no longer prints a findings line unless a run created some: an SBOM reader fills the inventory (D128, docs/34 C2).

**Why.** A pipeline that names its parser reads the same way every time; detection can change its answer when a file changes shape. A new parser works in the CLI with no release. The flexible variant (the name optional by default, the server detects and the CLI prints the choice) was rejected as the default for the first reason; it remains available as `--detect`.

**Consequence.** An upload without `--parser` or `--detect` now fails in the CLI. The example commands in the UI (`emptyCommand` and the like) must add `--parser` (docs/34 §10). `GET /api/v1/parsers` still lists only the built-in parsers and the tenant's packages; it is to list ClusterParser, ClusterSBOMParser and tenant parsers with their kind (open).

## D131: an SBOM reader can extract the vulnerabilities a document states, behind an option (2026-11-18)

**Context.** C2 (docs/34) removed the extraction of vulnerabilities from SBOM readers, so an SBOM upload created no findings. The owner's design had always been an option, off by default (`extractVulnerabilities: false`, docs/32 section 4.1), not removal: some teams keep a VDR in the document and want it in the findings list.

**Decision.**
1. `options.extractVulnerabilities` (default `false`) on `SBOMParser` and `ClusterSBOMParser` (both CRD copies, the three YAML specs, the chart value `sbomParsers.defaultSBOMParsers.cyclonedx.extractVulnerabilities`). Off, an SBOM run is assets only, as D128 and C8 say. A format that states no vulnerabilities (SPDX, Syft) is unaffected by it.
2. **Only what the document states.** The CycloneDX module reads the `vulnerabilities` section (JSON and XML) and nothing else; the CPE of a component is never read, because it names a product and matching on it is a guess. The host asks for the events with `EXTRACT_VULNERABILITIES=true` in the module's environment and ignores a `vulnerability` line it did not ask for.
3. **One read.** With the option on, the document is read once; the inventory is stored as for any SBOM (not for an ephemeral run), and the statements go through the ordinary merge as findings, so the engine's idempotency, keys and close rules apply unchanged.
4. **Family `sbom-<format>`** (for example `sbom-cyclonedx`), also when the document states nothing now. It is its own family, so a rescan closes only what an earlier document stated (a statement dropped from the document closes its finding) and never a scanner's finding, and the matcher of phase E will have its own family (decision 8 of docs/35) and cannot be closed by this one.
5. **Severity:** of several ratings the one with the highest score is used, with its own vector; the label when it is known, else the band of the score (9.0, 7.0, 4.0), else unknown.
6. **A statement that names a component the document does not contain** is a record error (D13): the run ends completed-with-errors, nothing is closed on it, and the statement is not attached to anything.
7. XML ratings are read in both forms, `<score><base>7.5</base></score>` (the schema) and `<score>7.5</score>`.

**Why.** Removing the option took a choice from the operator that the design gave them, and it did so silently. Keeping it off by default keeps the position of C2: nothing in an SBOM becomes a finding unless someone asks.

**Tests.** The module (option off, unset, `0`, `false`: no events; on: one event per affected component, the best rating, aliases, no CPE; XML in both score forms), the host (events read only when asked, a statement with no id or component refused), the mapping of a statement to a finding, and the processor end to end (on: inventory and a finding; off or default: no finding; a rescan without the statement closes it and leaves a scanner's finding open; an unknown component is a record error).

## D132: the dependency graph is drawn from a server-built view, without Mermaid (2026-11-18)

**Context.** The Dependency graph tab printed the Mermaid source as text and asked the reader to draw it elsewhere; the tree and the edge list were text; the numbers it showed (a root counted as a direct dependency, "1 direct and 840 transitive" for an SBOM that states no dependency at all) came from three places that did not agree: a flag a module wrote, the edges, and the CLI.

**Decision (owner: draw it like Dependency-Track's graph, without Mermaid).**
1. **One view, built on the server** (`graph.BuildView`, `internal/graph/view.go`): every component as a node with one id, every dependency as an edge by id (duplicates, self edges and edges to a component the document lacks removed and counted), the depth of each component from the root by breadth-first search (cycles end), `direct` (depth 1) and transitive (deeper), the components no path reaches, and the open findings of each component by severity. The root is the declared one; without one it is the component nothing depends on that reaches the most, the smaller id on a tie, so the answer is the same on every call. The answer is deterministic (sorted nodes and edges).
2. **An inventory is not a graph.** A document with no dependency edges has `has_dependencies: false` and no direct or transitive counts; the UI says so instead of drawing a flat list.
3. **Inferred top.** Many generators (the Maven and npm CycloneDX plugins) list the dependencies of every component but none for the root. Then the components nothing depends on are placed under the root with edges marked `inferred`, `inferred_root` is true and the page says it. Nothing is inferred for a root that does state dependencies, nor for an inventory.
4. **`direct` is computed in one place.** The host (`readEvents`) sets each component's `Direct` from the same view, so the flag stored with a component, the web graph and `rampart sbom graph` agree. A module's own direct flag is no longer used (it could not know the root of a document that lists none).
5. **Findings per component** come from `ListPackageRisk` (PostgreSQL): the open findings of the asset and track of the SBOM, by purl without version, and by version when the scanner reported one, so two versions of a package in one tree do not share findings. A finding counts once however many occurrences it has.
6. **Mermaid is gone from the API and the UI.** The graph answer no longer carries `mermaid` or `tree`. `rampart sbom graph --format mermaid` stays as an export, now deterministic and with every syntax character of a label escaped (a name could inject a statement before).
7. **The drawing** (`web/src/routes/applications/graph/`) is SVG written for this screen, not React Flow (docs/13 section 1 names it): the data is a tree expanded from a DAG with open and close, which React Flow does not lay out, the library is not a dependency of the app, and a layout of our own is small, deterministic and unit tested. Left to right, a level to a column; a component is marked by the shape of its worst open finding (docs/13 section 6); the path from the root to the selected component is drawn in the accent colour and the rest recedes; a component reached by several paths is opened at its first appearance and is a pointer ("shown above") elsewhere, which keeps a shared subtree from exploding; at most 1,500 components are drawn. The same tree is available as an outline list for the keyboard and screen readers (WAI-ARIA tree: arrows, Right, Left, Enter), a search that opens the way to a component, a filter "only paths with open findings", and an inspector docked on the right (path from the application, who uses it, findings by band). No cards, shadows or pills; strings are in i18n.
8. The tab loads when it is opened (it was loading with the page).

**Tests.** Go: the view (diamond, inventory, root choice, bad edges, risk, inferred top, deterministic Mermaid with a hostile name), the API (shape, counts, risk per version) and the SQL (`ListPackageRisk` on PostgreSQL). Web: the model (index, visible tree, layout, path, search) and the tab (tree, keyboard, search, filter, list, no dependencies, inferred root, no SBOM, failure, axe in both views).

## D133: what the SBOM readers must emit for a graph, and the sibling repositories brought level (2026-11-18)

**Context.** The dependency graph (D132) is only as good as the edges and components the readers write, and the two sibling repositories (`Rampart-Aspm/sbom-parsers`, `Rampart-Aspm/parsers`) still held the earlier code: the Syft finding parser, no per-record error protocol, CycloneDX and SPDX readers from before D128.

**Decision.**
1. **SPDX** turns every relationship that states a dependency into an edge, whichever way round it is written, in one function (`edgeDirection`): `DEPENDS_ON`, `CONTAINS`, `DYNAMIC_LINK`, `STATIC_LINK` and the SPDX 3 spellings forward; `DEPENDENCY_OF`, `BUILD_`, `DEV_`, `OPTIONAL_`, `PROVIDED_`, `TEST_` and `RUNTIME_DEPENDENCY_OF`, and `CONTAINED_BY` reversed. A relationship about something else (`DEPENDENCY_MANIFEST_OF`, tooling) adds no edge. The same function serves JSON, tag-value and the SPDX 3 form.
2. **CycloneDX** reads components nested in components (JSON and XML), because a dependency can name one by its bom-ref and the edge would otherwise point at nothing.
3. **Where a document gives no data, the reader gives none.** A reader does not make up edges. The one inference that exists is made once, by the graph view, and is marked (D132).
4. **The sibling repositories** were brought level, uncommitted: `sbom-parsers` has `sbom-cyclonedx` and `sbom-spdx` as in this tree (the VDR option, nested components, the relationship types, SPDX refusing a document that is not SPDX), the new `sbom-syft` (Syft is an SBOM reader there, not a finding parser; the old `syft` module is removed), their YAML specs with `options`, and the README; `parsers` has the per-record error protocol (`RAMPART_RECORD_ERRORS`, four lines in each of the 13 `main.go`). The import paths are rewritten; the `.wasm` files are rebuilt from the same sources.

**Still open.** The `pkg/` copies of the domain and the fingerprint in the two repositories can drift from this tree (docs/34 F32): one shared module and a fingerprint golden test in each repository are not done.

## D134: the feed scheduler keeps syncing: per-feed due checks, retry, and no stop on a panic (2026-11-18)

**Context.** The owner asked to be sure the feeds keep syncing. Reading `RunScheduler` found four ways it could stop being true: (1) a panic in a round (or in the re-score that follows it) was not recovered, so it ended the process; (2) the start-up round was skipped when KEV had synced recently, and nothing else was looked at, so a feed switched on later, or one that had failed while KEV succeeded, waited a whole interval (6 hours) after a restart; (3) a failed feed was tried again only at the next interval; (4) `OnSynced` (re-key and re-score everything) ran after every round.

**Decision.**
1. The scheduler looks every `min(interval, 30 minutes)` (`feeds.checkEvery`, tests) and at start, and syncs only the feeds that are **due**, each judged on its own state (`feed_state`): never synced is due at once; last round failed is due at every check (that is the retry); succeeded is due when its interval has passed; syncing now is not due. A manual sync, and a one-feed round, are not scheduled rounds and do every feed they are asked for.
2. A round that panics is logged and the loop goes on; it stops only when its context ends.
3. The re-key and re-score run only when a check synced at least one feed (a check that finds everything fresh costs one read of the state and changes nothing).
4. One replica syncs at a time (the advisory lock, as before; the sync buttons use the same lock). A `syncing` row left by a process that died is turned into an error at the start of a round, as before.

**Tests (PostgreSQL).** The due rule feed by feed (never synced, fresh, failed, syncing, older than the interval, manual); the scheduler syncs on each interval and not on each check, stops with its context, retries a failure at the next check with an interval of an hour, does not fetch a feed again inside its interval, survives a panic in `OnSynced` and does not re-score on a check that synced nothing. The panic test was run without the recovery and fails, so it tests what it says.

**What an operator should watch.** `rampart_feed_syncs_total{status="success"}` per feed should rise at least once in two intervals, and the Feeds page shows the last sync of each feed. An alert on "no successful sync of a feed for 2 intervals plus an hour" is not shipped yet (docs/35 phase D).

## D135: Feeds in the sidebar, one CVE section for the whole product, evidence by kind, and a location the screens can read (2026-11-18)

**Context.** Four things the owner asked for or that were found while doing them.

**Decision.**
1. **Feeds is an item of the sidebar** (`/feeds`, between Policies and Integrations), not a tab of Integrations. Everyone signed in reads it; Sync is for an administrator (the feeds are global). The page follows docs/13 section 6: a sentence where there were tiles, a table divided by rules, the selected feed in a docked inspector with Sync and Test, no uppercase labels, no pills, every string in i18n. The tokens it used did not exist (`text-11`, `border-border`, `bg-surface-2`, palette colours); the same replacement was made in 16 other files.
2. **What the databases know about a CVE is one component** (`VulnerabilityDetails`), used by the Finding inspector and by the Application page (it was the Finding page only; the Application page opened a separate modal with the scanner's description and nothing else). It is grouped in the order an analyst asks: what it is, is it being exploited, how severe, the record, where to read more, where else it is found. The Application modal also shows the evidence and the compliance controls the finding counts against.
3. **Evidence is shown by kind** (`EvidenceSection`): a code scanner gives file, lines, function and snippet; a dependency scanner the manifest and the dependency path; a web scanner the address, method and parameter; an infrastructure scanner the resource and its type; a container scanner the image; the tool's own rating. Nothing is shown that the scanner did not give. The text of a secret is not stored (only its hash) and is never shown; the page says so, and says when the scanner found the credential live.
4. **A real contract bug:** the server sends a finding's `location` nested by kind (`{ code: {...}, package: {...} }`, `domain.Location`), while the screens read `location.purl` and `location.file_path` flat, so against the real server the location of every finding was empty (the mock sent it flat and hid it). `lib/location.ts` (`locationOf`, `whereText`) flattens it once, and every screen reads it through that.
5. **Logout** left the person on the same page: the cache was cleared before the session was set to "none", which detached the mounted bootstrap from the session. The session is set first, then the data of the person who left is removed. A test fails on the old order.

**Not done, in docs/34 section 10:** the link from the dependency graph to the findings of a package (item 14); the affected ranges per package and which source said what in the CVE section (item 15); properties a parser adds itself (item 16); and the rest of the hard-coded English in the screens (`ApplicationSBOMSection`, `InventoryRoute`, `GroupsView`, `SavedViewsBar`, `WorkflowRoute`, `IntegrationsRoute`, `ApplicationAttestSection`, `ParsersView`, `PoliciesRoute`, `ApplicationLicensesSection`, `VulnerabilitiesRoute`, `ApplicationRoute`: about 300 strings counted by a script).

## D137: why a feed is not run, how a stopped feed is noticed, and doc 33 corrected (2026-11-18)

**Context.** The Feeds page showed a feed as "enabled" or not with no reason, and the refusal of a sync said "(egress deny without a mirror)" for every feed, including one switched off with `enabled: false`. The "enabled" state was worked out in four copies of the same block in `internal/query/feeds.go`, separately from the rule the sync itself uses, so the page and the sync could disagree (OSV with no ecosystem looked enabled; NVD switched off in the server configuration looked enabled and then refused). And a feed that silently stops being tried failed nothing, so `RampartFeedSyncFailing` could not see it.

**Decision.**
1. **One reason per feed that is not run**, in the list (`disabled_reason`): `switched_off` (the ClusterFeed says `enabled: false`; its own switch wins over a mirror address), `egress_denied` (egress is deny and the feed has no mirror address), `no_ecosystem` (OSV runs only for the ecosystems named), `server_disabled` (the server's own configuration: `feeds.nvdDisabled`). The first two come from the ClusterFeed; the last two only the server knows, through `enrich.OnDemand.Why`, which applies the ClusterFeed to the configuration the way a round does. The four built-in blocks became one function.
2. **The refusal says the reason** (409 `feed-disabled`), and the page shows it, with what to change.
3. **A stopped feed is noticed.** The gauge `rampart_feed_last_success_seconds{feed}` is read from `feed_state` at the start of the scheduler and after every check, so a sync by another replica or before a restart counts. The chart's `RampartFeedStale` fires when it is older than `metrics.prometheusRule.feedStaleSeconds` (default 46800, two sync intervals and an hour; set it with `feeds.interval`).
4. **docs/33 carries a section 0** that corrects it against the code (docs/34 section 8, points 1 to 13); the sections it corrects have a note. docs/04 describes the real `ClusterFeed`.

**Tests.** The list gives the right reason for each case (a switch, egress deny with and without a mirror, the server's two reasons, an optional source); the refusal names the real reason and not the egress rule; `Why` for NVD, OSV (also with the ecosystems from the resource) and the feeds that cannot be off by configuration; the page shows each reason.

**Not done:** attribution (D8; the terms of each source are being checked), source precedence (D9), the GHSA and JVN sources (D7: the owner has not decided).

## D138: a worked scoring example that a test applies, and the risk-policy example of doc 04 corrected (2026-11-18)

**Context.** The owner asked for an example of one application together with every resource that controls its score. Writing it showed three things: (1) the `RiskPolicy` example in doc 04 was refused by the server (it used `vuln.epss.score`, `app.business_criticality`, `finding.reachability`, `env.internet_facing` and a `recomputeOn` key, none of which exists); (2) a policy is chosen per tenant, not per application, so only the application's own facts differ between two applications of a tenant (`policySpec`: the namespaced policy named `default`, else the first by name, else the cluster policy by the same rule, else the built-in one); (3) a first draft of the example's `ClusterFeed` was refused because `epss` needs a `url` (the optional sources do not).

**Decision.**
1. **The example is a file that is applied in a test**, `docs/examples/payments-scoring/` (one commented file per resource), with the scores and deadlines of doc 36 section 15 asserted against the real scoring and SLA code, including the two caps (`maxDays`, `kevDueDate`). Text that quotes numbers is checked by the code that computes them.
2. **The `RiskPolicy` block of doc 04 is replaced by one that compiles**, with the variables a `when` can read listed, and a test parses that block from the markdown, so it cannot go stale again.
3. **`ScanSource` is not in the example** (see D139).
4. **Recorded, not decided:** a tenant that wants one factor changed must restate all twelve and does not receive a factor added later (doc 36 section 15.4, point 3). A way to change a built-in factor by name is an option for the owner; nothing is built.

**Tests.** `TestPaymentsScoringExample` (every document is accepted; three findings score as stated under both policies; the two SLA caps) and `TestRiskPolicyExampleOfDocs04IsAccepted` in `internal/config/apply`.

## D139: `ScanSource` is to be retired, and three roles need a new home first (2026-11-18)

**Context.** While writing the scoring example (D138) the owner said that `ScanSource` is not needed anywhere in the system, because the analyzers (D128: `SBOMAnalyzer`, `ClusterSBOMAnalyzer`, `ExternalAnalyzer`) took its role, and Dependency-Track, which it could point at, is gone. Reading the code for what depends on it (doc 36 section 15.5) shows the analyzers take over only one of its roles, pulling findings in (`connector`, `schedule`, `secretRef`, `dependencyTrack`), and that the analyzers are not built yet (docs/34 F26: nothing matches components to vulnerabilities; F30: the analyzer CRDs have no controller).

**Decision.** `ScanSource` is retired from the product. It is **not deleted in this change**: the working tree holds a large uncommitted change, and the kind carries three things that are not about where findings come from and that nothing else holds:
1. **CI trust** (`trustRules`, the `source_trust` table, the OIDC token exchange of D-entry "Trust Rules"): without it a CI job cannot authenticate to upload.
2. **Tracked branches** (`trackedRefs`): which branches are real and which runs are ephemeral (D10).
3. **What a report may close** (`ingestionPolicy`: `closeOldFindings`, `closeScope`, `maxClosePercent`, `minimumSeverity`, `acceptedFormats`).

**Needed from the owner before any code is removed:** where each of the three lives. Settled by D140 for the branches (the application names its branch); proposed in D140 for the other two.

**Not done:** no code, CRD, migration or chart change. When the three homes are decided: add them, migrate stored `scan_source` rows, remove the kind from `deploy/crds`, the chart, the operator, the apply library and `internal/domain/scansource.go`, and the `dependencyTrack` leftover with it (docs/34 phase F).

## D140: an application is one branch, with a `type`; `ScanSource` is replaced by fields on `Application` and `Tenant` (2026-11-18)

**Context.** Doc 36 section 14 had kept open whether every branch is an application. The owner's answer is that it is, and that it has been the rule from the start. The owner also proposed a `type`, the kind of thing that is watched (a repository, a machine, and so on). A first reading of it was too narrow (a switch between two field sets, with one value built); doc 36 section 16.1 states what the owner meant. This closes the question of D139 for one of the three roles of `ScanSource`.

**Decision.**
1. **An application is one branch of one repository.** It names `repository` and `branch` (flat, one of each) and carries its own `environment`. D10 (an asset is the repository, branches are tracks) and D56 (selectors match the repository address) are amended for applications of this kind: the asset key includes the branch, and selectors match the repository and the branch. An application with no `type` keeps today's behaviour, so no existing resource breaks.
2. **`type` is the kind of thing that is watched**: `repository`, `machine`, `image`, `url` (doc 36 section 16.1). It decides what names the application (`repository` and `branch`; `machine.hostname`; `image.repository`; `url.base`), which asset type it claims (D10), what can report on it and what its page shows. It does not decide the score: one risk policy serves every type, and a factor may read `app.type`. `repository` is the only value the CRD accepts until the others are built; the others are refused with a reason, as workload selectors are in D56. The owner's word `machine` is kept and maps to the `host` asset type inside; `node` is not used because the dependency graph calls a component a node. A branch is the version of a repository, so the type is `repository` and `branch` is a required field of it.
3. **The score reads the environment from the application**: `app.environment` and `app.type` join the variables of a risk policy; the built-in `PRODUCTION_ENV` reads `app.environment == "production"` instead of the branch name. `environment` has no default, so the score of an existing application does not change until its resource says one.
4. **`ScanSource` is replaced, not kept.** `trackedRefs` is dropped (the application names its branch); `ingestionPolicy` becomes `Application.spec.ingestion`; `trustRules` become `Tenant.spec.ciTrust` (proposed: an administrator's decision, per repository, so not on a team's application). Items 1, 2 and 3 are the owner's decision; the homes in item 4 for `ingestion` and `ciTrust` are my proposal until the owner confirms.

**Progress.** AB1 is done (docs/35): the Application resource, the score's variables, the environment, the settings tab. AB2 to AB6 are not. The slices are in docs/35 (AB1 to AB6); the first two make the rule real and let the guarded example of D138 be rewritten as doc 36 section 16 shows. Doc 36 section 16 lists the defaults taken (exact branch names only, no default environment, how an unclaimed branch is handled, the grouping of applications by repository).

## D141: Rampart is blind about parsers: no parser is compiled in, embedded or named in the server (2026-11-19)

**Context.** D127 principle 1 says that no parser is privileged because it is compiled into the binary, and docs/35 section 0 (owner, 2026-11-18) says the shipped modules reach the process from outside. D127 itself still embedded 20 manifests with `go:embed` "for out-of-the-box operation in Docker Compose and single-binary environments", and gave them the ids `builtin:<name>`, which also reserved their names. The owner confirmed the intent again on 2026-11-19: any parser, WASM, Lua or SBOM reader, can be supplied from outside, and the server knows none of them.

**Decision.**
1. **Nothing is embedded.** `internal/config/parsers` and `internal/config/sbomparsers` are removed. The server knows no parser by name.
2. **A parser reaches the server as a resource, in one of two ways.** (a) Through the control plane: `ClusterParser`, and the new `ClusterSBOMParser` (a reconciler, and `rampart apply`). Both are kept in the cluster's parser table; a `ClusterSBOMParser` is kept as the whole resource, so it is told apart from a report parser by its kind and not by its name. (b) From a directory of manifests, `RAMPART_PARSERS_DIR`, read at start: for a deployment with no control plane (Compose, one binary) and for tests. It is read the way `RAMPART_WASM_DIR` is for the modules the manifests name.
3. **One table, two kinds, so two name spaces.** A `ClusterSBOMParser` is named `sbom-*`; a `ClusterParser` may not be.
4. **One constructor builds every installed WASM or Lua parser** (`integrations.NewInstalledParser`), from the whole resource or from its spec alone. Its id is `builtin:<name>`, the form stored in runs and read by the compliance report (`CategoriesOf`) and the gate (`runMatches`). It says "installed for the whole cluster", not "compiled in".
5. **A name is resolved in this order: the registry, then the cluster's parsers, then the tenant's.** A name an administrator installed for the cluster is reserved: a tenant's mapping parser of the same name cannot take its uploads. The compiled-in copies gave the same protection; the order of D127 ("tenant before cluster") was not what the code did.
6. **The start-up module check reads the digest table**, since the server no longer knows which modules to expect: every module the table lists must be present and match. `GET /api/v1/parsers` lists what is installed.

**Found while doing it, hidden until then by the compiled-in copy.**
- The control plane keeps a `ClusterParser`'s spec alone. The WASM and Lua runtimes read a whole resource (`metadata.name`, `spec`), so a parser installed through the operator was refused ("source.oci or source.file is required", "script is required") and never ran. Every upload was served by the compiled-in copy. `NewInstalledParser` now wraps a spec alone into the resource before it reaches the runtime.
- A `ClusterSBOMParser` had a CRD, a chart template and RBAC, and no reconciler: the SBOM readers reached the server only through the embed.
- The adapter dropped the loader's error and kept a typed nil in a non-nil interface, so a parser that failed to build panicked at the first `Parse`. The error is kept and said ("runtime not loaded for builtin:x: ...").

**Consequences.**
- An administrator's own cluster parser now has the id `builtin:<name>` for new runs (it was `lua:<name>` or `wasm:<name>`), and the support level `builtin`, which the Integrations page words "Built in". Runs already stored keep their old id. Nothing reads the `lua:` or `wasm:` prefix except the name matching, which still accepts both.
- The start-up check no longer catches a parser installed with a module the table does not list; that parser is refused when it is used (the store checks the digest), so it never runs unverified.
- A server with nothing installed answers an upload with "Unknown parser ... Available parsers:" and an empty list. A Compose or one-binary deployment must set `RAMPART_PARSERS_DIR` or apply the resources.
- A `ClusterParser` with `runtime: native` resolves only against what the registry holds; no manifest of the project uses it.

**How the defaults are delivered now.**
- **Kubernetes.** Two charts own the default resources, each next to the code of its parsers: `rampart-parsers` (13 WASM and 4 Lua `ClusterParser`) in the parsers repository and `rampart-sbom-parsers` (3 `ClusterSBOMParser`) in the sbom-parsers repository. Rampart's chart depends on both (aliases `parsers` and `sbomParsers`, on by default), so `parsers.defaultParsers.*` and `sbomParsers.defaultSBOMParsers.*` are the values they always were. The chart renders every resource with exactly the spec of its manifest; each repository's CI checks that, and the manifests in `internal/testdata/parsers` are the same files.
- **Compose and one binary.** `RAMPART_PARSERS_DIR` and `RAMPART_WASM_DIR`, filled by `deploy/compose/fetch-parsers.sh`.
- **Tests.** Fixtures are in `internal/testdata`. The WASM modules are built from the two repositories by `hack/test-modules.sh` (CI: `.github/actions/parser-modules`, refs pinned in `.github/parser-modules.env`).

**Found on the way: the chart's `detect` was older than the embedded one.** All 20 resources the chart rendered had the first, simple `detect` (filenames and probes), while the embedded manifests, which the tests check and which the server used, have the scored one (`rules`, `filenameWeight`, `reject`). Removing the embed without replacing the chart's copy would have changed detection for every Helm install. The chart's copy is now the embedded manifests, moved to the parsers repositories (without `source.file`, a path of this repository's layout).

**Also fixed.** `templates/clustersbomanalyzer.yaml` used `default true`, which turns an explicit `false` into `true`: `sbomAnalyzer.sources.osv: false` could not be set (nor `minConfidence: 0`). Each key is now looked up by name. The matcher is still not wired (docs/34 F26, F30); this only makes the values mean what they say.

**Not done.**
- The two charts must be published (`chart-v0.1.0` tags in the two repositories, public packages) before this repository's CI can run `helm dependency update`; and the parser repositories hold uncommitted changes (the record-error support in 13 WASM parsers, the rewritten CycloneDX and SPDX readers, `syft` renamed `sbom-syft`) that Rampart's tests need. The refs in `.github/parser-modules.env` are `main` until then; pin them to commits.
- No Dockerfile step puts parsers in the image: Compose reads the two directories, and Kubernetes gets the modules as image volumes (`parsers.modules`).
- The tenant-scoped `SBOMParser` has no controller.
- The Integrations page words every cluster-installed parser "Built in"; "Installed for the cluster" would be accurate.
- `internal/targets/runner.go` applies `/etc/rampart/resources.yaml`, while the Compose quick start mounts a directory `/etc/rampart/resources/`, so its `default-resources.yaml` is not applied in the container (seen, not fixed).

## D142: Sonatype OSS Index is an external analyzer, not a feed (2026-11-19)

**Context.** The owner asked for Sonatype OSS Index as a gRPC analyzer, in a repository of its own with a Helm chart, shown in the UI, as a cluster and a namespaced resource. docs/30 says the commercial sources of Dependency-Track (OSS Index, Snyk, VulnDB) are lost "unless a feed brings them"; docs/33 section 1.1 says scanners are never feeds; docs/34 noted the two disagree. The owner's instruction is to do what Dependency-Track does, whatever the docs say.

**Decision.** It is an analyzer. A feed (D88, D89) brings bulk data that is downloaded and keyed by vulnerability id; OSS Index is a service that is asked about packages (`POST /api/v3/component-report`, at most 128 package URLs per request: the service answers 400 above that) and has no data set to download that this work found. It is attached as a `ClusterExternalAnalyzer` or an `ExternalAnalyzer` (the same fields). It lives in its own repository, `sonatype-analyzer` (service, image, chart, CI), outside this one; the contract it implements, `pkg/api/analyzer/v1`, is owned here and copied there.

**How it behaves, taken from Dependency-Track's source and checked against the real service.** The package URL is sent without qualifiers and subpath (with `?type=jar` the service answers no vulnerabilities for log4j-core 2.14.1, which has 7), answers are matched by a key that ignores what the service rewrites in the coordinate it echoes, only the types Dependency-Track asks about are looked up (the others are counted, not guessed), a token that starts `sonatype_pat_` is a Bearer token and any other is basic authentication, answers are cached per package. It differs in one place on purpose: a batch that fails after its retries fails the whole call and returns nothing, where Dependency-Track's analyzer returns an empty list, so a caller cannot read the silence as "fixed".

**What Dependency-Track does around its analyzers, which is the caller's side (not built here).** An analysis starts on a BOM upload, on a manual request, and on a schedule: every 60 s it looks for projects last analysed longer ago than the maximum age (24 h by default), oldest first, at most 50 in flight. One call per project per analyzer per run, with the whole BOM. Findings are attributed to the analyzer that reported them, are removed when it stops reporting them, and are kept when it fails. So an analyzer is called on upload and again daily, not once and not continuously.

**Verified.** With a Sonatype Guide personal access token, on 2026-11-19: `https://api.guide.sonatype.com/api/v3/component-report` answers 200 in OSS Index's format with a Bearer token and 401 without; Log4Shell, Lodash's command injection and the others are found through the built image; the chart renders both scopes with a resource the CRDs accept and refuses seven configurations that cannot work (an empty `networkPolicy.ingressFrom` among them: Helm's `required` accepts an empty list, which a NetworkPolicy reads as "from anywhere").

**Not verified.** Basic authentication with a real OSS Index account; the rate limits (no header was seen); the OSS Index terms of service, which could not be read, so use inside a commercial product is not checked; which package types the service supports (Dependency-Track's list is used). OSS Index is moving to Sonatype Guide; the original `ossindex.sonatype.org` still answered 401 to a made-up token.

**Not built when this was written, and built since.** Rampart had no controller, storage, API, page or caller for external analyzers, so the analyzer did not show in the UI and nothing called it. D143 builds all of it, in the order this paragraph listed.

## D143: Analyzers run like Dependency-Track's, the matcher and the services alike (2026-11-19)

**Context.** After D142 the owner asked that analyzers work the way Dependency-Track's do (analysis on upload, on request and on a schedule; findings attributed to the analyzer; a failed analyzer never closes findings; retries; states), for both kinds: the matcher inside
the server (`SBOMAnalyzer`, `ClusterSBOMAnalyzer`) and a service called over gRPC (`ExternalAnalyzer`, `ClusterExternalAnalyzer`, such as `sonatype-analyzer`); with a way to test an analyzer, to see its events (did it work, did it fail), and an Analyzers tab in the UI with its kinds.
Dependency-Track's behaviour was taken from its own source and documentation, as in D142; the full description and the checks are in [docs/38](38-analyzers.md).

**Decisions, and why.**

1. **One job per SBOM and analyzer, for every analyzer that is on, with the whole SBOM.** Dependency-Track does the same (a workflow step per analyzer; "analysis of individual components is not supported"). One analyzer answering for all would hide the others; one call per component would cost the service a request each.
2. **An analysis is an ingest run.** The answer is merged through the existing pipeline (`Processor.Process` with a parser that yields the answer's findings and `ScannerOverride = analyzer:<name>`): merge, close, the mass-close guard (D22), scoring and notifications are not written twice. The run is created
   only after the analyzer answered, so a failure leaves no run and reaches the merge with nothing. The scanner family `analyzer:<name>` (`analyzer:<namespace>/<name>` for a tenant's) is the attribution: the close scope is (source, family, asset, track), so an analyzer closes only what it reported.
3. **Failure is not silence.** A failed call returns an error and the merge is not reached (nothing is closed); five attempts with River's backoff; the last failure raises an in-app notification `analyzer_error`. An empty answer without an error is a success, and the mass-close guard holds a close that would remove more than half of the findings and more than 20: this is what protects against an
   analyzer whose own data is down. Dependency-Track's OSS Index analyzer returns an empty list when its batch fails (D142), which is what this design refuses to copy.
4. **Claim in the database, not River's unique jobs.** `sbom_analysis` has a row per (SBOM, analyzer); a claim succeeds only if none is pending or running (a row older than an hour is stale and freed). River keeps a finished job as a duplicate until its cleaner removes it, which would refuse a person who asks again.
   The row is also the state (`pending`, `running`, `completed`, `failed`, `timed_out`, `cancelled`, `not_applicable`) and what the sweep reads.
5. **The sweep: every 60 s, `analysis.maxAge` 24 h, `analysis.maxInFlight` 50, oldest first, never-analysed first.** The numbers are Dependency-Track's. It reads every tenant, so it runs on the system role with an advisory lock (one replica), like the SLA and ticket sweepers. A failed analysis is tried again by the sweep after an hour, not every minute.
   An SBOMAnalyzer's `schedule` is a cron expression (UTC, five fields; `internal/cron`): the SBOM is due when the schedule has fired since its last analysis. It is validated when the resource is accepted. No cron library was added: the reader is small and tested.
6. **Only the newest SBOM of an application and track is analysed.** An older one would reopen what the newer one dropped; it settles `cancelled`.
7. **Storage and refusals.** Migration 52 adds the two kinds to `cluster_policy` and `policy_object` and the `analyzer_event` table; migration 53 adds `sbom_analysis`. Last-valid-spec semantics as for the other policy objects. A spec the server cannot honour is refused with its reason, not accepted and ignored: `protocol: http` (no client),
   `tls.caSecretRef` and `auth.secretRef` (the server cannot read a Secret to use them), a tenant's `endpoint` (SSRF: a tenant may name only a `service`), a `timeoutSeconds` over 600, a bad cron expression. `tls.insecure: false` is honoured (TLS against the system roots); `timeoutSeconds` is honoured.
8. **Test and events.** Test is an action of an administrator: a service is asked for health and metadata (no component is sent, nothing is changed); the matcher is asked whether advisory data is loaded. Every test and every analysis is an event of the tenant that caused it, newest 200 kept per analyzer. This answers "does it work" without waiting for an upload.
9. **The page.** Ingestion gets a third tab, Analyzers: by kind (service, built-in matcher), scope, address or engine, status with the reason a resource was refused, the last result, Test, Analyze every SBOM, and the history. It says plainly which matcher settings do not change the matching yet.
10. **Rollout.** `analysis.enabled` (default true) is the switch. The built-in matcher stays off by default in the chart, so an upgrade analyses nothing until an analyzer is turned on; when one is, every existing SBOM is analysed 50 at a time and opens findings for applications that had none.

**Verified.** The service tests on the real merge engine and again on PostgreSQL with row-level security (the close queries match on the scan source: the doubt before this work), including a mutation check that a failure continuing to the merge fails four tests; the claim, due and in-flight queries; the matcher over `vulnerability_affected`
(which found that an advisory with a CVSS score and no severity word was graded `unknown`: fixed); the cron reader; the routes with their roles; the page with accessibility checks; the chart render and its schema; the analyzer service with a 5 MiB request (it refused one: its receive limit was gRPC's 4 MiB, and is now 64 MiB, as Rampart's client allows).

**Not verified.** The Sonatype analyzer called by a running Rampart in a cluster (no cluster was touched); River's retry backoff and priorities against a live River; the page in a browser (tests only); the version ordering of ecosystems beyond dotted numbers.

**Known limits, recorded rather than hidden.** The matcher reads `engine`, `rules.minConfidence`, `rules.includePreRelease` and `sources` but does not use them (one matcher, exact matching); it uses `rules.matchDirectOnly` and `schedule`. Severity comes from the CVSS score (the table keeps no severity word). Per-application roles are not consulted by the asset route.
There is no "analyze again" button on an application's page (the route exists). `openapi.json` documents only a small part of the API and was not extended. The in-memory store does not run analyses. `examples/external-analyzer` keeps gRPC's default 4 MiB receive limit.

## D144: The smaller decisions of the analyzer work, with their reasons (2026-11-19)

D143 records the design. These are the choices made while building it that D143 does not give, each with why. Where a choice is a limit, it is also listed in docs/38 section 9.

**Storage and naming**

| Decision | Why |
|---|---|
| Migration 53 (`sbom_analysis`) is a separate file; 52 was not edited. | Migration 52 may already be applied to a development database; goose skips a file it has run, so an edit would leave that database without the table. `database.minSchemaVersion` and `CurrentExpectedSchemaVersion` move to 53. |
| The analyzers are kept in the existing `cluster_policy` and `policy_object` tables, with their `kind` check widened, not in tables of their own. | They are policy objects with the same last-valid-spec rule (`applied_spec`, `compiled_ok`, `compile_error`): an edit that is refused keeps the spec in force and shows the reason. One mechanism, not two. |
| Two sets of kind names: `external_analyzer` and `sbom_analyzer` in the store, `external` and `sbom` (with scope `cluster` or `tenant`) in the API, the events and `sbom_analysis`. | The store kinds sit beside `risk`, `sla`, `parser`; the API names are what a person reads. `AnalyzerRef` is the one value that carries the API form everywhere above the store. |
| The scanner family of a tenant's analyzer is `analyzer:<namespace>/<name>`; a cluster one's is `analyzer:<name>`. | A cluster analyzer and a tenant's can share a name in one tenant. Without the namespace they would share a close scope, and one would close the other's findings. |
| `analyzer_event` and `sbom_analysis` carry row-level security by tenant; an event belongs to the tenant that caused it; the newest 200 events of each analyzer are kept. | A tenant must not read another's test results or analyses, which name SBOMs and findings. Cluster analyzers are seen by all, but what happened to them for one tenant is that tenant's. 200 is enough to see a pattern and bounded. |

**Who may do what**

| Decision | Why |
|---|---|
| Listing and reading the history need only a signed-in user (viewer for the history); Test and "Analyze every SBOM" need an administrator; "analyze one asset" needs the triager role. | Seeing whether an analyzer works helps everyone who reads a finding. Test makes the server dial an address, and analysing every SBOM queues work for the whole tenant, so both are an administrator's. Analysing one asset is what an upload already lets a triager do. |
| The list shows the address of a cluster analyzer to every user of the tenant. | The address is an in-cluster Service name, not a secret, and a person who sees "Could not reach …" needs it to act. A secret never appears: `auth.secretRef` is refused. |
| A tenant's `ExternalAnalyzer` may name only a `service`. | An `endpoint` would let a tenant make the server call any address (SSRF; docs/34 F29). |
| `POST /api/v1/assets/{id}/analyze` does not consult per-application roles. | The tenant role is enough to upload an SBOM for the asset; narrowing it by application is the access model's work, not this feature's. Recorded as a limit. |

**Test**

| Decision | Why |
|---|---|
| A test of a service calls `HealthCheck` and `GetMetadata` and sends no component. | A test is an answer to "is it up", and a component could cost money (Sonatype) or change nothing useful. |
| A test is cut off at 30 seconds, whatever the spec's timeout. | The spec's timeout (up to 600 s) is for a job; a person waiting on a button needs an answer. |
| Every test is recorded as an event, successful or not, with the person who ran it. | An analyzer that fails its test is exactly what the history is for. |
| The matcher's test checks that advisory data is loaded (the count of affected ranges and ecosystems), and says so when the OSV feed has not synced. | A matcher with no data matches nothing and looks healthy: this makes the silence visible. |

**Running**

| Decision | Why |
|---|---|
| Analyses run on their own queue, `analysis`, with 10 workers and a 20-minute job timeout. | A slow or down analyzer holds one of its workers, never an ingest worker (the reason the notification queue is separate, D97). 20 minutes is the longest analyzer call (10) and the merge after it. |
| River priority: manual 1, upload 2, scheduled 3. | River has four priorities and serves 1 first; this keeps Dependency-Track's order (manual 75, upload 50, scheduled 0). |
| The sweep tries a failed or timed-out analysis again after one hour (`FailedRetryAfter`), not at the next minute. | A completed analysis has a time to wait (24 h); a failed one has none, and would be queued every minute against an analyzer that is down. |
| A pending or running analysis older than an hour is stale and can be claimed again. | A worker that died leaves its row behind; without this the SBOM would never be analysed by that analyzer again. |
| An analysis creates its ingest run only after the analyzer answered. | A failed call must reach no merge and leave no run in the Ingest runs list; the failure is in the event and in the analysis record. |
| The trigger is a hook after `SaveSBOM` (`ingest.AnalysisTrigger`), and a failure to queue is logged, not returned. | An upload must not fail because the queue is down; the scheduled sweep finds the SBOM. A parse job that is retried stores the SBOM again and queues again: the older one is `cancelled` as replaced. |
| The service is built twice in the runner: on the application role for uploads, requests and the worker, on the system role for the sweep only. | The first respects row-level security per tenant; the sweep must see every tenant, which only the system role may. Without `database.systemUrl` the sweep is not started and the log says why (as for the ticket sweeper). |
| The finding's package (purl, name, installed version) is filled in from the component the analyzer named by reference. | The contract's `affected_component_ref` returns the reference it was given, and the client stores it in the package's purl field. Without this the finding would carry a reference where the identity of a finding needs the package. |
| The client sends and accepts messages up to 64 MiB; the Sonatype analyzer's receive limit was raised to match. | A whole SBOM in one call is more than gRPC's 4 MiB default (25 000 components are about 8 MiB); the analyzer refused one in a test. |
| The cron reader is written here (`internal/cron`); it reads numbers, `*`, ranges, lists, steps and five macros, in UTC; names (`mon`, `jan`) are refused. Day of month and day of week are "either matches" when both are set. | No cron library is in the module and none was added for forty lines of logic; refusing what it cannot read (rather than guessing) is the rule of D143 item 7; "either matches" is Vixie cron's rule, which operators know. |
| `analysis.enabled` defaults to `true`, while the chart's built-in matcher defaults to off. | The switch is for the whole mechanism; what makes an upgrade quiet is that no analyzer is on until the operator turns one on. |

**The matcher**

| Decision | Why |
|---|---|
| `engine`, `rules.minConfidence`, `rules.includePreRelease` and `sources` are accepted and not used; `rules.matchDirectOnly` and `schedule` are used. | The first four are in every resource the chart creates with their CRD defaults, so refusing them would refuse the default resource. They cannot change the result today: there is one matcher and a match is exact. (`tls.caSecretRef` and `auth.secretRef` are refused because accepting them would silently drop a security setting.) The page, the chart's comments and docs/37 say which is which. |
| A pre-release version is not filtered out by default. | The CRD default `includePreRelease: false` would read as "skip pre-release components", which hides vulnerabilities in them with no sign. Doing nothing is the lesser silent loss, and it is stated. |
| A range with `last_affected` ends at an affected version; a `VERSIONS` row lists exact versions. A withdrawn advisory is left out. | These are OSV's own meanings; `vulnerability_affected` stores them as given. |
| An advisory with no severity word is graded by its CVSS score; with no score it is `unknown`, not `info`. | The `vulnerability` table keeps a score and no word. `info` would say "harmless" about something that is only unscored. A test found that `unknown` (what an empty word parses to) was not being graded at all: fixed. |

**The page**

| Decision | Why |
|---|---|
| The Analyzers are a third tab of Ingestion, next to Ingest runs and Parsers & Formats, not a new place in the navigation. | The owner asked for a tab; analyzers belong beside the readers of reports. |
| The list shows plain words (Service, Built-in matcher, Ready, Switched off, Refused), no coloured pills; a failure is shown by text with an icon, in the red the Feeds page uses for errors. | The design rule: colour is for risk, and state is said in words. |
| A button an administrator alone may press is shown disabled with the reason beside it, not hidden. | A reader needs to know the action exists and who may do it. |
| "Analyze every SBOM" is disabled for an analyzer that is switched off or refused. | The server would queue nothing; the page says why instead of answering "0 queued". |
| The inspector says that engine, minimum confidence, advisory sources and pre-release do not change what the matcher matches yet. | A page that shows a setting implies it works. |
| The history lists tests and analyses together, newest first, in one phrase style ("Test worked", "Analysis failed"), with who and how long. | One list answers "did it work lately", whichever way it was started. |

**What was left alone**

| Decision | Why |
|---|---|
| `openapi.json` was not extended. | It documents findings, bulk and gate only; the parsers, feeds and every other route are missing from it too. Extending it for these five alone would make it look complete when it is not. |
| The in-memory store (no PostgreSQL) does not run analyses; the server starts them only with a database. | River, the claim table and the sweep are PostgreSQL's; a second implementation would test the copy, not the thing. The in-memory store implements the store interfaces so that the service is tested on the real merge engine. |
| `examples/external-analyzer` keeps the default 4 MiB receive limit. | It is a sample with two toy rules; the limit is noted (docs/38) rather than changed there. |
| There is no "analyze again" button on an application's page yet. | The route exists; the application page has its own design work. |

