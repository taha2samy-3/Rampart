# 12 — Database schema (PostgreSQL 16+)

Sketch of the v1 schema. Final DDL lives in `internal/store/migrations` (goose). Types are abbreviated; every tenant table has RLS enabled.

> **Deltas required by [16-implementation-decisions.md](16-implementation-decisions.md).** The sketch below predates the review. Apply these changes when writing the first migration:
>
> | Change | Decision |
> |---|---|
> | IDs generated in Go; remove `default uuidv7()` | D5 |
> | RLS predicate uses `nullif(current_setting('app.tenant_id', true), '')::uuid`; four database roles | D4 |
> | `app_user` becomes global `(issuer, subject)`; add `tenant_member`, `session`, `identity_provider`, `local_admin`, `secret_material` | D1, D3, D8 |
> | `asset.application_id` nullable; add `asset_version`; image key is `registry/repository` | D10 |
> | `occurrence` is no longer time-partitioned: unique `(tenant_id, finding_id, scan_source_id, occurrence_key)`, columns `first_seen`, `last_seen`, `last_ingest_run_id`, `seen_count`, `present`, `asset_id`, `track`, `asset_version`; large `raw` in object storage | D12, D28 |
> | Drop `finding_source` | D12 |
> | `occurrence_staging` renamed `ingest_staging`; deleted per run, never truncated; no RLS | D13 |
> | `finding` gains `track`, `detection`, `previous_state`, `content_hash`, `weak_fingerprint`, `correlation_key` (non-unique, display only), `kev`, `epss_bucket`, `fix_available`, `hierarchy_path`, `environment_kind`; loses `verified`, `source_count` | D11, D18, D24, D28 |
> | Add `ingest_run_scope`, `ingest_run_result` (ephemeral runs), `finding_key_alias`; `ingest_run.crd_uid` unique; `ingest_run.linked_run_id` | D2, D10, D11, D23 |
> | Add tenant-scoped `rule_local`, `vulnerability_local`, `vulnerability_alias_local`; global tables written only by feed sync | D19 |
> | Config tables keyed by `(tenant_id, kind, namespace, name)` | D21 |
> | Add `action_ledger`, `tenant_queue_limit` | D25 |
> | `api_token.scan_source_id` optional | D17 |
> | All secondary indexes start with `tenant_id`; published filter and sort matrix decides the index set | D28 |
> | `finding.asset_id` and `finding.application_id` lose their foreign keys | D36 |
> | `ingest_run.holds_secrets`, `ingest_run.report_purged_at`; retention indexes (migration 16) | D53 |
> | `application.compensating_controls`; ingest-made applications are `managed_by = none` (17) | D55 |
> | `application.selectors`, `application.rescore_needed` (18) | D56 |
> | `finding.lineage_key` (19) | D57 |
> | `finding.owner` (20) | D59 |
> | `risk_acceptance_proof`, insert-only for the application role (21) | D60 |
>
> From schema version 6 on, each decision in 16 names its migration; `internal/store/migrations` is the DDL.

## Conventions

- `id uuid primary key default uuidv7()` (extension or app-generated).
- `tenant_id uuid not null` leads every unique index and most secondary indexes.
- RLS: `create policy tenant_isolation on <t> using (tenant_id = current_setting('app.tenant_id')::uuid)` with `force row level security`. The application role owns no tables.
- `jsonb` for typed-by-category payloads (`location`, `attributes`, `risk_factors`); queried fields are promoted to columns.
- Enums are `text` with `check` constraints so adding a value is a cheap migration.
- Partitioned tables: `occurrence`, `finding_event`, `audit_event`, `trend_daily` by month (range on time).
- No foreign keys from partitioned high-volume tables to each other across partitions except `finding_id`; integrity is enforced by the merge job.

## Global (not tenant-scoped, read-only to tenants)

```sql
vulnerability (
  id text primary key,                 -- canonical: CVE-…, else GHSA-…, else OSV id
  aliases text[] not null default '{}',
  summary text, description text,
  cwes int[] not null default '{}',
  cvss jsonb not null default '[]',    -- [{version, vector, score, source}]
  cvss_best_score numeric(3,1), cvss_best_vector text,
  epss_score real, epss_percentile real, epss_date date,
  kev_date_added date, kev_due_date date, kev_ransomware boolean,
  ssvc jsonb, exploit_maturity text,
  published timestamptz, modified timestamptz,
  affected jsonb, fixed_versions jsonb, references jsonb,
  source_payloads jsonb, updated_at timestamptz not null
);
create index on vulnerability using gin (aliases);

vulnerability_alias (alias text primary key, vulnerability_id text not null);   -- alias graph lookups

weakness (id int primary key, name text, abstraction text, parents int[], top25_rank int, description text);

taxonomy (id text primary key, name text, version text, kind text);
taxon (taxonomy_id text, id text, name text, parent_id text, primary key (taxonomy_id, id));
taxon_mapping (taxonomy_id text, taxon_id text, key_type text, key text,        -- key_type: cwe | rule | control
               primary key (taxonomy_id, taxon_id, key_type, key));

rule (scanner_family text, rule_id text, name text, description text, help_uri text,
      default_severity text, cwes int[], category text, tags text[], primary key (scanner_family, rule_id));

feed_state (feed text primary key, cursor text, last_sync timestamptz, records bigint, status text, error text);
```

## Tenancy, identity, access

```sql
tenant (id, slug text unique, display_name text, k8s_namespace text, settings jsonb, quotas jsonb, created_at);

app_user (id, tenant_id, subject text, email text, display_name text, status text, last_login timestamptz,
          unique (tenant_id, subject));
team (id, tenant_id, name text, external_id text, unique (tenant_id, name));
team_member (tenant_id, team_id, user_id, primary key (team_id, user_id));

role_binding (id, tenant_id, principal_type text, principal_id uuid, role text,
              scope_type text, scope_id uuid,           -- tenant | hierarchy_node | application
              managed_by text, crd_ref jsonb);
api_token (id, tenant_id, prefix text, hash bytea, principal_type text, principal_id uuid,
           scopes text[], expires_at, last_used_at, created_by, revoked_at);

audit_event (id, tenant_id, at timestamptz, actor jsonb, action text, resource_type text, resource_id text,
             before jsonb, after jsonb, ip inet, user_agent text, request_id text)
  partition by range (at);                               -- insert-only grants
```

## Inventory

```sql
hierarchy_node (id, tenant_id, parent_id, name text, path ltree, tags text[], metadata jsonb,
                unique (tenant_id, path));
create index on hierarchy_node using gist (path);

application (id, tenant_id, hierarchy_node_id, slug text, name text, description text,
             business_criticality text, internet_facing boolean, data_classification text[],
             compliance_scope text[], compensating_controls text[], lifecycle text,
             owners jsonb, tags text[], managed_by text, crd_ref jsonb, version int,
             unique (tenant_id, slug));
service     (id, tenant_id, application_id, name text, kind text, owners jsonb, tags text[],
             unique (tenant_id, application_id, name));
environment (id, tenant_id, application_id, name text, kind text, internet_facing boolean, tags text[],
             unique (tenant_id, application_id, name));

asset (id, tenant_id, application_id, service_id, environment_id,
       type text, key text, display_name text, attributes jsonb, owners jsonb, tags text[],
       active boolean not null default true, first_seen timestamptz, last_seen timestamptz,
       external_refs jsonb,                               -- e.g. {"dtrack": {"connector": …, "project_uuid": …}}
       unique (tenant_id, type, key));
create index on asset (tenant_id, application_id);
create index on asset using gin (external_refs jsonb_path_ops);

asset_edge (tenant_id, from_id uuid, to_id uuid, relation text, attributes jsonb, verified boolean,
            primary key (tenant_id, from_id, to_id, relation));

sbom (id, tenant_id, asset_id, ingest_run_id, format text, spec_version text, serial text,
      object_ref text, component_count int, created_at);
sbom_component (tenant_id, sbom_id, purl text, purl_base text, name text, version text,
                licenses text[], scope text, direct boolean, hashes jsonb,
                primary key (tenant_id, sbom_id, purl));
create index on sbom_component (tenant_id, purl_base);
```

## Sources, connectors, ingestion

```sql
scan_source (id, tenant_id, name text, type text, scanner_family text, default_application_id,
             mapping jsonb, ingestion_policy jsonb, schedule text, connector_id, config jsonb,
             status jsonb, crd_ref jsonb, unique (tenant_id, name));

connector (id, tenant_id, name text, type text, config jsonb, credentials_ref jsonb,
           status jsonb, crd_ref jsonb, unique (tenant_id, name));

upload (id, tenant_id, scan_source_id, idempotency_key text, object_ref text, sha256 text,
        size_bytes bigint, format_hint text, context jsonb, options jsonb, status text, created_at,
        unique (tenant_id, idempotency_key));

ingest_run (id, tenant_id, upload_id, scan_source_id, application_id, asset_id,
            scanner_family text, scanner_version text, format text, context jsonb,
            scan_started timestamptz, scan_finished timestamptz,
            status text, stats jsonb, error text, raw_object_ref text, crd_ref jsonb,
            started_at, finished_at);
create index on ingest_run (tenant_id, asset_id, scanner_family, finished_at desc);

occurrence_staging (ingest_run_id uuid, seq int, tenant_id uuid, finding_key bytea, correlation_key bytea,
                    payload jsonb)                        -- unlogged; truncated per run
```

## Findings

```sql
finding (
  id uuid primary key, tenant_id uuid not null,
  finding_key bytea not null, finding_key_version smallint not null default 1,
  correlation_key bytea,
  category text not null, scanner_family text not null, rule_id text,
  title text not null, description text,
  vulnerability_id text, cwes int[] not null default '{}', taxa text[] not null default '{}',
  application_id uuid not null, service_id uuid, environment_id uuid, asset_id uuid not null,
  location jsonb not null,
  purl_base text, file_path text,                         -- promoted from location for filtering
  tool_severity text, severity text not null, severity_override_reason text,
  cvss_score numeric(3,1), cvss_vector text,
  risk_score int not null default 0, risk_band text not null default 'low', risk_factors jsonb,
  reachability text,
  state text not null default 'open', resolution text,
  justification text, justification_detail text, impact_statement text, action_statement text,
  verified boolean not null default false,
  first_seen timestamptz not null, last_seen timestamptz not null, resolved_at timestamptz,
  reopened_count int not null default 0,
  sla_policy_id uuid, sla_start timestamptz, sla_due timestamptz, sla_breached_at timestamptz, sla_paused_at timestamptz,
  owner_user_id uuid, owner_team_id uuid, tags text[] not null default '{}',
  duplicate_of_id uuid, risk_acceptance_id uuid,
  occurrence_count int not null default 0, source_count smallint not null default 1, ticket_count smallint not null default 0,
  search tsvector,
  created_at timestamptz not null, updated_at timestamptz not null, version int not null default 1,
  unique (tenant_id, finding_key)
);
create index finding_explorer on finding (tenant_id, state, risk_score desc, id);
create index finding_app      on finding (tenant_id, application_id, state, risk_band);
create index finding_asset    on finding (tenant_id, asset_id, scanner_family, state);
create index finding_vuln     on finding (tenant_id, vulnerability_id) where vulnerability_id is not null;
create index finding_corr     on finding (tenant_id, correlation_key) where correlation_key is not null;
create index finding_sla      on finding (tenant_id, sla_due) where state in ('open','under_investigation','affected');
create index finding_purl     on finding (tenant_id, purl_base) where purl_base is not null;
create index finding_tags     on finding using gin (tags);
create index finding_taxa     on finding using gin (taxa);
create index finding_search   on finding using gin (search);

occurrence (
  id uuid, tenant_id uuid not null, finding_id uuid not null, ingest_run_id uuid not null, scan_source_id uuid,
  scanner_family text, scanner_name text, scanner_version text,
  tool_record_id text, tool_fingerprints jsonb,
  tool_severity text, cvss_vectors jsonb, location jsonb,
  normalized jsonb, raw jsonb,
  seen_at timestamptz not null,
  primary key (seen_at, id)
) partition by range (seen_at);
create index on occurrence (tenant_id, finding_id, seen_at desc);
create index on occurrence (tenant_id, scan_source_id, tool_record_id);     -- Dependency-Track matrix lookups for write-back

finding_source (tenant_id, finding_id, scan_source_id, scanner_family text,
                first_seen, last_seen, last_ingest_run_id, present boolean,
                primary key (tenant_id, finding_id, scan_source_id));      -- drives reimport-close without scanning occurrences

finding_event (id, tenant_id, finding_id, at timestamptz, actor jsonb, type text, "from" jsonb, "to" jsonb, note text)
  partition by range (at);

finding_note (id, tenant_id, finding_id, author_id, body text, attachments jsonb, created_at, edited_at);

finding_group (id, tenant_id, application_id, name text, group_by text, key text, unique (tenant_id, application_id, group_by, key));
finding_group_member (tenant_id, group_id, finding_id, primary key (group_id, finding_id));

risk_acceptance (id, tenant_id, name text, scope jsonb, decision text, justification text, impact_statement text,
                 owner_id, requester_id, approver_id, status text, proof jsonb,
                 expires_at timestamptz, on_expiry text, restart_sla_on_expiry boolean,
                 managed_by text, crd_ref jsonb, created_at, decided_at);

ticket_link (id, tenant_id, finding_id, group_id, connector_id, external_key text, external_url text,
             external_status text, last_synced timestamptz, sync_state jsonb,
             unique (tenant_id, connector_id, external_key));
```

`finding_source` is the key to cheap reimport-close: a run marks `present=true` for keys it saw and `present=false` for the rest of its `(asset, source)` scope. A finding closes when no source still reports it.

## Policies (mirrored from CRDs)

```sql
policy_object (id, tenant_id, kind text,                 -- dedup | risk | sla | automation | retention | exception
               name text, namespace text, cluster_scoped boolean, spec jsonb, compiled_ok boolean, compile_error text,
               generation bigint, crd_uid text, updated_at, unique (tenant_id, kind, name));
policy_evaluation (tenant_id, policy_id, day date, evaluations bigint, matches bigint, errors bigint,
                   primary key (tenant_id, policy_id, day));
policy_simulation (id, tenant_id, policy_id, finding_id, at, would_apply jsonb);
```

## Upstream sync state (Dependency-Track and other API pulls)

```sql
upstream_project (
  tenant_id, scan_source_id, external_id text,           -- DT project UUID
  name text, version text, parent_external_id text, tags text[], classifier text, active boolean,
  properties jsonb, asset_id uuid, application_id uuid, mapping_rule text,   -- null application = unmapped
  last_bom_import timestamptz, last_synced timestamptz, last_sync_status text, last_error text,
  missed_discoveries smallint not null default 0,
  primary key (tenant_id, scan_source_id, external_id));
create index on upstream_project (tenant_id, scan_source_id) where application_id is null;

upstream_cursor (tenant_id, scan_source_id, kind text, cursor text, updated_at, primary key (tenant_id, scan_source_id, kind));

upstream_push (id, tenant_id, scan_source_id, finding_id, kind text,        -- analysis | vex | bom
               payload jsonb, event_id uuid, status text, attempts int, last_error text, created_at, done_at);

engagement_alias (tenant_id, alias bigint, application_id, scan_source_id, primary key (tenant_id, alias));  -- DefectDojo shim
```

## Read models (maintained by the `policy` target)

```sql
application_summary (tenant_id, application_id, open_critical int, open_high int, open_medium int, open_low int, open_info int,
                     risk_score int, exposure_count int, sla_breached int, mttr_days jsonb, coverage jsonb,
                     last_ingest timestamptz, updated_at, primary key (tenant_id, application_id));
hierarchy_rollup (tenant_id, hierarchy_node_id, … same counters …, posture_score int, primary key (tenant_id, hierarchy_node_id));
trend_daily (tenant_id, day date, scope_type text, scope_id uuid, band text,
             opened int, closed int, reactivated int, open_total int, breached int,
             primary key (tenant_id, day, scope_type, scope_id, band)) partition by range (day);
control_status (tenant_id, application_id, taxonomy_id text, taxon_id text, open_findings int, passed_checks int, last_evaluated,
                primary key (tenant_id, application_id, taxonomy_id, taxon_id));
```

## Jobs

River's own tables (`river_job`, `river_queue`, `river_leader`) live in schema `river`. Queues: `parse`, `enrich`, `policy`, `notify`, `dtrack-sync`, `dtrack-push`, `maintenance`.

## Sizing notes

- 5M findings × ~1.2 kB ≈ 6 GB heap plus ~5 GB indexes. Fits a single CNPG instance comfortably.
- Occurrences dominate: one per finding per run. With 20 runs per day on 1 000 assets, expect ~10–50 M rows per month; monthly partitions and 180-day retention bound it. `raw` is the heavy column; it may be nulled after `rawReportsDays` while keeping `normalized`.
- Hot path writes: `finding` upsert (HOT updates kept possible by not indexing `last_seen`/`updated_at`), `finding_source` upsert, `occurrence` COPY.
- Autovacuum tuned per table (`finding`: scale factor 0.02); fillfactor 85 on `finding`.
