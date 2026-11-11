# 17 — Design review

Two independent reviews were run on documents 00–15 and the ADRs on 2026-11-11: an architecture critique and an implementation-readiness check. Neither reviewer wrote the design. Nothing was executed; the claims about PostgreSQL, Kubernetes and third-party libraries come from reading and are marked where they still need a test.

## Verdict

**The component split is sound. The first draft of the ingestion core and of the tenant boundary was not safe to build from.** Both reviewers said "not ready", for overlapping reasons. The defects are now addressed by decisions in [16-implementation-decisions.md](16-implementation-decisions.md), and the affected documents were corrected or carry a pointer to the decision that supersedes them. What remains open is listed at the end.

What held up under review:
- Kubernetes for configuration, PostgreSQL for data (ADR 0001).
- One binary with targets; ingestion and UI never share a process in production (ADR 0004).
- PostgreSQL as the default queue (ADR 0002), with a changed event granularity.
- Standards-first ingestion and the OpenVEX vocabulary (ADR 0003).
- `tenant_id` with row-level security (ADR 0005), with database roles added.
- Dependency-Track as the SCA system of record, with events treated as untrusted triggers (ADR 0006).

## Critical findings and how they were resolved

| # | Finding | Concrete failure | Resolution |
|---|---|---|---|
| 1 | Reimport-close scope was defined three different ways (02, 05, 12) | A Trivy upload closes all Semgrep findings on the asset; a feature-branch scan closes `main` | One scope: source, scanner family, asset, track. A finding closes only when no occurrence is present. D10, D13 |
| 2 | The merge SQL was wrong | Two rows with one key in a batch abort the statement; reactivation was never detected on PostgreSQL 16; a retried batch double-counted | Rewritten: collapse keys, read existing rows `FOR UPDATE`, classify from pre-update state and a content hash, recompute counters. D13 |
| 3 | No ordering or locking for concurrent runs | An older run finishing last closes what the newer run found | Advisory lock per scope and a high-water mark; late runs become `stale`. D13 |
| 4 | Image and workload assets were keyed by digest and UID | Every build created a new asset and a full new set of findings; triage never carried over | An asset is the long-lived thing; digest, commit and UID are versions. Findings are kept per track. D10 |
| 5 | One `state` field mixed "still detected" with "what we decided" | A risk-accepted finding that was fixed reopens at expiry; an upstream "resolved" oscillates with reactivation | Separate `detection` and disposition; expiry on an absent finding resolves it. D18 |
| 6 | Cross-tool merge could not work with the upsert key and raced | The merged-away tool re-creates its finding on the next run | v1 keeps per-tool findings and adds non-destructive correlation groups; merge is deferred. D24 |
| 7 | Global tables were written from tenant reports | One tenant changes rule severity, help links or CVE aliases for all tenants | Global tables are written only by feed sync; tenant data goes to tenant-local tables. D19 |
| 8 | Secret access was unsolved and contradictory | The first connector cannot authenticate: workers have no Kubernetes access and cannot mount Secrets from other namespaces | The operator copies referenced material, envelope-encrypted, into Postgres. D1 |
| 9 | Three confused-deputy paths across tenants | A `ReportIngest` reads another tenant's object; a namespaced source reads every namespace of the local cluster; a namespace label attaches a namespace to a victim tenant | Object keys bound to the tenant prefix; local watching only through a platform-admin kind; tenant binding only from the `Tenant` resource. D20 |
| 10 | One custom resource per upload | Tens of thousands of objects in etcd; reports parsed twice; CI uploads fail on quota | API uploads create no custom resources. D1, D2 |
| 11 | CI federation had no tenant binding and ingest credentials could mass-close | An empty report with a raised severity threshold closes every finding and passes the gate | Tenant in path and audience, immutable id claims, token exchange, clients may only tighten, mass-close guard. D22 |

## Major findings

| Area | Finding | Resolution |
|---|---|---|
| Dependency-Track triage sync | Lossy round-trip, upstream decisions overwritten, clock-based conflict rule | v1 ships `import` only; write-back later with per-pair sync hashes. D23 |
| Dependency-Track flows | Webhook secret published in status; leading-edge debounce drops events; pull before analysis settles; gate passes with no SCA results | Secret in a Secret, trailing debounce, settle check, gate waits for linked run. D23 |
| Operator | uid-keyed config breaks restore from Git; deletion undefined; noisy status; data-plane work inside the operator | Keyed by tenant, kind, namespace, name; deletion table; throttled status; cluster watching moved to a later `collector`. D21 |
| Database roles and pooling | One role for everything; `LISTEN/NOTIFY` behind transaction pooling | Four roles, direct connection for listeners. D4 |
| Occurrence volume | One row per finding per run would reach hundreds of millions of rows a month | Occurrences are upserted evidence; storage grows with change. D12, D28 |
| Query performance claim | Facet counts, joins to global tables and missing indexes contradict "500 ms on 5M" | One SLO for a published filter and sort matrix; denormalized columns; capped facet counts. D28 |
| Queue premise | Per-finding events contradicted "each job is a whole report" | One event per run and scope; recomputed read models; action ledger; causation depth. D25 |
| Ingestion speed claim | Unbounded as stated | Restated with hardware and scope; a Phase −1 spike must prove it. D28 |
| Identity | Email-domain hijack, email-based bindings, shared provider reach, revocation promise | Approved domain claims, subjects qualified by provider, tenant allow-list, stated revocation bound. D27 |
| Live updates | Stream scoped to tenant, not to the user's scope; no fan-out design | Server-side scope filter and coalescing. D27, 13 §3 |
| DefectDojo shim | Collided with the `/api/v2` versioning plan | Mounted under `/compat/defectdojo/`. D23 |
| Tenant and namespace | One namespace per tenant conflated tenant and team | A tenant owns a list of namespaces. D20 |
| CI gate | "New" had no baseline; no way to know all scans arrived; risk band not yet computed | Expected scans declared, baseline track, final status includes scoring. D26 |
| Phase 0 readiness | No configuration reference, no non-Kubernetes bootstrap, undecided IDs and migrations | D3, D4, D5, D6 |
| Fingerprint | Encoding, fallbacks and canonical id unspecified | Full specification. D11 |
| Asset resolution | No algorithm from upload context to asset and application | Resolution order and canonical context. D10 |
| Filter grammar | One example line | EBNF, fields, cursors, builder. D16 |
| Roadmap | v1.0 in 18 weeks with ~20 parsers, 14 CRDs, three deployment modes was not credible; priorities disagreed with phases | Rewritten: MVP at week 17, v1.0 at week 29 for four to five engineers; priorities realigned; scope cut. [09](09-roadmap.md), D29 |

## Consistency fixes applied

About fifty naming and structural mismatches were reported. The ones that change meaning were fixed in place: target names (00, 02, ADR 0004), table names and read models (02), run status and stats (03, 04), context location (02, 11), parser signature (02), batch size (02), dedup field names and default scope (04), feed-mirror kind (03, 04), SAML implementation (07), login and auth routes (11, 14), migration hook (15), metrics port (15), queues (ADR 0002), route prefixes (ADR 0004), tenant binding (ADR 0005, 02, 07, 15), drafting leftovers (10, 16).

Documents 03, 04, 10, 12 and 14 carry a note at the top naming the decisions that supersede parts of them. The SQL in 12 is still the pre-review sketch plus an explicit delta table; the first migration must be written from both.

## Still open

These were not resolved by writing; they need a test, a live system, or a decision by the team.

| Item | Why it is open | When |
|---|---|---|
| 100k findings in 60 s; 5M-finding query SLO | No measurement exists | Phase −1 spikes, then nightly benchmarks |
| `COPY` plus RLS behaviour, River behind PgBouncer, bundled CNPG install order | Stated from documentation, not run | Phase −1 spikes |
| Dependency-Track endpoints marked "confirm" in doc 10 | Verified only where the public docs describe them; the rest is from the OpenAPI definition as remembered | Before Phase 3, against a live instance |
| `go-sarif` and `cyclonedx-go` version coverage; controller-runtime against the minimum Kubernetes version | Not checked against current releases | Phase 0 |
| Name, API group, license | Team decision; baked into code | Phase −1 |
| `Application` kind name next to Argo CD | Kept with a short name; renaming is still cheap before the scaffold | Phase −1 |
| Schema document 12 | Sketch plus deltas, not final DDL | Phase 0 |
| Field lists in 03 versus 12 | Descriptive only; 12 plus deltas is authoritative | Phase 0 |
| Risk weights and bands | Reasonable defaults, not calibrated on real data | After MVP, with pilot data |
| Team size | Assumed four to five; the calendar depends on it | Phase −1 |

## Added after the review

The first design gave only parsers an extension point, and only as compiled-in Go. [19-integration-sdk.md](19-integration-sdk.md) adds one set of contracts for parsers, API sources, trackers and notifiers, with four tiers: standard formats, declarative YAML, sandboxed plugins, built-in Go. It has not been through an independent review yet, and three of its performance assumptions are listed there as unverified.

## How to read the document set after the review

1. [00](00-vision-and-scope.md) and [02](02-architecture.md) for the shape.
2. [16](16-implementation-decisions.md) for anything precise: it wins on conflict.
3. [09](09-roadmap.md) for what is built when.
4. The topic documents (03–08, 10–15) for depth, read together with the note at their top.
