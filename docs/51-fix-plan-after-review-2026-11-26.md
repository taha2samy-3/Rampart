# 51. Fix plan after the review of 2026-11-26

Status: plan. Nothing in this file is applied. Written 2026-11-26 after a read-only review of the whole tree (docs 00 to 50, the Go code,
the web UI, the chart, and the CI logs of runs `45736108114` and `45135126735` on GitHub). Nothing was built or run locally.

Rules this plan follows (docs/16 D58, AGENTS.md, the owner's way of working):
- Work the phases in order and the steps of a phase in order; finish a step, with its tests, before the next; stop after each step for the owner to commit.
- Each step that decides something gets a D-entry in docs/16 with the reason; a doc sentence the step contradicts is corrected in the same step.
- Every step ends with the AGENTS.md section 5 battery. Phase 0 exists because that battery cannot be trusted today.

Sizes: S is a day or less, M a few days, L a week or more.

## 0. Why this order

1. **CI first.** The PostgreSQL job has passed while its tests failed, since 2026-11-11 (section 1). Until it fails when a test fails, no fix below can be shown to work.
2. **Security next** (phase 2): secrets stored, triage by a CI token, federation without a branch, credentials in clear text. Each is reachable with a default install.
3. **Correctness** (phase 3): things that silently do nothing or do the wrong thing, without a security cost.
4. **The UI telling the truth** (phase 4), then the `/integrations` retirement (docs/50), which depends on nothing above but should not compete with them.
5. **Decisions and documents** (phase 5) run beside the others: some steps wait on an owner decision listed in section 6.

## 1. Phase 0: CI tells the truth (S)

| Step | What | Where | Done when |
|---|---|---|---|
| 0.1 | Set `defaults: run: shell: bash` at the top of `ci.yml`. GitHub then runs `bash --noprofile --norc -eo pipefail`, so `go test ... \| tee` fails when `go test` fails. Without it, the default `bash -e` takes `tee`'s exit code. Check every `\| tee` and `\| grep` step in both workflows. | `.github/workflows/ci.yml`, `helm-release.yml` | A deliberately failing store test turns the job red (try it on a branch, then revert) |
| 0.2 | The store suite hits `panic: test timed out after 10m0s`, so every test after the hang never runs. `TestApplicationChanges_LargeApplication_OnPostgreSQL` takes 180 s and fails. Find the cause; do not just raise the timeout. Then give the job an explicit `-timeout` like the unit job's. | `internal/store/*_test.go`, `ci.yml` | The suite finishes; its time is known |
| 0.3 | Migration 00057's marker reads `-- Expand-safe migration for...`. The policy test wants `-- expand-safe: <reason>`. Fix the comment only. Goose tracks version numbers, not file content, so an applied database is not affected. | `internal/store/migrations/00057_external_trackers.sql` | `TestMigrationsAreExpandOnly` passes |
| 0.4 | The owner runs the full battery. Every failure that 0.1 uncovers goes into a list appended to this section, fixed before phase 2 or moved into a later step by name. | | The CI run is green for real |

## 2. Phase 1: security (each step M unless marked)

### 1.1 Secrets never stored (D42), whatever the parser does

Today, `merge.go:368` stores `RawPayload` as given. The only redaction deletes three top-level keys, and only in the branch with no `Attributes` (`merge.go:340-346`). On top of that, the WASM host fills an empty payload with the whole emitted line (`integrations/wasm/parser.go:250`), and that line holds `secret_value`. Redaction is left to the parsers, which are outside this repository (D141). The core must not rely on them.

- Rampart redacts, not the parser. For a finding of category `secret`, `occurrence.raw` is not stored at all. For every finding, `Attributes` and the raw payload pass through one recursive redactor. It strips the known secret keys at any depth, and any string equal to the record's secret value.
- The WASM and Lua hosts strip `secret_value` from the line before using it as `RawPayload`.
- Data: migration 00058 (expand-safe, data only) sets `raw = NULL` and redacts `normalized` for stored occurrences of secret scanners. The step's D-entry says how many rows a real database had; the owner runs it.
- Tests: a hostile WASM parser that puts the secret in `RawPayload`, in a nested attribute and in a renamed key. None reaches the database (PostgreSQL test). The gitleaks and trufflehog fixtures again.
- Correct D147 and docs/46 ("strictly redacted" was not true). In the parsers repository, gitleaks' `Line` and semgrep's `extra.metavars` are follow-ups to log there.

### 1.2 VEX inside an SBOM upload decides nothing on its own

Today, `applyVEXStatements` (`ingest/processor.go:560-646`) sets findings to `not_affected` with no role, no application scope, no check for ephemeral runs, across the whole application (`store/audit.go:96-112`). Its timestamp rule also lets an undated statement, or a CycloneDX build time, override a person's decision. `/api/v1/vex` requires the triager role and the application scope (`query/vex.go:131, 210`).

- The same rules as `/api/v1/vex`: the uploader needs the triager role and the application scope. Otherwise (an ingest token, a triager scoped to another application) each statement becomes a request, as Dependency-Track decisions did (D92). This waits on decision Q2.
- Never from an ephemeral run.
- Match the uploaded asset (and track), not the application. This matters most for `unassigned`.
- A statement with no timestamp of its own never overrides a person. A document's build time is not a statement time.
- After a state change, re-score (`ScoreBatch`, as `triageOne` does). Count applied, requested and failed statements in the run instead of `continue` and a log line.
- A CycloneDX VEX-only document is detected by what it contains, not by the format name `"openvex"` (`processor.go:544`, `sbom/wasm.go:29`, which also names a format in code, against D141). It must not become the asset's latest SBOM with zero components.
- Tests on PostgreSQL for each rule. Correct docs/47 section 5 and D148 (the code is in `processor.go`, not `processor_sbom.go`).

### 1.3 Federation binds repository and branch, and revoking works

Today:
- Trust rules made from `ScanSource.auth.federation(s)` have an empty provider. `federationBindings` (`ingest/federation_binding.go:27-49`) binds the repository and ref only for `github` and `gitlab`, so the token carries only the commit. A feature branch can upload as `main`.
- `TrustRule.Validate` returns early on `boundClaims` (`domain/scansource.go:125-131`), which skips D22's immutable-id rule. The chart's example binds by name (`values.yaml:432`).
- The reconciler calls `SaveTrustRules` only when the list is not empty (`operator/reconciler.go:317`), so removing a federation leaves it working.

Fix:
- A rule must say which claim names the repository and which names the ref. Either the provider (`github`, `gitlab`, ...), or explicit `repositoryClaim` and `refClaim` for a generic issuer. A rule that names neither is refused with its reason.
- D22 holds with `boundClaims`: GitHub needs `repository_id` and `repository_owner_id`. Fix the chart example.
- Always call `SaveTrustRules`, including with an empty list. On ScanSource deletion or disable, delete the rows (D21 says tokens are revoked).
- Tests: a feature-branch token that uploads `branch=main` is refused. A removed federation is refused at the exchange. A rule without a repository claim is refused by the operator (envtest).

### 1.4 External trackers: TLS, references, connections (S to M)

- `UseTLS()` is true unless `tls.insecure: true` is written (`domain/tracker_spec.go:102`). Today, clear text is the default and the tenant's Jira credentials cross the pod network in clear.
- Refuse `tls.caSecretRef` and `auth.secretRef` until they are read, as `analyzer_spec.go:102-105` does. Today they are accepted and ignored.
- A namespaced `ExternalTracker` may name a Service only in its own namespace. The same for `ExternalAnalyzer`, which has the same gap.
- One gRPC connection per tracker, kept and closed when the spec changes and at shutdown. Today `ResolveTracker` dials once per pending ticket and nothing calls `CloseClient`.
- Live events: either add `live_event` triggers for `ticket`, `ticket_outbox` and `tracker_event`, or remove "Live updates via SSE" from `TicketsQueueView.tsx:40`.
- D-entry: the tracker contract returns (reversing D96 for trackers) and namespaced gRPC trackers are allowed (amending D94). Today neither is recorded.

### 1.5 Vulnerability pages do not call the internet on every view

Today, the live fetch writes with the application role, which may not write `vulnerability` (`00001:714`). The errors are dropped (`enrich/advisory_live.go:222, 241`). So every view of an unscored CVE calls OSV and NVD, keyless and with no limit. `POST /vulnerabilities/{id}/refresh` has no role check. The sweeper of docs/44 and `ClusterAdvisorySource` have no caller.

- The refresh route needs the triager role, single flight per id, and a cooldown (AGENTS.md section 4).
- Persistence goes through the system store, or is dropped in favour of a bounded cache. A failure is logged and said.
- A page view never fetches live, only the refresh button does. Decision Q4.
- `ClusterAdvisorySource`: read it (mode, URLs, token file through the guarded client of D69 and the token path rule of docs/35 D2), or stop shipping it. A CRD that changes nothing breaks "honest status".
- The sweeper: wire it with River priority 1 to 4 and one acquired connection for lock and unlock (as `analysis/sweeper.go:24-33`), or delete it and correct docs/44, which describes it as delivered.
- The NVD v4 score is not stored in the v3 fields (`advisory_live.go:147-150`).

## 3. Phase 2: correctness (S each unless marked)

| Step | What | Where |
|---|---|---|
| 2.1 | The platform cap on manual analyses runs on the system store. On the app role, row-level security makes it count 0. | `query/app_refresh.go:47`, `store/analysis.go:228` |
| 2.2 | The 5-minute cooldown also covers `POST /assets/{id}/analyze`. The manual marker becomes its own column, so a later upload's claim does not erase it. A failed `DispatchAsset` is said, not answered "up to date". | `query/analyzers.go:420`, `app_refresh.go:107,175` |
| 2.3 | A retried analysis checks it still owns its claim (an attempt token in `sbom_analysis`) before merging. Otherwise a manual claim during River's backoff runs a second merge. | `analysis/service.go`, `store/analysis.go:108` |
| 2.4 | Two analyzers of different kinds with the same name share the family `analyzer:<name>` and close each other's findings. Refuse the second name (simplest, no data change). | `domain/analysis.go:64` |
| 2.5 | `rtrim(repository, '.git')` strips characters, not the suffix. Use `regexp_replace(repository, '\.git$', '')`. When a repository has several branch applications (D140), match the branch too or refuse as ambiguous; never `LIMIT 1` without an order. Selector mode reads `application.tags`, which nothing fills: fill it or refuse the mode. | `store/postgres.go:1622-1680` |
| 2.6 | `GetScanSource` errors are ignored at three places, so a store error skips the binding and category checks. Fail closed. | `ingest/gateway.go:315,455,484` |
| 2.7 | A clean rescan closes nothing. With no findings, the close scope is the parser id (`cluster:trivy`), not the family (`trivy`). | `ingest/processor.go:250` |
| 2.8 | Old runs keep `builtin:<name>` (D146 removed the fallback 12 minutes after adding it). Migration 00058 or 00059 rewrites the stored ids to `cluster:<name>`. Otherwise compliance evidence, the gate and "last run" lose them. | migration, `compliance.go:171`, `gate.go:177`, `query/parsers.go:60` |
| 2.9 | The presigned path checks the modules before creating a run (fail fast, AGENTS.md section 1). The direct path does not leave an asset behind a 404. Remove the dead `createChoice` branch. | `ingest/gateway.go:474-512, 826, 874`, `resolution.go` |
| 2.10 | `scan_source.application_id ON DELETE CASCADE` (00056), chained with `ingest_run.scan_source_id ON DELETE CASCADE`, erases history on an application delete. Use `SET NULL` (D21, D49). | migration |
| 2.11 | `FindFindingByTicketRef` and `FindingHasTicket` filter by connector. | `store/tickets.go:262,293` |
| 2.12 | `POST /inventory/components/scan` ignores its purl and starts a full re-score per request. Make it 501 with the reason, or real with single flight. | `query/inventory.go:187` |
| 2.13 | The chart's bootstrap Application renders `name`, `lifecycle` and `tags`, which the CRD prunes, into a namespace no Tenant lists. Bump the chart version when CRDs change (0.3.26 did not move with f1f90f1). | `templates/bootstrap-resources.yaml`, `Chart.yaml` |

## 4. Phase 3: the UI tells the truth

| Step | What | Where |
|---|---|---|
| 3.1 | Bands come from the server. `bandFromScore` invents medium at 400 and an `info` band; the server's default is medium at 300, with no info band, and a RiskPolicy can change it. Read the bands from `/api/v1/scoring`. The ScoreCard draws the markers from them. Fix the test that asserts the wrong band, and the mock's third set (800/500/200). | `lib/band.ts`, `ApplicationScoreCard.tsx`, `ApplicationRoute.tsx:79`, `ApplicationsRoute.tsx:102`, `dev/mock-server.mjs` |
| 3.2 | 13 files use colour and size classes that `@theme` does not define (`danger`, `warning`, `success`, `muted`, `layer-*`, `surface-2/3`, `ink-3`, `text-10/11/15/22/38`), so severity has no colour. Use the existing tokens. Add a test that fails on a class outside the theme. | `styles/index.css`, the 13 files |
| 3.3 | Polling: `IngestionRoute.tsx:60` (3 s), `OverviewRoute.tsx:23`, `TopBar.tsx:69` (60 s) refetch data that SSE already invalidates. Remove them; keep the fallbacks that run only without SSE. | |
| 3.4 | Design rules (docs/13, D144): the KPI tiles and "% of scale" in the ScoreCard, "In policy" with no deadline, red counts that are 0, pulse dots, raw `rose`/`amber`, state shown by colour, rounded pills. The `NO-BUILTIN` badge: `Logo.tsx`'s copy is dead code; the owner decides whether the login page keeps its copy (Q6). | |
| 3.5 | Words: missing i18n keys (`parsers.crdResource`, `parsers.uploadFormat`, `common.error`). `inventory.scanNowTooltip` still says matching is Dependency-Track's work. Leftover Dependency-Track types in `api/types.ts`. docs/41's fix (say why a framework does not apply instead of "could not be evaluated"). `ScannerEvidenceSection` hides a load error and fetches the finding three times. A missing SLA cell says "0 days" instead of "Not configured". | |
| 3.6 | The mock's `/api/v1/sources` returns `{items}` where Go returns `{sources, total}`, so the Sources tab is always empty under the mock and in e2e. | `dev/mock-server.mjs:642` |
| 3.7 | Retire `/integrations`: [docs/50](50-retiring-integrations-page.md), as revised. | |

## 5. Phase 4: decisions and documents (beside the others)

| Step | What |
|---|---|
| 4.1 | ScanSource: D139/D140 retire it, while 8a4208a and docs/48 extend it. Until the owner decides (Q1), no new ScanSource feature. Either AB3/AB4 of docs/35 resume, or a D-entry reverses D139/D140 and docs/35 says so. |
| 4.2 | docs/48 claims what the code does not do: Argon2id (`token_hash` is never written), Mode A tokens from `tokenSecretRef` (never read for authentication), 404 `application_not_registered`, required `applicationRef`/`categories`, removed `trackedRefs`. Correct it to the code, or build it after Q1. |
| 4.3 | D-entries for what was done with none: docs/48, docs/49 (see 1.4), migrations 55 to 57, the `/ticketing` page. Each step above adds its own. |
| 4.4 | docs/09: a status table that covers D120 to now (parsers as resources, Dependency-Track removed, analyzers, ticketing), and the v1.0 line that still says "including Dependency-Track". docs/12: the delta table stops at migration 42. docs/35 section 00: what landed after 2026-11-19. |
| 4.5 | Docs 42 to 49 carry claims the code does not back (listed in each step above) and an invented byline (docs/48: "Rampart Core Security & Architecture Team"). Correct them; docs/43 is in Arabic while the docs are English. |
| 4.6 | Pin `.github/parser-modules.env` to commits (still `main`). |

## 6. Decisions needed from the owner

| # | Question | Proposed answer |
|---|---|---|
| Q1 | ScanSource: retire it (D139, D140) or keep it extended (docs/48)? | Retire, as decided. The new binding (`applicationRef`, `categories`, generic claims) moves to `Application.spec.ingestion` and `Tenant.spec.ciTrust`. |
| Q2 | May a CI (ingest) token ever change triage through a VEX inside an SBOM? | No: it becomes a request a triager approves. |
| Q3 | 1.1's data migration rewrites stored occurrences of secret scanners. Run it on the dev cluster first? | Yes, with a dry-run count. |
| Q4 | Should a vulnerability page call OSV/NVD live at all? Air-gapped installs cannot. | Only the refresh button, by a triager; page views read the database. |
| Q5 | Keep the docs/44 sweeper (wire it) or delete it? | Delete; the NVD incremental sync of docs/35 D already re-reads changed CVEs. |
| Q6 | The `NO-BUILTIN` badge on the login page: keep it? | Remove; the design rules have no badges on the wordmark (docs/18). |

## 7. What was not checked

Runtime behaviour (nothing was run here). The full redaction set of the external parser modules. Whether an empty SBOM's analysis actually closes findings (2.7's twin for analyzers). The dev cluster. Whether the failures hidden by phase 0 are only the two seen in the logs: the suite stopped at the timeout, so the tests after it are unknown.
