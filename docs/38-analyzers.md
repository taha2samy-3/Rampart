# 38. Analyzers: how Rampart looks for vulnerabilities in an SBOM

This is the record of the analyzer work (decision D143 in [docs/16](16-implementation-decisions.md)): what was built, how it behaves, how to use it, what was checked and what was not.
It follows how Dependency-Track runs its analyzers, which the owner chose as the model over the older documents (docs/30, 33 and 34 disagreed with each other about it).
The decisions are D143 (the design) and D144 (the smaller choices, each with its reason) in docs/16.

## 1. What an analyzer is

An analyzer takes the components of an SBOM and answers with the vulnerabilities they have. There are two kinds, and the Analyzers tab (Ingestion, third tab) shows both:

| Kind | Resources | What it is |
|---|---|---|
| **Service** (`external`) | `ClusterExternalAnalyzer`, `ExternalAnalyzer` | A service that Rampart calls over gRPC (contract `pkg/api/analyzer/v1`): Sonatype OSS Index (own repository `sonatype-analyzer`), a scanner, an in-house database. |
| **Built-in matcher** (`sbom`) | `ClusterSBOMAnalyzer`, `SBOMAnalyzer` | The matcher inside the server (`internal/analyzer/matcher`). It compares each package URL and version with the affected ranges the OSV feed loaded. |

A `Cluster…` resource is set by an administrator and seen by every tenant. The namespaced kind belongs to one tenant, and a tenant's `ExternalAnalyzer` may name only an in-cluster `service` (an `endpoint` would let a tenant point the server at any address).

## 2. The lifecycle (the part that is Dependency-Track's)

| Question | Dependency-Track | Rampart |
|---|---|---|
| When does an analysis start? | On a BOM upload (priority 50), on a manual request (75), on a schedule (0). | The same three, as `upload`, `manual` and `scheduled`. River priority 2, 1 and 3 (1 is served first). |
| Every analyzer, or one? | Every analyzer that is on, side by side, each with the whole BOM. | One job per SBOM **and** analyzer, for every analyzer that is switched on and accepted. One call carries the whole SBOM (up to 64 MiB). |
| The schedule | Every 60 s: projects last analysed longer ago than the maximum age (24 h), oldest first, at most 50 in flight. | `analysis.maxAge` (24 h), `analysis.maxInFlight` (50), a sweep every 60 s; the SBOMs never analysed come first, then the oldest analysis. An SBOMAnalyzer with `schedule` (cron, UTC) is due when the schedule has fired since its last analysis. |
| Only the newest SBOM? | The project's latest BOM. | The newest SBOM of each application and track. An older one is `cancelled`. |
| Findings of an analyzer | Attributed to it; removed when it stops reporting them. | The scanner family is `analyzer:<name>` (`analyzer:<namespace>/<name>` for a tenant's), so an analyzer closes only what it reported itself. |
| An analyzer fails | Its findings are kept; ANALYZER_ERROR is raised. | Nothing is closed (the merge is never reached), the job is retried, the last failure raises an in-app notification (`analyzer_error`). |
| Retries | Five attempts with backoff. | Five attempts (`jobs.AnalysisMaxAttempts`), River's default backoff (seconds at first, minutes by the last). |
| States | PENDING, COMPLETED, FAILED, CANCELLED, NOT_APPLICABLE, TIMED_OUT | The same, with `running` added: `pending`, `running`, `completed`, `failed`, `timed_out`, `cancelled`, `not_applicable`. |
| One at a time | A concurrency key per project. | The claim in the database: only one analysis per SBOM and analyzer is pending or running (a stale one, older than an hour, is freed). River's unique jobs are not used, because River keeps a finished job as a duplicate until its cleaner runs, which would refuse a person who asks again. |

Where Rampart differs on purpose:

- **A mass close is held.** An answer that would close more than half of an analyzer's findings, and more than 20 of them, is held for confirmation like any ingest run (D22). This is the guard against an analyzer that answers
  "nothing" because its own data is down: a success with an empty list does not wipe the scope. It shows in the event ("a close of findings is held for confirmation").
- **Failure and silence are different.** A failed call returns an error and merges nothing. Dependency-Track's own OSS Index analyzer returns an empty list when its batch fails (D142), which a caller cannot tell from "fixed".

## 3. How one analysis runs

1. **Claim.** `ClaimSBOMAnalysis` records `pending` (`sbom_analysis`), or does nothing if one is in flight. Then a job is put on the `analysis` queue (10 workers, so a slow analyzer never holds an ingest worker). If the job cannot be queued, the claim is released as `failed`.
2. **Read.** The worker finds the analyzer (gone: `cancelled`; off: `not_applicable`; refused: `not_applicable` with the reason), the SBOM (gone or replaced by a newer one: `cancelled`) and the ingest run that stored it (its scan source, application and context are where the findings belong).
3. **Call.** `running`. The matcher reads the advisories; a service is called once with the whole SBOM, with the spec's timeout (default 60 s, at most 600) and TLS when `tls.insecure` is not true. The answer's package reference is replaced by the component's purl, name and installed version.
4. **Merge.** The findings go through the same pipeline as an uploaded report: an **ingest run** (`format: sbom-analysis`, scanner family `analyzer:<name>`, the SBOM's source, application and context) merges them, closes what the analyzer no longer reports, applies the
   mass-close guard, scores and routes notifications. So the run appears in the Ingest runs list, with its counts.
5. **Record.** `completed` with the counts, and an **event** (`analysis`, `succeeded`) with the components, findings, new and closed, the run id and the attempt. On failure: `failed` or `timed_out`, an event `failed` ("failed on attempt 2 of 5: … It will be retried; its findings are kept as they were"), and, after the last attempt, the notification.

## 4. Seeing and testing an analyzer

**The Analyzers tab** (Ingestion → Analyzers) lists every analyzer the tenant sees, by kind and scope, with its address or engine, its status (Ready, Switched off, Refused with the server's reason) and the last result.
The inspector shows how it is set up and:

- **Test** (administrator): a service is asked for health and metadata (no component is sent): "Serving: <name> <version>, N package types", or why not (nothing answers there, the time ran out, it does not implement the contract, it refused). The matcher is asked whether it has advisory data
  ("N affected ranges in M ecosystems are loaded", or that the OSV feed has not synced). Every test is recorded as an event with who ran it.
- **Analyze every SBOM** (administrator): queues the newest SBOM of every application for this analyzer, in the background.
- **History**: the last 20 events, tests and analyses, newest first, with who, when and how long.

## 5. The API

| Route | Role | What it does |
|---|---|---|
| `GET /api/v1/analyzers` | any signed-in user | The analyzers with kind, scope, address or engine, status, refusal reason and last event. |
| `GET /api/v1/analyzers/events?kind&scope&namespace&name&limit` | viewer | One analyzer's events, newest first (the tenant's own: an event belongs to the tenant that caused it). |
| `POST /api/v1/analyzers/test` | admin | Tests one analyzer and records the answer. |
| `POST /api/v1/analyzers/analyze` | admin | Asks one analyzer to analyse the newest SBOM of every application. `202 {queued}`; `409` when analysis is switched off; `404` for an analyzer the tenant does not have. |
| `POST /api/v1/assets/{id}/analyze` | triager | Asks every analyzer that is on to analyse the newest SBOM of one asset (each track). `202 {queued}`. |

`openapi.json` documents a small part of the API (findings, bulk, gate) and none of these; it was not extended.

## 6. Settings

| Setting | Default | |
|---|---|---|
| `analysis.enabled` (`RAMPART_ANALYSIS_ENABLED`) | `true` | Off: analyzers are listed and testable; nothing runs them; the two analyze routes answer 409. |
| `analysis.maxAge` (`RAMPART_ANALYSIS_MAX_AGE`) | `24h` | How old an analysis may be before the sweep asks again. At least a minute. |
| `analysis.maxInFlight` (`RAMPART_ANALYSIS_MAX_IN_FLIGHT`) | `50` | Analyses queued or running at once, across tenants. |
| `sbomAnalyzer.enabled` | `false` | The chart's built-in matcher resource. Off by default. |

The sweep needs `database.systemUrl` (it reads every tenant). Schema version **53** (`database.minSchemaVersion`) is required.

**Rolling out.** Enabling an analyzer on a cluster that already holds SBOMs analyses all of them, 50 at a time, and opens findings (and their notifications and tickets) for applications that had none. The built-in matcher is off by default so that nothing changes on upgrade.
Set `analysis.enabled: false` first if that must wait.

## 7. What was built (files)

| Area | Files |
|---|---|
| Domain | `internal/domain/analyzer_spec.go` (specs, validation, events), `internal/domain/analysis.go` (states, triggers, `AnalyzerRef`, `AnalysisStore`), notification kind `analyzer_error` |
| Storage | migrations `00052_analyzers.sql` (two kinds, `analyzer_event`) and `00053_sbom_analysis.sql`; `internal/store/analyzers.go`, `internal/store/analysis.go`; in memory: `internal/ingest/memory_analysis.go` |
| Operator | four reconcilers and controllers (`internal/operator`), RBAC (`rbac.yaml` of the chart and of `deploy/operator`), `ApplyDocument` for the four kinds |
| Running | `internal/analysis` (service, sweeper), `internal/jobs/analysis.go` (job, worker, queue), the hook `ingest.AnalysisTrigger`, the wiring in `internal/targets/runner.go`, `internal/cron` (the schedule) |
| Matcher | `internal/analyzer/matcher`: advisories from `vulnerability_affected`, `last_affected` and exact-version ranges, direct-only, grading by CVSS score; the client `Dial` with TLS and 64 MiB messages, and `Probe` |
| API | `internal/query/analyzers.go` |
| Web | `web/src/routes/ingestion/AnalyzersView.tsx`, `AnalyzerInspector.tsx`, `analyzers.test.tsx`; API layer, strings and the shared test server |
| Chart | `analysis.*` values, environment, schema; the comments of `sbomAnalyzer` rewritten to say what is and is not used |
| Docs | D142 and D143 in docs/16, docs/37 section 3.12, this file |
| Sonatype analyzer | its own repository: the receive limit raised to 64 MiB (a whole SBOM is more than gRPC's 4 MiB default), README updated |

## 8. What was checked

All of it passed when this was written (commands in section 10).

| Claim | How |
|---|---|
| A failed analyzer closes nothing; a later answer closes only what it dropped; another analyzer's findings are never touched | Service tests on the real merge engine, then again on **PostgreSQL** with row-level security (the close queries match on the scan source, so this was the doubt); a mutation check (letting a failure continue to the merge) fails four tests |
| An empty answer does not wipe an analyzer's scope | 30 findings, an empty answer: all 30 stay open, the event says the close is held |
| Upload, request, schedule; one at a time; budget; oldest first; failed analyses wait; a cron schedule | Service tests, and `Sweep` on PostgreSQL as the system role across tenants |
| Claim, due and in-flight queries; tenants cannot read each other's records | PostgreSQL tests (`internal/store/analysis_test.go`) |
| The matcher over the real table: bounds, `last_affected`, exact versions, withdrawn advisories, severity from the score | PostgreSQL test and matcher unit tests; the severity test found a real defect (a 9.8 score was `unknown`), fixed |
| The cron reader | 40 cases: fields, steps, ranges, day-of-month/day-of-week rule, 31 February, `Prev` over a day, a month and years |
| The routes: roles, 409 when off, 404, bad input, tenant of the call | `internal/query/analyzers_test.go`, with the race detector |
| The page | 19 tests including accessibility checks; the whole web suite (38 files, 285 tests). **Also opened in Chromium** (Playwright against the dev mock server, `web/dev/mock-server.mjs`, which now serves the analyzer routes) at 1440 px and 390 px, which found five defects the tests did not: on a phone, selecting a row collapsed the table to zero height and the inspector covered it (a grid that may shrink squeezes a scroll container to nothing); the Status and Last result columns were off the screen; a refused analyzer showed an empty Address row; a long address broke in the middle of a word; and "Last result" named two different things. All fixed and re-measured (the table keeps its height, the page has no horizontal overflow). |
| The chart | `helm template` (without the remote dependencies): the environment, the schema refusing `maxAge: soon` and `maxInFlight: 0` |
| The analyzer service takes a 5 MiB request | its own test, which fails without the raised limit |

## 9. What was not checked, and the limits

- **The page against the real server:** it was opened in a browser against the dev mock server, which answers in the real API's shape but is not the real server. Not done against a running Rampart.
- **Not run end to end:** the Sonatype analyzer image called by a running Rampart in a cluster (no cluster was touched). Each part is tested; the whole is not.
- **River.** The queue is exercised through a recording fake and through the real database for everything but River itself: the enqueue, the retry backoff and the priority were not run against a live River in a test. The settings used are River's documented ones.
- **Version comparison** in the matcher is by dotted numbers with a simple pre-release rule. Debian epochs, Maven qualifiers and similar are not implemented, so a match there can be wrong either way.
- **Matcher settings read but not used:** `engine`, `rules.minConfidence`, `rules.includePreRelease` and `sources`. The page and the chart say so. `matchDirectOnly` and `schedule` are used.
- **Severity.** The vulnerability table keeps a CVSS score, not a severity word, so severity comes from the score; an advisory with no score is `unknown`. A row of OSV data with no package URL cannot be found by the matcher.
- **An external analyzer** cannot use a private CA or a credential on the call (`tls.caSecretRef`, `auth.secretRef` are refused with a reason), and `protocol: http` is refused.
- **Per-application roles** are not consulted by `POST /assets/{id}/analyze`: the triager role of the tenant is enough.
- **Where the button is.** "Analyze every SBOM" is on the Analyzers tab. There is no "analyze again" button on an application's page yet (the route for it exists).
- **The in-memory store** (no PostgreSQL) does not run analyses: the server starts them only with a database.
- **A stuck claim** (a worker that died) is freed after an hour, by the next sweep or request.
- `examples/external-analyzer` builds its gRPC server with the default 4 MiB receive limit; a large SBOM would need it raised there as it was in `sonatype-analyzer`.

## 10. How to run the checks

**Timing, measured on one 8-core laptop that was also running an IDE and a browser.** `go test -race ./...` did not finish cleanly there, for reasons that are not the analyzers:
`internal/store` alone, without the race detector, takes about 9 minutes (102 tests pass, 1 is skipped), more than Go's default 10-minute limit under `-race`; `internal/ingest` takes 150 s without it
and also passed alone; and `cmd/rampart` `TestCLIE2EUploadAndSBOM` passes in 39 s without `-race` but exceeds its own 120 s client timeout with it, **and fails the same way on the commit before this work** (a clean
worktree of `b6fdb2a`, same machine). Run the packages with `-timeout 30m`, and that test without `-race` on a loaded machine.


```
go vet ./... && gofmt -l .                                  # clean
export RAMPART_WASM_DIR=$(hack/test-modules.sh)
export RAMPART_TEST_POSTGRES_URL='postgres://rampart_owner:rampart_password@127.0.0.1:5435/rampart?sslmode=disable'   # a throwaway database
go test -race -timeout 30m ./...                              # cmd/rampart TestCLIE2EUploadAndSBOM needs no -race on a loaded machine
cd web && npx tsc --noEmit && npx eslint src && npx vitest run --maxWorkers=1 --testTimeout=20000
cd ../../sonatype-analyzer && go test -race ./...
```

## 11. For the owner

- Nothing is committed or pushed. Review the diff, then commit.
- Publish `rampart-parsers`, `rampart-sbom-parsers` and the analyzer chart and image (`chart-v0.1.0`, `v0.1.0`) so that `helm dependency update` works and the analyzer can be installed.
- **Rotate the Sonatype token** that was pasted in the conversation (it is in the transcript).
- Decide the `LICENSE` of the analyzer repository, and read the OSS Index terms before using it in a commercial product.
- Decide whether `analysis.enabled` should be `true` on the first upgrade (section 6, "Rolling out").
