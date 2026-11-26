# 52. Fix progress after the review of 2026-11-26

Status: report. Written 2026-11-26, when the owner asked to stop all work. It records how far the fix plan
([docs/51](51-fix-plan-after-review-2026-11-26.md)) and the `/integrations` retirement plan ([docs/50](50-retiring-integrations-page.md)) got,
what was verified and what was not, and what is left. **Nothing is committed**; every change is in the working tree for the owner to review.

## 1. Summary

- **Done:** every step of docs/51 phases 0 and 1 is done; phase 1 has gaps inside some steps (section 3). Phase 2 is done except 2.4 and 2.9, with gaps in 2.5 and 2.6. Phase 3 is done, and docs/50 is done in code.
- **Decisions recorded:** D149 to D154 at the end of [docs/16](16-implementation-decisions.md), plus a correction note on D147.
- **Migrations added:** 00058 to 00062. The schema version is now **62** (`CurrentExpectedSchemaVersion`, and the chart's `database.minSchemaVersion`). Chart version: **0.3.27**.
- **Not verified as a whole.** Every step was tested package by package as it was written. The final full battery was stopped at the owner's request before it finished, so the full Go suite, the full PostgreSQL suite after migrations 61 and 62, the operator suite with envtest, and Playwright have **not** run against the final tree. That is the first thing left to do (section 8).

## 2. Where the project is, phase by phase

| Phase (docs/09) | State |
|---|---|
| Phase 0: foundations | Built. Known gaps from docs/09: the data-service network policies, `Archive`, the name-conflict condition. |
| Phase 1: ingest core | Built. The throughput goal was withdrawn (D35). |
| Phase 2: MVP | Built, except G6 (a generated OpenAPI client). `openapi.json` still documents only findings, bulk and the gate (D144). |
| Phase 3: workflow and integrations | Built as docs/09 records. Milestone 3.4 (Dependency-Track) was later removed on purpose (D129). |
| Work outside the roadmap (docs 29 to 49) | **Done:** parsers as resources with nothing compiled in (D127, D141, D146), the SBOM pipeline (docs/35 C1 to C9), analyzers on upload, on request and on a schedule (D143, D144), and the Sonatype analyzer in its own repository. **Partly done:** feeds (docs/35 D7 to D9 open); ticketing (docs/49 slices 1 to 5 partly: no `TicketTracker` CRD; slice 6 not done); advisory sources (`ClusterAdvisorySource` is read by nothing, the docs/44 sweeper is not wired). **Not started:** AB2 to AB6 (docs/35). **Undecided:** retire `ScanSource` (D139, D140) or extend it (docs/48). |
| Phase 4: hardening to v1.0 | Not started as a phase. Some parts exist: `ClusterFeedMirror`, parser fuzzing, signed images in CI. |
| Phase 5 | Not started, apart from the first plugin slices (D94, D98). |

docs/09's status table still stops at Phase 3.6. It does not mention D120 onward, and its v1.0 line still says "including Dependency-Track". Updating it is in section 8.

## 3. docs/51: step by step

Legend: **done** (code and tests), **partial** (part done; the rest is listed), **not done**.

### Phase 0: CI tells the truth

| Step | State | What changed | Verified |
|---|---|---|---|
| 0.1 `pipefail` | done | `.github/workflows/ci.yml`: the two `go test ... \| tee` steps run `set -o pipefail`. It is not set file-wide: with `pipefail`, `helm template ... \| grep -q` can fail on SIGPIPE. | The GitHub log of run `45736108114` showed `FAIL rampart/internal/store` inside a job marked green, which is the reason for this step. The fixed workflow has not run on GitHub yet. |
| 0.2 store suite timeout | done | The cause is the race detector on the 10,000-finding test, which takes about 180 s on CI, plus go test's default 10-minute timeout. The store job now has `-timeout 25m`. | Locally, without `-race`, the suite ends in about 5 minutes with no hang. |
| 0.3 marker on 00057 | done | The comment now reads `-- expand-safe: <reason>`. | The policy test passes. |
| 0.4 the real failure list | partial | Locally, the one failure behind the mask was `TestRunErrors_RecordsAndRawReport`. Its cause was a **stale local WASM module**, not a bug: `hack/test-modules.sh` decides by file times and skipped `semgrep`. After a forced rebuild it passes. | The full list on CI stays unknown until the fixed workflow runs. |

### Phase 1: security

| Step | State | What changed | Tests |
|---|---|---|---|
| 1.1 secrets never stored | done | `internal/ingest/redact.go`, applied in the processor before the merge. The WASM host no longer copies the emitted line as the raw payload of a secret finding. Migration **00058** scrubs stored rows, lifting FORCE RLS inside its transaction. D149, plus the D147 correction. | New `redact_test.go` (hostile record, nested key, renamed key, short value). `native_reports_test.go` now also checks `normalized`. 00058 applied on PostgreSQL 16. |
| 1.2 VEX inside an SBOM | partial | The gateway sets `context.vex_decider` from the caller, never from the client. Without a decider nothing is applied and `stats.vex_skipped` counts it. Only the uploaded asset is touched. No VEX from ephemeral runs. A statement without a time never overrides a person. A decided finding is scored again. VEX-only is detected by content, not by the name `openvex`. D150. **Left:** turning a CI token's statements into requests a triager approves (Q2), and CycloneDX statements still taking the document's `metadata.timestamp` as their time. | Two existing tests updated to a triager upload. New `TestProcessSBOM_OpenVEX_FromACITokenDecidesNothing` (CI token, then triager, then another asset). New `vex_decider_test.go`. |
| 1.3 federation | done | A federation must name `provider` (and then the D22 immutable ids) or `repositoryClaim` and `refClaim`. The token is bound to those claims. The operator **and** `rampart apply` (which ignored `auth` before) replace the rules every time, with an empty list too. Disabling a source deletes its rules. Migration **00061**. CRD in both copies, plus the bundle (`crds-bundle.py --check` passes) and the chart example. D151. | Domain validation test, generic-issuer binding test (feature branch uploading as main is refused), operator revocation test. Old fixtures that encoded the unsafe behaviour were updated. |
| 1.4 external trackers | partial (done by an agent) | TLS unless `tls.insecure: true`; `caSecretRef` and `auth.secretRef` are refused; a namespaced tracker or analyzer may only name a Service in its own namespace; one cached gRPC connection per tracker, closed on spec change and at shutdown (`internal/connectors/tracker_conns.go`); `examples/external-tracker` sets `insecure: true`. A ticket reference belongs to its connector (`FindingHasTicket` and `FindFindingByTicketRef`, done by me). D152. **Left:** `live_event` triggers for tickets (the "Live updates via SSE" text was removed instead); stored analyzer rows are re-checked for the namespace rule only at their next reconcile. | `tracker_conns_test.go` (25 resolves make 1 dial; a spec change makes 1 new dial; nothing dials after Close; a foreign namespace is refused); a PostgreSQL ticket test with another connector. |
| 1.5 advisory live fetch | partial (agent) | Page views read only the database. Refresh needs the triager role, runs one fetch per id at a time, and has a 5-minute cooldown (429 with Retry-After; 409 in stored mode; 502 without upstream text). Writes go through the system pool, or nothing is stored and the log says so. The NVD key comes from `feeds.nvdApiKeyFile`. v4 scores no longer land in the v3 fields. The sweeper's priority and lock bugs are fixed. D152. **Left:** the sweeper is still not wired (Q5); `ClusterAdvisorySource` is still read by nothing (mode always hybrid). | `query/vulnerability_refresh_test.go`; enrich tests (no upstream call on a page view, 403 for a viewer, single flight, 429, no echoed error). |

### Phase 2: correctness

| Step | State | Note |
|---|---|---|
| 2.1 in-flight cap | done | Counts through the system store (`SetInFlightCounter`, wired in `runner.go`). Without `database.systemUrl` the cap is not applied. D153. |
| 2.2 cooldown | done | Migration **00062** adds `sbom_analysis.last_manual_at`, which later claims keep. The cooldown also covers `POST /assets/{id}/analyze` (429). A failed dispatch now answers 503. Test updated: the manual time survives the sweep's claim. |
| 2.3 duplicate merge during retry | done | A non-final failure keeps the row `pending` with its error; `failed` or `timed_out` is written on the last attempt. Analysis tests updated. |
| 2.4 analyzer family collision across kinds | **not done** | A `ClusterSBOMAnalyzer/osv` and a `ClusterExternalAnalyzer/osv` still share `analyzer:osv`. The plan proposes refusing the second name. |
| 2.5 repository binding | partial | `.git` is now matched as a suffix. A reference matching several applications is refused (`AmbiguousApplicationRef`). PostgreSQL test added. **Left:** selector mode matches `application.tags`, which no CRD field fills, so it still cannot match on PostgreSQL. |
| 2.6 fail closed on a source lookup error | partial | Three of the four reads now refuse the upload (503, or the transaction fails). The read before the category check on the presigned path still treats a lookup error as "no source" and skips the check. Not covered by a test. |
| 2.7 clean rescan | done | Scope is the parser's name, not its id. The test fails without the fix ("closed 0 of the 3") and passes with it. |
| 2.8 old parser ids | done | Migration **00059** rewrites `builtin:`, `lua:` and `wasm:` to `cluster:`, and scope families to the tool's name. |
| 2.9 presigned fail-fast, orphan asset | **not done** | `handleCompleteUpload` still creates a run without checking that the modules are present; a 404 on the direct path can still leave an asset behind. |
| 2.10 cascade | done | Migration **00060**: `ON DELETE SET NULL`. |
| 2.11 ticket reference per connector | done | See 1.4. |
| 2.12 `POST /inventory/components/scan` | done (agent) | Answers 501 with the reason. **Left:** the two UI buttons that call it (`InventoryRoute.tsx:73`, `ApplicationSBOMSection.tsx:123`) are still there and show the 501 reason. |
| 2.13 chart | done | The bootstrap Application renders `displayName` (no `name`, `lifecycle` or `tags`, which the CRD prunes). The values example names a tenant namespace. Chart 0.3.27. `helm lint` and `helm template` pass with both parser delivery files (local only). |

### Phase 3: the UI tells the truth (done by an agent)

| Step | State | Note |
|---|---|---|
| 3.1 bands from the server | done | Bounds come from `/api/v1/scoring` (`risk.bands`). An application's band is the worst band of its open findings. There is no `info` band. Score card test and mock fixed. |
| 3.2 classes outside the theme | done | About 150 uses in 26 files replaced. New guard test `web/src/styles/themeClasses.test.ts`. |
| 3.3 polling | done | Removed from Ingestion, Overview and TopBar; the fallback runs only without SSE. |
| 3.4 design rules | done | KPI tiles, "% of scale", "In policy", pulse dots and pills are gone; state is said in words. The `NO-BUILTIN` badge is unchanged (Q6) and exempted from the guard test. |
| 3.5 words | done | Missing i18n keys added. `scanNowTooltip` corrected. Dependency-Track types and mock routes removed. The docs/41 refusal reason is shown with no Try again. Scanner evidence shows load errors and shares one query. A missing SLA cell says "Not configured". |
| 3.6 mock contract | done | `{sources, total}`, like Go. |
| 3.7 retire `/integrations` | done | See section 4. |

### Phase 4: decisions and documents

| Step | State |
|---|---|
| 4.1 ScanSource: retire or extend | **waiting on the owner (Q1)** |
| 4.2 correct docs/48's claims | not done |
| 4.3 D-entries | done: D149 to D154, plus the D147 correction |
| 4.4 docs/09, docs/12, docs/35 status | not done |
| 4.5 correct docs 42 to 49 | not done (only D147) |
| 4.6 pin `.github/parser-modules.env` | not done (still `main`) |

## 4. docs/50: retiring `/integrations`

| Step | State |
|---|---|
| 1. connector `kind` from the server | done: `domain.ConnectorKindOf`, a `kind` field in `GET /api/v1/connectors`, and `connector_kind_test.go` (every accepted type has a kind; deferred types have none) |
| 2. `/notifiers` | done, with its own icon |
| 3. parser packages on `/parsers` | done: runtime, version, error and "used by" in the inspector |
| 4. "API access" in Administration | done: issues no token, does not present `tokenSecretRef` tokens as working |
| 5. navigation and redirect | done: `/integrations` redirects to `/notifiers` (`replace: true`) |
| 6. removals | done: `IntegrationsRoute.tsx` and its test deleted; the catalogue dialog moved to `web/src/features/connectors/` |
| 7. Dependency-Track words | done |
| 8. tests | done (with axe) |
| 9. docs | partial: recorded in D154; **docs/13 not updated** |
| 10. battery | the frontend part passed (below) |

## 5. Migrations added

| Number | Purpose | Applied locally |
|---|---|---|
| 00058 | scrub secrets in `occurrence.raw` and `normalized` (FORCE RLS lifted inside the transaction) | yes, PostgreSQL 16 |
| 00059 | `builtin:`/`lua:`/`wasm:` parser ids to `cluster:`; scope families to the tool's name | yes |
| 00060 | `scan_source.application_id ON DELETE SET NULL` (`-- expand-safe:` marker) | yes |
| 00061 | `source_trust.repository_claim`, `ref_claim` | yes, in the later single-test runs |
| 00062 | `sbom_analysis.last_manual_at` | yes, in the later single-test runs |

All are expand-only. 00058 and 00059 change data; run them on the dev cluster first with a count (Q3).

## 6. Verification: what ran and what did not

**Ran and passed (package by package, while working):**
- `internal/ingest` (full package, about 170 s); `internal/domain`; `internal/config/...`; `internal/analysis`; `internal/query`; `internal/targets`; `internal/connectors`; `internal/operator`. **For the operator, the envtest tests did not run** (`KUBEBUILDER_ASSETS` is not set locally): only the reconciler unit tests ran.
- PostgreSQL (local container): the targeted tests `TestRunErrors_RecordsAndRawReport`, `TestFindApplicationByRef_OnPostgreSQL` and the ticket tests. Before the last changes, the full store suite ran once: 106 passed, with the one stale-module failure explained in 0.4.
- `go build ./...`, `go vet` and gofmt on the touched packages.
- Frontend (the agent's final run): `bun run typecheck`, `bun run lint`, `bun run test` (51 files, 339 tests), `bun run build` (one Vite warning: a chunk over 500 kB, possibly not new).
- Trackers and advisory (agent): `go test -race` for connectors, tracker, enrich, query, jobs, config, config/apply, targets and examples.
- `python3 hack/crds-bundle.py --check`: 27 CRDs. `helm lint`. `helm template` with both parser delivery files.

**Not run:**
- The full battery after the last change: started, then stopped at the owner's request.
- The full store suite with `-race` after migrations 61 and 62.
- The operator envtest suite.
- Playwright e2e.
- The fixed CI workflow on GitHub.
- Anything on a cluster (by rule).

## 7. Screenshots

Taken by the UI agent with Playwright and Chromium against the dev mock server, desktop 1440×900. **I have not looked at them myself.**
They are in the session scratchpad, which a reboot can clear; copy them into `docs/images/` to keep them.

| File | What it shows |
|---|---|
| ![](/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/ff220f8d-23fe-4eea-a45f-200dd227cfe1/scratchpad/screens/01-application-scorecard.png) `01-application-scorecard.png` | Billing, 650 High; band markers at 300/600/800 from the server |
| ![](/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/ff220f8d-23fe-4eea-a45f-200dd227cfe1/scratchpad/screens/02-application-scorecard-dark.png) `02-application-scorecard-dark.png` | Checkout, dark theme, 1000 Critical |
| ![](/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/ff220f8d-23fe-4eea-a45f-200dd227cfe1/scratchpad/screens/03-finding-detail-evidence.png) `03-finding-detail-evidence.png` | Finding page: state in words, scanner evidence |
| ![](/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/ff220f8d-23fe-4eea-a45f-200dd227cfe1/scratchpad/screens/04-notifiers.png) `04-notifiers.png` | The new `/notifiers` page: notifier connectors and packages |
| ![](/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/ff220f8d-23fe-4eea-a45f-200dd227cfe1/scratchpad/screens/05-ticketing-bindings.png) `05-ticketing-bindings.png` | Ticketing bindings, trackers only (filtered by `kind`) |
| ![](/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/ff220f8d-23fe-4eea-a45f-200dd227cfe1/scratchpad/screens/06-administration-api-access.png) `06-administration-api-access.png` | Administration, "API access" section |
| ![](/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/ff220f8d-23fe-4eea-a45f-200dd227cfe1/scratchpad/screens/07-parsers-mapping-package.png) `07-parsers-mapping-package.png` | Parser inspector of a mapping parser, with its package's compile error |
| ![](/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/ff220f8d-23fe-4eea-a45f-200dd227cfe1/scratchpad/screens/08-compliance-refusal.png) `08-compliance-refusal.png` | Compliance: the server's out-of-scope reason, no Try again (docs/41) |
| ![](/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/ff220f8d-23fe-4eea-a45f-200dd227cfe1/scratchpad/screens/09-integrations-redirect.png) `09-integrations-redirect.png` | `/integrations` landing on `/notifiers` |
| ![](/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/ff220f8d-23fe-4eea-a45f-200dd227cfe1/scratchpad/screens/10-about-scoring.png) `10-about-scoring.png` | About: scoring factors and bands in words |

## 8. What is left, in order

1. **Run the full battery yourself** (AGENTS.md section 5): `go test -race ./...` with `RAMPART_WASM_DIR=$PWD/.cache/wasm`, the store suite on PostgreSQL, the operator suite with envtest, `bun run typecheck/lint/test/build`, Playwright, and `helm lint`/`template`. Then push to a branch and check that CI is green **for real** now: a red result is expected the first time, if it uncovers more hidden failures.
2. **Answer Q1 to Q6** (section 9). Q1 (ScanSource) blocks docs/35 AB3 and AB4, and the docs/48 corrections.
3. Finish the open steps:
   - 2.4 (analyzer name across kinds);
   - 2.9 (presigned fail-fast, orphan asset);
   - 2.6's last read;
   - 2.5's selector mode;
   - 1.2's requests flow;
   - 1.4's ticket live events;
   - 1.5's `ClusterAdvisorySource` and the sweeper, after Q5;
   - remove the two UI buttons that call the 501 route;
   - handle 403/429/409 on the vulnerability refresh button in the UI.
4. Fix `hack/test-modules.sh`: it decides by file times, so a checkout or pull can leave a stale module, as happened to `semgrep` here. It should compare against the source commit or a content hash.
5. Documents:
   - docs/09: a status table that covers D120 onward, and remove "including Dependency-Track";
   - docs/12: the delta table, which stops at 42;
   - docs/35, section 00;
   - docs/13: the navigation section;
   - correct the claims of docs 42 to 49 and docs/48 (docs/51 4.2 and 4.5);
   - pin `.github/parser-modules.env`.
6. Phase 4 of the roadmap (hardening to v1.0) has not started.

**Left in the environment:**
- A PostgreSQL test container named `rampart-test-pg` (port 5433) is still running. Stop it with `docker rm -f rampart-test-pg`.
- `.cache/wasm` was rebuilt from the sibling repositories.
- The old semgrep module was moved to `/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/ff220f8d-23fe-4eea-a45f-200dd227cfe1/scratchpad/semgrep-old.wasm`.

## 9. Owner decisions, and what was assumed meanwhile

| # | Question | Assumed in the code until answered |
|---|---|---|
| Q1 | ScanSource: retire it (D139, D140) or keep it extended (docs/48)? | Nothing assumed. ScanSource was fixed where it was unsafe, not extended or removed. |
| Q2 | May a CI token change triage through VEX? | No. Its statements are skipped and counted; not turned into requests yet. |
| Q3 | Run the data migrations 00058/00059 on dev first? | Written; not run on any cluster. |
| Q4 | Should vulnerability pages fetch live? | No. Only the refresh button, by a triager. |
| Q5 | Wire or delete the docs/44 sweeper? | Neither. Its bugs are fixed and it is left unwired. |
| Q6 | Keep the `NO-BUILTIN` badge? | Kept, unchanged. |

## 10. Opinion

The foundation is strong. Phases 0 to 3 were built with tests, decisions and reasons, and the CI is broad (PostgreSQL with RLS, envtest, Playwright, Compose, kind). The work of 2026-11-20 to 2026-11-26 was done faster and outside that discipline. It shipped real security holes (stored secrets, triage by a CI token, federation without a branch, credentials in clear text). It added docs that claim things the code does not do, and decisions with no D-entry. And it ran behind a CI that had hidden failing tests since 2026-11-11.

Today's fixes close the most serious of those holes, each with a test, but the tree has not been verified as a whole yet. **It is not ready to release until the full battery and the fixed CI are green.** Three suggestions:

1. Stop adding features until docs/09 tells the truth again.
2. Decide Q1, because ScanSource is now half-retired and half-extended.
3. Keep the rule that every new doc gets a D-entry and that any "done" or "verified" in a doc names the test that shows it.
