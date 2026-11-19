# 35. Execution plan for what docs 29 to 33 describe and is not built yet

Status: plan, being executed (see section 00 for what has landed). Written 2026-11-18. It follows [docs/34](34-review-and-fix-plan.md), which lists what is wrong in the work already in the tree. Frontend work is collected in one last phase on purpose (the owner's decision), so each earlier phase is backend, CRDs, chart and docs only.

Sizes are relative: S is a day or less, M a few days, L about a week or more. They are estimates, not commitments.

## 00. Progress (kept current; the owner commits)

Landed in the working tree, each with tests. "Run by me" means the package tests of the touched packages, `go build ./...` and `go vet`; the full suite, the PostgreSQL store tests and the Helm lint are the owner's.

| Step | State | What changed |
|---|---|---|
| A (F1 to F7) | done | dangling `dtEnqueuer` removed; `-- expand-safe:` marker and its policy test; CRD copies identical |
| B1, B9 | done (delivery), B16 later | `internal/wasmstore` (digest table, strict mode, start-up check), chart `parsers.delivery.mode=imageVolume`, `ArtifactSynced` is `Unknown/NotPulled` instead of a false `True` |
| B2 | done | one detection engine (`domain.DetectSpec.Score`, one scale, auto-select threshold 40) for compiled-in, WASM, Lua and SBOM parsers; the old scorers are weights in the YAML |
| B5 | done | per-record error protocol (`RAMPART_RECORD_ERRORS`, `{"__record_error":...}`) in the host and the 14 modules |
| B8 | done | a tenant `Parser` accepts `mapping` and `declarative` only |
| **C1** | **done** | one SBOM host (`internal/sbom/host.go`). The run fails on a module that does not compile, traps, exits non-zero, exceeds its memory (spec `limits.maxMemoryMB`, default 1024) or time (2 minutes), writes a line that is not JSON, or writes a component or edge that names nothing. A module that recognises nothing in the document fails the run. The processor no longer logs and goes on |
| **C2** | **done** (revised by D131) | an SBOM reader is assets by default; `options.extractVulnerabilities` (default false) turns the vulnerabilities a CycloneDX document states into findings of the family `sbom-<format>` (never from a CPE): domain, three YAML specs, both CRD copies, chart value, module (JSON and XML), host, processor, tests |
| **C3** | **done** (this repository) | `sbom-syft` is a `ClusterSBOMParser` and a streaming module (`parsers/wasm/sbom-syft`); the Syft `ClusterParser`, its module and its chart entry are gone; **one rule "is an SBOM": the parser is an SBOM reader (`sbom.IsReader`)** in the gateway and the processor; the SBOM endpoint answers 400 for a report that is not an SBOM; the CLI no longer tries readers (C9) |
| **C8** | **done** except the gate | an SBOM run (`Processor.processSBOM`) takes no part in the merge, the scan-finished clock or the close of a scope, records no scope, and an ephemeral SBOM run stores nothing. "The gate waits for the match job" needs E5 |
| **C9** | **done** | the CLI names the parser (D130): `--parser` required, `--detect` opt-in, no format list in the CLI; `sbom graph/path` need `--parser`; the unknown-parser 400 lists the installed names; the upload response carries `parser` and `detected`. Still open: `GET /api/v1/parsers` (cluster and SBOM parsers) |
| **G-graph** | **done** (pulled forward at the owner's request) | dependency graph: `graph.BuildView`, `ListPackageRisk`, the graph API without Mermaid, direct flags computed once in the host, the drawn tree, list, inspector, search and filter (D132); `extractVulnerabilities` restored (D131) |
| **D0, D1 to D6** | **done** (D7 to D9 open) | docs/33 corrected (section 0), docs/04 describes the real ClusterFeed; conditional requests, the 429 handling, the guarded HTTP client, token files and egress, the CRD surface (`enabled`, `nvd.tokenFile`, `osv.ecosystems`), migration 00050 and the OSV writer, storage modes; the scheduler keeps syncing (D134); the reason a feed is off and the `RampartFeedStale` alert (D137) |
| **Scoring example** | **done** (D138) | `docs/examples/payments-scoring/`: one application, one commented file per resource (five: no `ScanSource`, D138, D139), and every resource that controls its score, applied and asserted by `scoring_example_test.go` (docs/36 section 15); the invalid `RiskPolicy` block of docs/04 replaced by one that compiles, with a test that parses it |
| **Retire `ScanSource`** | **decided, not started** (D139, D140) | the analyzers took its role; the three things it carried get homes: branches on the `Application`, `ingestion` on the `Application`, `ciTrust` on the `Tenant` (the last two await the owner's yes). Done in AB3 and AB4 below |
| **AB1** | **done** (D140) | `Application` has `type` (only `repo`; `machine` refused with its reason), `repository`, `branch` and `environment`: the domain and its validation, migration 00051 (schema version 51, with database checks), the store (read, write, the person's PATCH), both CRD copies, `app.type` and `app.environment` in the risk policy, the built-in `PRODUCTION_ENV` reads the environment (no default, so no score moved), `GET /api/v1/scoring` lists the allowed values, the page's context carries them; the frontend types, the Settings tab (environment, and what the application is), the framework marks for the policy chart's frameworks and a fallback that retries a changed logo address. Tests: domain, risk, apply, PostgreSQL end to end (the environment reaches the stored score), query, and the settings tab. **Not in AB1:** nothing resolves an upload by branch yet (AB2), so `repository` and `branch` name and show an application but do not yet claim its uploads |
| **AB2** | not started (needs AB1) | resolution by repository and branch: the asset key includes the branch for such applications, selectors match both, an unclaimed branch is Unassigned unless its name is ephemeral, `IsEphemeral` reads the tenant's applications instead of `ScanSource.trackedRefs`; D10 and D56 amended. Then the **guarded example is rewritten** as doc 36 section 16.2, and the hand-computed numbers (800 and 460) are asserted |
| **AB3** | not started (needs AB2, and the owner's yes on the homes) | `Application.spec.ingestion` and `Tenant.spec.ciTrust`: the ingest merge and the CI federation read them; a migration copies the stored `scan_source` rows (`ingestionPolicy` to the applications, `trustRules` and `source_trust` to the tenant) |
| **AB4** | not started (needs AB3) | remove `ScanSource` and `ClusterScanSource`: the CRDs (`deploy/crds` and the chart), the operator, the apply library, `internal/domain/scansource.go`, the store (migration that drops `scan_source`), the finalizers, the CLI and the UI that list sources, the `dependencyTrack` leftover (phase F); 41 files and 24 test files mention it today |
| **AB5** | not started (needs AB2) | the UI: the application list shows repository and branch, a view that groups applications by repository, create and edit with `environment` (the paused Settings tab of docs/36 section 8 returns here), the About page |
| **AB6** | not started | `type: machine`: a host source and a parser, the asset resolution for it (the `host` asset type), the page for it, then `machine` accepted in the CRD; after it `image` and `url`, which already have asset types |
| SPDX module | fixed | input that names no SPDX version is refused (it was reported as an empty SPDX 2.3 inventory) |

B14 (sibling repositories): done in the working trees, uncommitted (D133): `sbom-syft` added and `syft` removed in `sbom-parsers`, `sbom-cyclonedx` and `sbom-spdx` level with this tree, the record-error protocol in the 13 finding modules of `parsers`. Still open: their `pkg/` copies of the domain and the fingerprint can drift from this tree until one shared module and a fingerprint golden test exist (docs/34 F32).

Behaviour notes of C3 that differ from the old Syft finding parser: Syft gave one `license`-category finding per package; it now gives components. A directory source whose name and version match a package is the root, so the edges leaving it are direct (the old graph marked nothing direct for Syft). Findings that earlier runs of the old parsers (`builtin:sbom-*`, `syft`) created stay as they are until the matcher (phase E) owns that family; nothing closes them.

## 0. Update: the parsers live in two repositories

Read after the plan was written: `Rampart-Aspm/parsers` and `Rampart-Aspm/sbom-parsers` build the modules and publish signed OCI artifacts (`ghcr.io/rampart-aspm/<repo>/<name>`). See docs/34 section 0. Consequences for this plan:

- **Decided (owner, 2026-11-18): the shipped parsers reach the process through an init container, or an image volume where the cluster supports it, by digest. A registry client inside Rampart comes later, only for parsers added as resources, and it must not write to the operator's local disk** (the operator is a separate Deployment in docs/15; the parsing processes are stateless and share nothing with it; the chart runs `-target=all` with one replica today only because the targets are not split yet). See B1, B9 and B16.
- **B1 and decision 1 become "how this repository consumes those artifacts".** Options: (a) the Dockerfile fetches the published artifacts at image build time by digest, verifies the cosign signature and the digest table, and copies the modules to a fixed directory (works offline at run time, in Compose and without the operator; recommended); (b) the server or an init container pulls from the registry at start with the same verification (needs a registry client and a cache; the operator's `ArtifactSynced` condition then becomes true); (c) the Helm chart mounts them as image volumes (needs a Kubernetes version that supports them; not available in Compose). The file search for sibling directories stays only as a development convenience, behind an explicit `RAMPART_WASM_DIR`.
- **A new first task in phase B (B0, S):** correct the registry path in every resource (`ghcr.io/rampart-aspm/parsers/<name>` and `ghcr.io/rampart-aspm/sbom-parsers/<name>`), pin by digest, and make the SBOM loader find `sbom-parsers`.
- **B13 (the workflow in this repository)** is replaced by: delete `.github/workflows/wasm-parsers.yml` here; in the two repositories pass inputs through `env:` and give the publish job, not the test job, the write permissions.
- **New task B14 (M): one shared module for the types and the fingerprint** (docs/34 F32), with a fingerprint golden test in each repository; this is a prerequisite for B11 (the equivalence tests) to mean anything.
- B11's oracle is the deleted Go parsers in this repository's history; the tests themselves run in the two repositories' CI.

## 0b. Update: the resource model

Docs/34 section 0b. Changes to this plan:

- **B15 (S) is on hold, not done:** removing the namespaced `Parser` (both CRD copies, the operator registration, the RBAC, the tenant branch of `package_parsers.go`, docs/04 and docs/19) would also remove the tenants' own `mapping` parsers, a feature that was built and tested on the dev cluster. The owner's wording ("there is no CRD named parser, there is ClusterParser, SBOMParser and ClusterSBOMParser") was read as describing the shipped defaults, not as a decision to remove the tenant kind, so it is not removed. **B8 is done instead** (it closes F14 without removing the feature): a tenant's `Parser` accepts only `mapping` and `declarative` (validation in `rampart apply` and the operator, the CRD schema enum, and `tenantAndCluster` ignores a stored tenant parser with another runtime). Tell me if the tenant kind should go.
- **C2 is replaced (S):** remove the `vulnerability` event, the `extract_vulnerabilities` option and the host code that turns it into a finding, from the host and from the two modules (and from `sbom-parsers/wasm/syft` if it has it); an SBOM parse yields metadata, components and edges only. A test that every SBOM fixture, including CycloneDX with a VDR section and SPDX with CPE references, gives zero `RawFinding`.
- **C3 is restated (S):** Syft is an `SBOMParser`; remove the `syft` `ClusterParser` from `internal/config/parsers`, the chart and docs/31; one rule "SBOM means the resource kind" in the gateway, the processor, the CLI and the gate.
- **New task C8 (S):** an SBOM run does not run the scan-finished and mass-close path and the gate waits for the match job (this depends on E5); verify what the processor does today with a run that has no findings.
- The finding parsers are 17 (13 WASM and 4 Lua), not 18 or 21; B12's "counts agree" check uses that number.

## 1. Order and dependencies

```
A  Green tree (docs/34 section 3)
        |
B  Parser platform (docs/34 section 4)  --------+
        |                                        |
C  SBOM pipeline hardening (section 5)           |
        |                                        |
D  Feeds (doc 33, section 4 below)  ---- D1 independent items can start after A
        |
E  Native matcher (docs 30 and 32)   needs C (clean SBOM) and D3 (affected-ranges table)
        |
F  Dependency-Track leftovers and documents (can run beside B to E)
        |
G  Frontend, one pass (needs the APIs of B to E)
```

A is a prerequisite for everything: nothing can be tested while the tree does not build. B, C and D1/D2 are independent of each other and can be done by different people. E is the longest chain.

After every phase the owner runs: `go build ./...`, `go vet ./...`, `go test ./...`, the PostgreSQL store tests, `gofmt -l .`, `go mod tidy` (no diff), the Helm lint and the CRD-copy diff (`diff -r deploy/crds deploy/helm/rampart/crds`), and sends the output. This plan and the review did not run any of it.

## 2. Phase A: make the tree green (S to M)

Tasks F1 to F7 of docs/34, in this order: F1 (remove the dangling `dtEnqueuer`), F4 (`go mod tidy`), F7 (gofmt), F2 (the `-- expand-safe:` marker for migration 00049 and the policy test), F3 (copy the two CRDs into the chart; set `sbomAnalyzer.enabled: false` until a controller exists), F5 (fixture paths in the store tests), F6 (the WASM workflow).

Definition of done: the owner's commands above are green on a clean checkout. Then commit in small steps (the owner commits; this plan does not).

## 3. Phase B: the parser platform (L)

Goal of docs/29: no change of output, no change of speed, and a shipped image that works.

| Step | Task | Files | Size | Depends on |
|---|---|---|---|---|
| B1 | **Shipped modules by digest through an init container** (an image volume where supported): the chart lists each module image by digest in `values.yaml` (`ghcr.io/rampart-aspm/parsers/<name>@sha256:...`, `.../sbom-parsers/<name>@sha256:...`); an init container (or volume) puts the files in one fixed directory shared by the pod; the server reads a digest table at start, verifies each file, and **fails at start-up** if a default module is missing or does not match; pull secrets and a mirror for an air gap come from Kubernetes (`imagePullSecrets`, node mirror); signature verification is an admission policy on the cluster (Kyverno or the policy-controller), documented, not code in Rampart. For Compose: a helper service that fills a volume from the same images. The sibling-directory search stays behind `RAMPART_WASM_DIR` for development only | `Dockerfile`, `deploy/compose/Dockerfile`, `internal/integrations/wasm/parser.go`, `internal/sbom/*` (one shared loader), `internal/integrations/default.go` | M | A |
| B2 | One scoring scale, deterministic tie-break, refuse an ambiguous auto-detection, port the old scorers to `detect` weights | `internal/integrations/default.go`, `registry.go`, `internal/integrations/{wasm,lua}/parser.go`, `internal/config/parsers/*.yaml` | M | A |
| B3 | Resolution order in one function (decision 2): `byName` and `detect` use it; cluster resource can override or disable a default | `internal/ingest/package_parsers.go` | M | A |
| B4 | Fix the Lua host: read `location` (code, web, package, resource, image), `rule_name`, `cvss_vector`, `scanner_version`, `tool_severity`, `tool_record_id`, `raw_payload`; share one validated schema with the WASM host | `internal/integrations/lua/parser.go`, `parsers/lua/*` | M | A |
| B5 | Per-record errors in the guest protocol; bounded line length; close the pipe on early return | `parsers/wasm/*/main.go` (one shared wrapper), `internal/integrations/wasm/parser.go` | M | B1 |
| B6 | Sandbox: one limits helper (memory, time, output, stderr), clamp values, sanitised module paths, remove `dofile`/`load`/`require`/`print` from Lua, bound Lua input | `internal/integrations/{wasm,lua}/parser.go`, `internal/sbom/*` | M | B1 |
| B7 | Stored (database) parsers compile; compile errors go to the resource status | `internal/store/parsers.go`, `internal/ingest/package_parsers.go`, `internal/operator/*` | S | B3 |
| B8 | Tenants may not select `lua`, `wasm`, `native` (schema and validation) | `deploy/crds/parser.yaml` and the chart copy, `internal/integrations/declarative/declarative.go`, `internal/config/apply/apply.go` | S | A |
| B9 | Integrity: digest table (B1); **stop claiming a pull that does not happen now**: `ArtifactSynced` must not be `True`/`Pulled`/`verified` for a non-empty `source.oci` (set it from the digest check of B1, or leave it unset and say "loaded from the image"); a failed check is `False` with the reason | `internal/operator/reconciler.go` | S now, L for OCI | B1 |
| B10 | Aliases for retired ids (`builtin:cyclonedx`, `builtin:spdx`, `builtin:dependencytrack`, `dependency-track`) for two releases; keep category and asset type as before unless deliberately migrated | `internal/ingest/gateway.go`, `package_parsers.go` | S | A |
| B11 | Restore the tests: recover the deleted Go tests from git history and run them through the WASM host; fuzz target; secret-never-stored tests; fingerprint-stability tests; per-parser Detect tests; golden comparison old versus new for every parser (old Go output as the oracle); one benchmark per format with a CI threshold | `parsers/wasm/*`, `parsers/lua/*`, `internal/ingest/*_test.go`, `.github/workflows/ci.yml` | L | B1 to B6 |
| B12 | Packaging: remove the `dependencytrack` ClusterParser, add `timeoutSeconds` to the schema and read it, make the chart's parser count match the embedded set (a CI check), a CRD upgrade path (decision 6) | `deploy/helm/rampart/*`, `internal/config/parsers/*` | M | A |
| B13 | Workflow: build the package, `-trimpath`, inputs through `env:`, least-privilege, one tag scheme, rebuild-and-compare job (or stop committing binaries: decision 1) | `.github/workflows/wasm-parsers.yml` | S | A |
| B16 | **Dynamic pull for parsers added as resources (later, L):** when a `ClusterParser` or `SBOMParser` names a `source.oci` that is not in the shipped set, the process that will run it fetches it on first use (or a job stores the bytes in the object store Rampart already uses), checks the digest from the resource and the cosign signature, caches it, and the status says `Pulled`/`PullFailed` from the real result; no module is written to the operator's local disk; a resource may only name a registry on an allow-list (the SSRF rule, D69) | `internal/integrations/wasm/*`, `internal/sbom/*`, `internal/operator/reconciler.go`, `internal/objectstore` | L | B1, B9 |

Definition of done for B: for each parser, the golden test shows identical `RawFinding`s and identical finding keys to the old Go parser on its test data; the image starts in a clean container and parses one fixture per parser; the benchmark is within the agreed threshold (docs/29 section 7, decision 4); fuzz and secret tests exist for the secret scanners.

## 4. Phase C: the SBOM pipeline (M to L)

| Step | Task | Files | Size | Depends on |
|---|---|---|---|---|
| C1 | One SBOM host; fail the run on a non-zero exit, a malformed line or a missing module; validate every event; one pass for components, edges and findings; honour the `SBOMParser` spec | `internal/sbom/{parser,wasm}.go`, `internal/ingest/processor.go` | M | B1, B6 |
| C2 | Embedded findings: `VulnIDs`, `PurlBase`, real severity; never from a CPE reference; extraction follows the option | `internal/sbom/parser.go`, `parsers/wasm/sbom-*` | S | C1 |
| C3 | Syft SBOM reader and one "is an SBOM" rule in gateway, processor and CLI | `internal/config/parsers/syft.yaml`, `internal/ingest/*`, `cmd/rampart/cli.go` | M | C1 |
| C4 | Direct and transitive from the root's edges, order independent; fix XML revision versus spec version, nested components, licence expressions, `licenseDeclared`; say in the docs what is streamed | `parsers/wasm/sbom-cyclonedx`, `sbom-spdx` | M | C1 |
| C5 | Gate: restore family matching, the SBOM ids, a 400 for the retired name | `internal/query/gate.go` | S | B10 |
| C6 | Scope checks on the graph and path endpoints; one rule for an application with several assets | `internal/query/api.go` | S | A |
| C7 | Controllers for the SBOM and analyzer kinds, or stop shipping them (decision 5) | `internal/operator/*`, CRDs, RBAC | M | decision 5 |

## 5. Phase D: feeds (doc 33)

### 5.1 Gap table: what the spec says and what exists

| Item | Spec | Code now | Status | Needed |
|---|---|---|---|---|
| `nvd.tokenFile` | in the CRD | key only from server config `feeds.nvdApiKeyFile`, read once at start; the chart mounts no secret | DIFFERENT | `tokenFile` on `nvd`, read each round; chart mount |
| `osv.ecosystems` | in the CRD | only `feeds.osvEcosystems` / `RAMPART_FEEDS_OSV_ECOSYSTEMS`; the CRD cannot turn OSV on, in an air gap either | MISSING | `ecosystems` in domain, CRD, chart |
| `githubAdvisories` | a key, two paths | none; D88 did not build it (GHSA arrives inside the ecosystem archives) | MISSING | decide (decision 7) |
| `jvnIpedia` | a key | nothing | MISSING | new source or drop (decision 7) |
| `cisaKev`, `enisaEuvd` | key names | real keys `kev`, `euvd` | DIFFERENT | fix the document |
| EUVD sync | `/api/v1/advisories` | `/api/vulnerabilities?exploited=true&size=100&page=N`; keeps CVE aliases only | DIFFERENT | fix the document |
| VulnCheck | index API, cursors | backup link with SHA-256 check, full replace | DIFFERENT | fix the document, or build the index |
| EPSS, Exploit-DB, Metasploit, Vulnrichment | `url` | done (and `tokenFile` also accepted) | DONE | the EPSS `epss_date` is the sync time, not the file's score date: parse it |
| `custom[]` | name, url, format, tokenFile | also `pushTokenFile` (D94) | PARTIAL (document) | add to the document |
| `storageMode` | lightweight stores less, full stores raw and can mirror | only effect: `full` defaults OSV ecosystems to Go, npm, PyPI, Maven; both write the same columns | DIFFERENT | define real behaviour (D5) |
| `egress: deny` | blocks outbound calls | skips feeds that have no mirror URL; blocks nothing at HTTP level; the example, the preset and the chart write public URLs as `url`, so `deny` still reads the public endpoints | PARTIAL | reword; reject public defaults under `deny` (D4) |
| `checkTokenFile` | no relative paths, no symlinks, secret mounts only | `IsAbs` and `Clean` only | DIFFERENT | a directory prefix allow-list; not symlink rejection (Kubernetes secret mounts are symlinks) |
| NVD incremental | `lastModStartDate`, 120 days | done (cursor in `feed_state`, falls back to a full read beyond 120 days; delays 6 s keyless, 0.7 s keyed) | DONE | add 429, 403 and `Retry-After` handling |
| KEV conditional GET | ETag, If-Modified-Since | plain GET every round | MISSING | store the ETag in `feed_state.cursor`; handle 304 |
| OSV | zip per ecosystem, plus query batch | zip only, full download and rewrite each round; `withdrawn` and `severity` not parsed | PARTIAL | incremental by `modified`; parse withdrawn and severity; drop query batch (it would send SBOM inventory to api.osv.dev) |
| Cursors in `feed_state` | all incremental feeds | only NVD | MISSING | one for KEV and any new incremental feed |
| Metrics (8.2) | five named metrics | none exists; the older `rampart_feed_syncs_total` is defined but `RecordFeedSync` has no caller, so the `RampartFeedSyncFailing` alert and a dashboard panel never fire | MISSING and an existing bug | wire the calls; add the histogram and the rekey counter |
| `feed_state`, alias tables | as in section 8.1 and 5.1 | the migrations differ (nullability, foreign keys, tenant, RLS) | DIFFERENT | fix the document |
| `vulnerability_alias_local` | tenant-asserted aliases | read, never written | PARTIAL | add a writer or drop the claim |
| `finding_key_alias`, rekey | steps 1 to 4 | done; runs after each feed round, not as a job | DONE | reword; add a counter |
| `canonicalVulnID` | CVE else source id | first CVE alias else the OSV id | DONE | records with several CVEs: the first wins; define it |
| Affected-ranges table | not in the spec | nothing indexes `vulnerability.affected`; no reader | MISSING | add (D3): the native matcher needs it |

### 5.2 Steps

| Step | Task | Files | Size | Depends on |
|---|---|---|---|---|
| D0 | Correct doc 33 (docs/34 section 8): CRD keys, the OSV bucket, EUVD and VulnCheck descriptions, token path rule, DDL, storage mode semantics, `url` meaning per source (a full file for KEV, EPSS, Exploit-DB, Metasploit, Vulnrichment; a base address for OSV, EUVD, VulnCheck); fix the duplicate D121; add a decision entry | `docs/33`, `docs/16` | S | none |
| D1 | **Independent, no schema:** wire the existing feed metric and add the histogram and rekey counter; KEV conditional GET (ETag in `feed_state.cursor`); NVD 429 and `Retry-After`; parse the EPSS score date | `internal/telemetry/metrics.go`, `internal/enrich/{sync,fetch,nvd_sync}.go`, `internal/ingest/rekey.go` | S to M | A |
| D2 | **Secrets and egress:** `tokenFile` only under one dedicated prefix (not the directory that holds the session key, S3 keys and admin password), redact `tokenFile` and `pushTokenFile` from `GET /api/v1/feeds`, strip the NVD key on a cross-host redirect, validate feed URLs with the D69 guard (an allow-list for internal mirrors), check the host of the VulnCheck signed link, reject public default URLs under `egress: deny` | `internal/domain/feed_mirror.go`, `internal/query/feeds.go`, `internal/enrich/*`, chart | M | A |
| D3 | **CRD surface:** `nvd.tokenFile`, `osv.ecosystems` (and OSV under `deny` with a mirror), the chart secret mount and values; keep the real key names; one change set across `domain/feed_mirror.go`, `enrich/fetch.go` `applyMirror`, `targets/runner.go` (read the key each round), `query/feeds.go` (its duplicated defaults), the CRD and its Helm copy, `templates/clusterfeed.yaml`, `values.yaml`, `deploy/presets/clusterfeed-default.yaml`, `deploy/compose/resources/default-resources.yaml` | many | M | D2 |
| D4 | **Migration 00050 (expand-only, D124; 00049 is taken):** `vulnerability_affected(vulnerability_id, ecosystem, package_name_normalised, purl_base, range_type, introduced, fixed, last_affected, versions[], withdrawn)` with indexes on `(ecosystem, package_name_normalised)` and `purl_base`; a nullable `source` on `vulnerability_alias`; grants (system writes, app and ro read); bump `CurrentExpectedSchemaVersion` and `minSchemaVersion` to 50 | `internal/store/migrations/00050_*.sql`, `internal/store/migrate.go`, `values.yaml` | S | A |
| D5 | **OSV writer:** write the normalised rows per record, parse `withdrawn` and `severity`, incremental by `modified`, per-ecosystem name normalisation (the same function the matcher uses), emit the set of changed vulnerability ids for the re-match; alias provenance: record the source and restrict which sources may create an alias (the first writer wins today, so a wrong alias lets the rekey merge findings in every tenant) | `internal/enrich/sync.go` (`writeOSVChunk`), `internal/enrich/fetch.go` (`OnSynced` carries ids) | L | D4 |
| D6 | **`storageMode` semantics by behaviour:** what is stored (raw payload into `source_payloads` or not), which default ecosystems, how it relates to a mirror; stop writing near-empty rows for every EPSS CVE in lightweight mode | `internal/enrich/*`, `internal/domain/feed_mirror.go` | M | D5 |
| D7 | **New sources** (each independent, each with page and size caps, a cursor, tests, a status row, the SSRF guard): GHSA REST (only if decision 7 keeps it), JVN iPedia (XML, paging), VulnCheck index and cursors (only if decision 7 keeps it) | `internal/enrich/sources_sync.go`, `internal/domain/feed_mirror.go`, `internal/query/feeds.go`, tests | M to L each | D3 |
| D8 | **Attribution:** a NOTICE file and a place where the licence of each feed is shown (GitHub Advisory Database is CC-BY 4.0; other terms to be checked, none verified here) | repository root, docs | S | none |
| D9 | Source precedence for description, CVSS, CWE (today the description is first-writer) written down and implemented | `internal/enrich/*`, docs/16 | M | D5 |

Tests to update: `domain/feed_mirror_test.go`, `enrich/mirror_test.go`, `enrich/exploitation_test.go`, `store/feeds_test.go` (PostgreSQL), `store/rekey_test.go`, `query/feeds_test.go`, `config/apply/catalogue_examples_test.go`, `store/schema_version_test.go`. Documents: docs/04 (the ClusterFeed section), docs/16, docs/33, docs/30, docs/32.

## 6. Phase E: the native matcher (docs 30 and 32) (L)

Prerequisites: C1 to C4 (a trustworthy SBOM), D4 and D5 (the affected-ranges table).

| Step | Task | Files | Size |
|---|---|---|---|
| E1 | Corpus and differential harness: 15 to 20 real SBOMs; compare with Grype, Trivy, osv-scanner (Dependency-Track is gone, so the reference set is those three); record the threshold agreed in decision 4 | `testdata/sbom-corpus/`, a harness under `internal/analyzer/` | M |
| E2 | Matcher model: the OSV events, several ranges, `versions`, type, withdrawn; ecosystem comparators from maintained libraries (licence and API checked first); a test table per ecosystem including every wrong result in docs/34 F27 | `internal/analyzer/matcher/*` | L |
| E3 | Candidate store: implement `FindCandidatesByPurlBase` over `vulnerability_affected`; per-ecosystem name normalisation shared with D5 | `internal/store`, `internal/analyzer/matcher` | M |
| E4 | Output: `PurlBase`, `ManifestPath`, `DependencyPath` from the edges, ecosystem, scanner name, dedupe; keys stable and collision free; family name decided (decision 8) | `internal/analyzer/matcher/matcher.go` | M |
| E5 | The job: `sbom_match` per (asset, track) enqueued when an SBOM is stored; through the existing engine (idempotency, mass-close guard, closing on removal); ephemeral runs matched in memory for the gate | `internal/jobs`, `internal/ingest/processor.go`, `internal/query/gate.go` | L |
| E6 | Re-match after a feed sync using the changed ids from D5 (a periodic sweep as a backstop) | `internal/enrich/fetch.go`, `internal/jobs`, `internal/targets/runner.go` | M |
| E7 | Shadow mode for two releases: the matcher runs and writes a comparison report, not findings; then on by default | flag, report | M |
| E8 | External analyzer: TLS, allow-list, cluster-scoped only, honour the CRD fields, batching, retries and size limits, full response mapping, a correct example | `internal/analyzer/client`, `examples/external-analyzer`, `internal/domain/analyzer.go` | L |
| E9 | The refresh endpoint does what it says, or stays 501; the log line is true | `internal/query/app_refresh.go`, `internal/targets/runner.go` | S |

Definition of done: the differential harness meets the threshold on the corpus; re-uploading the same SBOM gives the same keys; a component upgraded or removed closes its finding; a feed change re-matches the affected assets; KEV and EPSS reach the findings.

## 7. Phase F: Dependency-Track leftovers and documents (S to M, beside B to E)

1. `ScanSource` and `Connector` CRDs: remove `dependencyTrack`, `connector`, `schedule` and the connector type with a deprecation window (decision 3), or reject them with a clear message now.
2. A migration to drain or delete queued `dtrack_sync` jobs; connectors of the retired type get a clear status.
3. Reverse D23 and D92 in docs/16 explicitly; say it in D128; update ADR 0006 and `adr/0002`; README, docs/04, 05, 10, 11, 12, 15 and the images.
4. `parsers/README.md` and `parsers/wasm/README.md`: the real directories; docs/02, 05, 09, 25 pointers to `internal/parsers`.
5. Correct docs 29, 31, 32 to say what is built and what is not (docs/34 section 9). Mark status words truthfully until each phase is done.

## 8. Phase G: frontend, one pass (after B to E)

**Owner's priorities for this phase (2026-11-18), in this order:** (1) the link from the dependency graph to the findings of a package (docs/34 section 10 item 14); (2) the database details of a CVE on the Application page, with the same panel as on the Finding page (item 15); (3) everything a parser reports, kept and shown, including properties a parser adds itself (item 16). Items 14 and 15 need a small backend step each (`purl_base` in the graph node; affected ranges and sources in the vulnerability record); item 16 needs a design decision on `RawFinding.properties` first.

Every item is in docs/34 section 10. The pass is planned as one change set once these backend facts are fixed: the parser list API (source, runtime, digest, verification), the feed CRD keys and statuses (D3, D7), the licence field (server-side classification), the application filter on the components API, the version field, the matcher status. The order inside the pass: remove dead Dependency-Track code and strings; Parsers page; Feeds page and its manifest printer; the application tabs (licences, graph, SBOM refresh); tests and i18n last.

## 9. Decisions needed from the owner

1. **How WASM modules reach the process. Decided: the shipped set by an init container or image volume, by digest (B1); a runtime puller later for added parsers (B16).** The options that were considered: (a) built into the image and checked against a digest table in the binary (works offline, in Compose and without the operator; still acceptable for Compose); (b) pulled from OCI with a digest and a cosign signature (needs a registry client and key management; docs/19 asks for it); (c) embedded in the binary (about 71 MB for 16 modules; heavier). Also whether the compiled `.wasm` files stay in git (not reproducible today) or are built in CI only.
2. **Resolution order** between embedded, cluster and tenant resources, and whether a cluster resource may disable a default.
3. **Dependency-Track CRD fields:** remove now or with a deprecation window.
4. **Acceptance thresholds:** the benchmark limit for parsers (docs/29 suggested 10%) and the matcher recall threshold against the other tools (docs/30 suggested 98%).
5. **The six new kinds:** build controllers for them, or ship only what is read (`ClusterParser`), and keep `ExternalAnalyzer` cluster-scoped.
6. **Helm and CRD upgrades:** a separate CRD chart, a pre-upgrade hook, or a documented manual step.
7. **Feed sources:** keep or drop GHSA REST, JVN iPedia and VulnCheck index. The OSV archives already carry GHSA records; JVN is a new XML source with its own terms.
8. **Family name** for native matcher findings and whether the double-count window with older findings is accepted.
9. **Attribution:** where licence notices are shown.

## 10. Risks

| Risk | Where | Mitigation |
|---|---|---|
| Finding keys change and findings are closed and reopened | parsers (B4, B10), matcher (E4) | golden key comparison before any switch; shadow mode |
| A Bandit report is parsed as Semgrep and closes real findings | detection (B2) | ambiguity is an error, cross-detection test |
| The shipped image cannot run parsers | B1 | image test in CI |
| A wrong alias merges findings across tenants | D5 | provenance and an allow-list of alias sources |
| An SBOM is truncated and saved as the newest | C1 | fail the run |
| Secrets leak through a token file path | D2 | one prefix, redaction in the API |
| The matcher claims results it does not produce | E9 | 501 until it works; docs say "not built" |
| Scope creep: three large changes land in one commit | all | A first, then small commits per step; the owner commits |
