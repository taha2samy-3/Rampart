# 29. Plan: every parser is a `Parser` resource, shipped by default ("all come in front door")

Status: Phase 1 & Multi-Runtime Engine Implemented (2026-11-18, docs/16 D127). All 21 parsers wrapped as ClusterParser CRDs with runtime: native, plus runtime: lua and runtime: wasm implemented and verified in CI.

## 1. The goal and the two promises

The owner's principle: a parser Rampart ships should come in by the same door as a parser a user writes. No parser is special because it is compiled into the binary. They are `Parser` custom resources, installed by the Helm chart by default.

Two promises must hold when a parser moves out of the binary:

1. **The same output.** The same input gives the same findings with the same finding keys. If a key changes, every existing finding is closed and a new one is opened (the key is a hash, D11), so this is the promise that matters most.
2. **The same speed.**

## 2. What is true today

### 2.1 The parsers

21 built-in parsers, about 7,400 lines of Go, all registered as `builtin:<name>` in `internal/integrations/default.go`:
sarif, cyclonedx, spdx, syft, openvex, genericjson, gitlab, trivy, grype, semgrep, gitleaks, trufflehog, checkov, bandit, dependencycheck, dependencytrack, snyk, nuclei, zap, prowler, kubebench. Aliases: generic, gitlab-sast, dependency-track.

### 2.2 What the declarative runtime can and cannot do

The runtime that exists is `runtime: mapping` (YAML plus CEL, `internal/integrations/mapping`, about 1,100 lines, the `Parser` CRD). It reads JSON (an array, or an object followed along a `$.a[*].b[*]` path) and streams records through `json.Decoder`.

It can set: RuleID, Title, Description, ToolSeverity, Severity (by map), ToolRecordID, VulnIDs, CWEs, CVSSVector, Category, Code{FilePath, StartLine}, Package{Purl, ComponentName, InstalledVersion, FixedVersion, ManifestPath}.

It cannot set (`domain.RawFinding`, `internal/domain/entities.go:374`):

- RuleName, RuleDescription, ScannerName, ScannerVersion
- SecretValue, SecretVerified
- VEX
- Code: EndLine, columns, LogicalLocation, Snippet, SnippetHash
- Package: DependencyPath
- Web (url, method, parameter), Resource (address, key, type), Image
- the scanner family per record
- path cleaning and NFC normalisation
- redaction of the raw payload (the record is stored as it came)
- anything that is not JSON (XML, SPDX tag-value), JSONL (not confirmed in the runtime), an SBOM or its graph

### 2.3 Why the finding key is the blocker

The key is `SHA-256("v1", family, scope, fields...)` (`internal/normalize/fingerprint.go`). Which fields depend on the category:

| Category | Fields in the key |
|---|---|
| SAST | RuleID, clean path, then the first of LogicalLocation, SnippetHash, hash of Snippet, else the start line (weak) |
| SCA | canonical vulnerability id, PurlBase, clean ManifestPath |
| Secret | RuleID, file, SnippetHash, else hash of SecretValue, else the start line (weak) |
| IaC | RuleID, file, Resource.Address, else the start line (weak) |
| Compliance / CSPM | RuleID, Resource.Key |
| DAST | RuleID, normalised URL, method, parameter |
| License | PurlBase, RuleID |

A mapping that cannot set SnippetHash, SecretValue, Resource or Web gives a different key for every SAST, secret, IaC, DAST and CSPM finding. The first run after the move would close all of them and open all of them again. That is the loss to avoid, and the reason the plan starts with equivalence tests.

Two smaller identity risks: the raw payload is the last-resort key input and the mapping stores a re-marshalled record where built-ins store a redacted one; and the descriptor id changes from `builtin:trivy` to `mapping:trivy`, so stored `parser` ids and `format=` hints in users' CI need an alias.

### 2.4 Speed (measured once, on a loaded laptop)

- No parser benchmark exists in the repo. Spike 6 (D-spike, `internal/integrations/spike_test.go`) documents about 80,000 records per second for path selection plus CEL; it was not re-run.
- A throwaway benchmark, 20,000 synthetic gitleaks records (9.9 MB): built-in 1.37 to 1.55 s (6.4 to 7.2 MB/s), a mapping that sets the same few fields 1.05 to 1.20 s (8.3 to 9.4 MB/s). The mapping was faster **because it did not redact**, so it is not output-equivalent; the built-in pays a second decode and an encode per record. Both are slow in absolute terms (about 70 microseconds per record), which is `encoding/json`, not the runtime.
- The ingest target of 100,000 findings in 60 s was not reached (about 130 s, D35). The cost is binding 35 parameters per row in `UpsertFindings`; parsing is about 7 s of the 130 (roughly 5%). Moving parsers does not touch the bottleneck.
- Not measurable: SARIF and XML, because the runtime cannot read them.

Conclusion on speed: no evidence that a mapping is slower, and parsing is a small part of ingest. It is still one synthetic case, so the plan adds a benchmark gate (Phase 0).

### 2.5 Deployment

- Only the namespaced `Parser` kind exists. A Parser CR belongs to a tenant by its namespace (`GetTenantByNamespace`); there is no `ClusterParser`. Cluster-scoped kinds do exist for policies, feeds and frameworks, so the pattern is known.
- The Helm `crds/` directory is installed on `helm install` and is not updated or removed on `helm upgrade` (Helm's documented behaviour). Default resources therefore go in `templates/`, not `crds/`; the chart already does this for `templates/clusterfeed.yaml`. A custom resource cannot be created in the same release as its CRD from `crds/` either.
- `deploy/presets/` and `internal/config/presets/` (embedded) hold default policies; nothing in Helm applies them (found by grep, UNVERIFIED beyond that).
- **Compose and "operator off":** `deploy/compose` has no operator. If parsers were only CRs, ingest would have no parsers there. `rampart apply` exists (UNVERIFIED how it stores a Parser).

## 3. The design

### 3.1 One door, three ways to read

A parser is always a `Parser` resource. What differs is how it reads:

- `runtime: mapping`: declarative, YAML and CEL (today's runtime, extended in Phase 2). For formats that are a list of records.
- `runtime: lua`: a script run by the host (section 3.1.1). For logic a mapping cannot express: the standards (SARIF, and the SBOM formats through their own resource, docs/30) and the tools that need state across records.
- `runtime: native`: names the compiled reader that exists today (`native: sarif`, ...). **A bridge, not a destination**: it exists so that Phase 1 changes nothing, and it is removed parser by parser as each is rewritten in `mapping` or `lua` and passes the gate.

This is the key move. **Phase 1 wraps all 21 built-ins as resources with `runtime: native` and changes no output and no speed**, because the code that runs is the same code. The principle ("all come in front door") holds from that day: every parser is listed, versioned, overridable and replaceable through the same resource. Moving a parser from `native` to `mapping` is then a separate, optional, per-parser decision that has to pass the equivalence gate.

The owner's decision (2026-11-18): the large standards (SARIF, CycloneDX, SPDX, Syft) do **not** stay native for good; they move to Lua. The owner also noted that carrying the whole principle through is hard and should be taken step by step, so the plan puts a measured gate in front of each step (Phase 3, Lua spike) and keeps `native` until the gate is passed.

#### 3.1.1 The Lua runtime

Design rule: **the host reads, Lua decides.** The host owns I/O and decoding (JSON as a stream, XML as events, SPDX tag-value as lines), so a 200 MB document is never loaded into Lua. Lua receives one record at a time and returns the fields. The host API (small and fixed): `records(path)` and `table(path)` (the lookup table SARIF needs, read once before the results), `emit(finding)`, and the helpers a mapping gets (`cleanPath`, `nfc`, `snippetHash`, `redact`, `derivePurl`, `sha256`, severity maps). The output goes through the same validator as a mapping's, so a script cannot emit a malformed finding.

Sandbox: only the base library (no `io`, `os`, `package`, `load`, `dofile`, `require`), a context deadline per file, a call-depth limit, no network, no clock except what the host passes in. gopher-lua (Lua 5.1, MIT) has no instruction or memory limit of its own: the deadline is by context cancellation, and memory is bounded by never loading a document (record at a time) and by the worker's memory limit. That is weaker than the WASM sandbox docs/19 chose for untrusted plugins. So: **Lua is allowed in `ClusterParser` (shipped by the chart, reviewed, signed), and a tenant's `Parser` stays `mapping` until a stronger Lua sandbox is built** (the rule of docs/19: a tenant may only use data runtimes).

**Measured (2026-11-18, throwaway benchmark, loaded laptop, one synthetic file):** 50,000 SARIF results (13.5 MB), rules table of 200 referenced by index. The compiled SARIF reader: 0.78 to 0.87 s (15 to 17 MB/s), 0.9 million allocations. A Lua function fed by the host, which only maps a handful of fields: 1.41 to 1.52 s (about 9 MB/s), 8.1 million allocations and 8.7 times the memory. So Lua was about 1.8 times slower on parsing and much heavier on allocation. Caveats: the Lua run decoded the whole document first (a streaming host would use less memory), it did less work than the compiled reader (no snippet hash, no path cleaning), and the machine was loaded. Parsing is about 5% of ingest (docs/29 section 2.4), so 1.8 times slower parsing is about 4% on the whole; the memory is the real cost. The gate in Phase 3 repeats this on the real parser with the real fields and a realistic large file.

### 3.2 Where the defaults live

Recommended (option A):

- The default `Parser` specs are YAML files in the repository, embedded in the binary (`go:embed`, like `internal/config/presets`), and also installed by the chart as **cluster-scoped** `ClusterParser` resources from `templates/` (so a `helm upgrade` updates them).
- At start the server loads the embedded set, then the `ClusterParser`s, then each tenant's `Parser`s. Later wins by name: a tenant's `Parser` over a `ClusterParser` over the embedded one. So a user can override or disable a default the same way they add a parser, and Compose or an operator-less install still works.

Option B (CRs only, nothing embedded) is not recommended: Compose and operator-off installs would ingest nothing.

New work for A: a `ClusterParser` kind (CRD, reconciler, a global store path in place of `parserSet.tenant` returning nil for no tenant), and the loading order.

### 3.3 Names and compatibility

- Keep `builtin:<name>` resolving, as an alias of the same name, for at least two releases: stored `parser` ids, `format=` hints, `expect:` in the gate and the CLI use them.
- `builtin wins ties` in detection (`package_parsers.go`) must become "the default of that name wins ties", with the same scoring; the hand-written scorers move into a `detect` block.
- `formatMismatch` (a wrong named format is refused, so an empty scan cannot close real findings) must hold for every resource, not only built-ins.

## 4. Phases

### Phase 0: the safety net (before anything moves)

1. **Golden output.** For every built-in, run it over all its test data and fuzz corpora and store the canonical `RawFinding` stream and the computed finding keys. This is the definition of "same output".
2. **Equivalence test** (`old == new`): for each parser, the old and the new reader give identical `RawFinding`s and identical keys on that corpus. A parser does not move until this is green.
3. **Parser benchmarks** (none exist): a benchmark per format on a realistic large file, with a threshold in CI (for example no more than 10% slower in ns/op and no more allocations than the built-in) so a regression is a failing build.
4. **Fuzz tests for the runtime** itself (the Go parsers have fuzz tests; the mapping runtime must have its own, over CEL and path selection).
5. **Shadow mode** (a flag): run both readers on a real upload, store the old result, log any difference. Used for one release before a parser is removed.

### Phase 1: wrap, no change (small)

Resource for each of the 21 as `runtime: native`; `ClusterParser` kind; embedded defaults; the chart template; aliases; the loading order; a `rampart parsers` listing showing source (embedded, cluster, tenant). Output and speed are unchanged by construction; the test is that the golden set still passes through the resource path.

### Phase 2: extend the runtime (the main work)

Add to `runtime: mapping`:

| Need | For |
|---|---|
| Output fields: SecretValue, SecretVerified, RuleName, RuleDescription, ScannerName, ScannerVersion, per-record family, full Location (EndLine, columns, LogicalLocation, Snippet, SnippetHash, Resource, Web), Package.DependencyPath, VEX | secrets, SAST, IaC, DAST, CSPM, VEX |
| `redact:` list of paths, applied to the stored raw payload | gitleaks, trufflehog, semgrep secrets, gitlab |
| JSONL input (confirm what exists) | trufflehog, nuclei, prowler |
| A lookup table read earlier in the same stream (`tables:`) | SARIF `rules[]` by index or id |
| CEL helpers: `cleanPath`, `nfc`, `snippetHash`, `cweList` (string or list), `derivePurl` (OS family) | trivy, semgrep, all |
| Nested walks (site/alert, results in results) | zap, trivy, checkov |
| Per-record `family` | gitlab (`gitlab-<kind>`) |

Secret handling is a security requirement: a secret must not reach the stored payload, the database or a log. Each secret parser needs a test that searches the stored payload for the secret.

### Phase 3: move parsers from `native` to `mapping`, in waves, each behind the Phase 0 gate

| Wave | Parsers | Why this order |
|---|---|---|
| 1 | grype, bandit, dependencycheck, snyk, the vulnerability rows of trivy | plain rows, most likely expressible today (UNVERIFIED against real vendor output) |
| 2 | gitleaks, trufflehog | secrets: redaction and SecretValue |
| 3 | semgrep, checkov, prowler, kubebench, nuclei, zap | SnippetHash, Resource, Web |
| 4 | genericjson, gitlab, dependencytrack, openvex | full field set, VEX |
| 5, `runtime: lua`, after the Lua gate | sarif | needs the lookup table (`table(path)`), snippet hash, logical location, the enrichers for Semgrep, Trivy and Gitleaks |
| 6, their own resource (docs/30) | cyclonedx, spdx, syft | an SBOM is not a list of findings: `SBOMParser`, also Lua, with XML and tag-value input from the host |

Each wave: write the mapping, pass equivalence on the corpus, pass the benchmark gate, run in shadow for one release, then switch the default and keep the Go reader one more release behind a flag.

### Lua gate (before any parser is written in Lua)

Repeat the benchmark above with the real SARIF fields, on a realistic large file (for example 100,000 results with real Semgrep and Trivy output), measuring time, allocations and peak memory, for the compiled reader and the script. Pass when the script's time is within the threshold chosen in decision 4 and its peak memory is bounded by the record, not the document. If it does not pass, SARIF stays `native` and the question is reopened with the owner (the alternatives are WASM, which docs/19 already plans for plugins, or Starlark, which is deterministic and has an execution-step limit).

### Phase 4: remove the Go readers that moved

Only after a release in which shadow mode logged no difference on real uploads.

## 5. What would be lost and gained

Honest list of what moving to `mapping` costs: the Go compiler no longer checks a parser's types; a parser's subtle logic that is in Go today (SARIF enrichers for Semgrep, Trivy and Gitleaks, `derivePurl`) has to be expressed in CEL or become a helper; error messages and detection scoring have to be reproduced. What it gains: a parser can be fixed or added without a release; users can read, copy and override a default; one path to test and to fuzz.

## 6. Risks and how the plan answers them

| Risk | Answer |
|---|---|
| Finding keys change, findings are closed and reopened | Phase 0 golden keys and the equivalence gate; nothing moves without it |
| A secret reaches the stored payload | `redact:` in the runtime and a test per secret parser |
| A mapping is slower | benchmark gate in CI; parsing is about 5% of ingest |
| Compose or operator-off install has no parsers | defaults embedded in the binary |
| `helm upgrade` leaves old default parsers | defaults in `templates/`, not `crds/` |
| Stored `builtin:` ids and CI `format=` stop working | aliases kept for two releases |
| A wrong named format closes real findings | `formatMismatch` applies to every resource |
| Detection picks a different parser | scorers move into `detect` and are tested on the corpus |

## 7. Decisions needed from the owner

1. Accept Phase 1 (`runtime: native` wrappers) as the first deliverable, with `mapping` migration as an optional, per-parser step afterwards.
2. Option A (embedded plus `ClusterParser`) or option B (CRs only).
3. ~~Whether the standards stay `native`~~ Decided: they move to Lua (SARIF as a `Parser`, the SBOM formats as `SBOMParser`), staged behind the Lua gate; `native` is only a bridge.
4. The benchmark threshold (suggested: 10% in ns/op).
5. How long the `builtin:` aliases and the Go readers stay (suggested: two releases).

## 8. To verify before building

- Whether `runtime: mapping` reads JSONL today (the doc comment says so; the code path was not traced).
- How `rampart apply` stores a `Parser`.
- Whether any Helm template applies `deploy/presets`.
- Each Wave 1 parser against real vendor output.

## 9. Implementation Record (Completed 2026-11-18, D127)

Phase 1 along with complete multi-runtime support has been implemented in the codebase:

1. **CRD Definitions Synced:**
   - `deploy/crds/clusterparser.yaml` & `deploy/helm/rampart/crds/clusterparser.yaml` (Cluster-scoped `ClusterParser`).
   - `deploy/crds/parser.yaml` & `deploy/helm/rampart/crds/parser.yaml` (Namespaced `Parser`).
   - Clean schema without hardcoded `spec.version` or redundant `spec.family`.
2. **Database Migration 49:**
   - `internal/store/migrations/00049_cluster_parser.sql`: Added `parser` kind to `cluster_policy` and `policy_object` CHECK constraints.
   - `CurrentExpectedSchemaVersion = 49` and Helm `minSchemaVersion: 49` synchronized.
3. **Multi-Runtime Execution Engine:**
   - `lua`: Sandboxed `gopher-lua` engine (`internal/integrations/lua/`) with JSON decoding/encoding and iterative finding yielding. Used for 4 flat parsers (`bandit`, `genericjson`, `nuclei`, `zap`).
   - `wasm`: Sandboxed `wazero` engine (`internal/integrations/wasm/`) running WASI preview 1 with zero network syscalls, bounded memory, and streaming JSONL over stdin/stdout. Works offline in air-gapped enterprise environments. Used for 17 security finding parsers.
   - `mapping`: Declarative CEL mapping parser (`internal/integrations/mapping/`).
4. **Resolution Precedence & Ingestion Pipeline:**
   - Precedence: `Tenant Parser` > `Cluster Parser` > `Embedded Defaults`.
   - `package_parsers.go` compiles and caches resources dynamically across `PostgresStore` and `MemoryConfigStore`.
5. **Helm Chart & Operator Integration:**
   - All 21 standard parsers deployed by default via Helm in `deploy/helm/rampart/templates/clusterparsers.yaml`.
   - Every default parser can be individually toggled via `parsers.defaultParsers.<name>.enabled: true/false` in `values.yaml`.
   - RBAC rules granted for `clusterparsers`, `clusterparsers/status`, and `clusterparsers/finalizers`.
   - Operator manager registers `ClusterParser` and `Parser` controllers with generation predicates.
   - Verified clean with `helm lint`, `helm template` (21 resources rendered), and 100% passing tests in `go test ./internal/...`.

## 10. Complete Removal of Native Parsers from Internal Codebase

In accordance with architectural decisions:
1. **Zero Native Finding Parsers in `internal/`:**
   - The legacy `internal/parsers/` directory has been completely eradicated.
   - Zero finding parsers are compiled natively into the Rampart binary. All 17 vulnerability/finding parsers run as sandboxed WASM modules, and 4 flat parsers run as sandboxed Lua scripts.
2. **Dedicated Native SBOM Readers (`internal/sbom/readers/`):**
   - Per docs/30, SBOM documents are component graphs rather than lists of vulnerability findings.
   - CycloneDX, SPDX, and Syft component extraction logic has been cleanly relocated to `internal/sbom/readers/{cyclonedx,spdx,syft}`.
   - These readers implement the strict `ParseSBOM` contract (`domain.SBOM`, components, dependencies) and are used exclusively for inventory storage (`saveSBOM`) and vulnerability matching.

## 11. WASM OCI Lifecycle, Observability, and Error Diagnostics

To achieve secure, observable, and isolated execution:

1. **WASM OCI Packaging & GHCR CI/CD (`.github/workflows/wasm-parsers.yml`):**
   - All 17 WASM parsers reside in self-contained directories under `parsers/wasm/<name>/` with their own `main.go`, `parser.go`, `Dockerfile`, and test suites.
   - GitHub Actions workflow automatically discovers parsers, builds them with `GOOS=wasip1 GOARCH=wasm`, runs unit and sandbox tests, packages them into scratch OCI containers, and publishes them to GitHub Packages (`ghcr.io/rampart/parsers/<name>:<version>` and `:latest`).
   - Supply chain security: OCI images are signed keylessly with Cosign and attested with SLSA Level 3 Provenance.

2. **OCI Image Pull Status Observability:**
   - The operator reconciles `ClusterParser` and `Parser` resources.
   - When pulling WASM OCI artifacts from GHCR / registries, the controller updates CRD status condition `ArtifactSynced`:
     - `status: "True"`, `reason: "Pulled"`, `message: "Successfully pulled OCI artifact digest sha256:..."`
     - `status: "False"`, `reason: "PullFailed"`, `message: "Failed to pull image: 401 Unauthorized / manifest unknown..."`
   - Surfaced directly in CLI via printer columns: `kubectl get clusterparser` displays `NAME`, `RUNTIME`, `CATEGORY`, `SYNCED`, `AGE`.

3. **Parser Execution Diagnostics & Root-Cause Failure Reporting:**
   - **Sandbox Exit & Crash Capture:** If a WASM module exits with non-zero exit code, times out, or exceeds memory quotas, Wazero intercepts the error, captures `stderr`, and attaches it directly to `ingest_runs.error_message`.
   - **Corrupted Record Isolation (`RecordError`):** If a parser encounters corrupted or unparseable JSON/text lines on stdout:
     - The line number and parsing error are intercepted via `RecordError` (`Where: wasm.stdout:line <n>`, `Message: ...`).
     - Stored into the `ingest_run_errors` table with exact line number, column, and raw payload excerpt.
     - Ingestion does not silently drop findings; developers and SecOps teams can inspect the exact reason for any parse failure via `GET /ingest/runs/{id}/errors`.


