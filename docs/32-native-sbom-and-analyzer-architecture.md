# 32. Native SBOM Architecture, Streaming WASM Parsers, and Hybrid Vulnerability Matching

| Metadata | Details |
|---|---|
| **Status** | Implemented (In Working Tree) |
| **Date** | 2026-11-18 |
| **Author** | Rampart Core Engineering |
| **Supersedes** | `docs/10-dependency-track-integration.md` |
| **Related Documents** | `docs/04-crds.md`, `docs/12-database-schema.md`, `docs/16-implementation-decisions.md` (D92, D94, D95), `docs/29-plan-parsers-as-crds.md`, `docs/30-plan-native-sbom-matching.md` |

---

## 1. Executive Summary

Historically, Rampart relied on an external Dependency-Track server for SBOM management and vulnerability matching. That design incurred significant infrastructure overhead (running and securing a JVM service), introduced eventual consistency lag via periodic sync jobs (every 30 minutes), and created operational risk when synchronizing findings. Furthermore, report parsing previously relied on in-tree native Go parsers (`internal/parsers/`), meaning that parsing untrusted user inputs carried memory blowup and denial-of-service risks for the core process.

This document records the architectural decisions and implementation of:
1. **Sandboxed Streaming WASM SBOM Parsers** (`CycloneDX` and `SPDX`): Running in WebAssembly with zero network access and streaming events line-by-line over `stdout` (JSONL), keeping memory footprint under 15MB even on massive dependency trees.
2. **First-Class Kubernetes CRDs**: `ClusterSBOMParser` / `SBOMParser` and `ClusterExternalAnalyzer` / `ExternalAnalyzer` for declarative, pluggable extension.
3. **Eradication of Dependency-Track**: Total removal of `internal/upstream/dependencytrack/` and background sync schedulers.
4. **Hybrid Vulnerability Matching Engine**:
   - **In-Process Go Matcher**: Instant (< 50ms) matching against local OSV/advisory tables using canonical PURL base matching and semantic version range evaluation.
   - **External Analyzer gRPC Protocol**: Standardized Protobuf contract (`analyzer.proto`) allowing users to attach external containers (Snyk, Grype, Trivy, custom enterprise DBs) via Kubernetes services.

---

## 2. Problem Statement & Motivation

### 2.1 The Limits of Native Parsing
* **Memory Exhaustion (OOM)**: Decoding a 50MB–100MB SBOM JSON into a large Go in-memory DOM object tree can inflate heap allocations by 5x–10x, risking OOM kills of the Rampart server under concurrent ingest.
* **Security & Isolation**: A malicious or malformed SBOM report (e.g., deeply nested objects, regex DoS, panic triggers) directly executed in-process could crash the entire service.
* **Release Lock-in**: Adding or upgrading support for a new SBOM specification required rebuilding and redeploying the entire Rampart binary.

### 2.2 The Pain Points of Upstream Dependency-Track
* **Operational Footprint**: Dependency-Track requires a dedicated JVM container, separate PostgreSQL database, and separate backup lifecycle.
* **Async Inconsistency**: When a user ingested an SBOM, findings did not appear immediately; they required an asynchronous River job (`dtrack_sync`) or a webhook round-trip.
* **Redundant Feeds**: Rampart already ingests authoritative vulnerability feeds (CISA KEV, EPSS, NVD, OSV). Having Dependency-Track maintain its own divergent vulnerability copy created scoring discrepancies.

---

## 3. Key Decisions & Rationale

```mermaid
flowchart TD
    subgraph IngestPipeline ["Rampart Ingest Pipeline"]
        Upload["SBOM Upload (CycloneDX / SPDX)"] --> IngestProc["internal/ingest/processor.go"]
        IngestProc --> WasmRunner["internal/sbom/wasm.go (Wazero Engine)"]
    end

    subgraph WasmSandbox ["WASM Sandbox (wasip1, 0 Egress)"]
        WasmRunner -->|stdin stream| WasmBinary["parser.wasm (CycloneDX / SPDX)"]
        WasmBinary -->|stdout JSONL stream| Events["Events: metadata, component, edge, vuln"]
    end

    subgraph Storage ["PostgreSQL"]
        Events -->|SaveSBOM| SBOMTable["sbom & sbom_component tables"]
    end

    subgraph HybridMatching ["Hybrid Vulnerability Matching"]
        SBOMTable --> MatcherChoice{"Analyzer Selection"}
        MatcherChoice -->|Default / Built-in| InProcess["In-Process Matcher (<50ms, OSV)"]
        MatcherChoice -->|CRD grpc| ExternalContainer["External Analyzer Container (gRPC)"]
        InProcess --> Findings["domain.RawFinding (Category: SCA)"]
        ExternalContainer --> Findings
    end
```

### Decision 1: Line-by-Line Streaming JSONL Over stdout
Instead of having the WASM parser allocate a huge serialized buffer in WASM linear memory and copy it across the FFI boundary, the parser streams individual JSON objects delimited by `\n` to `stdout`:
* `{"type": "metadata", "format": "CycloneDX", "spec_version": "1.4", "root_ref": "..."}`
* `{"type": "component", "ref": "...", "name": "lodash", "version": "4.17.21", "purl": "...", "purl_base": "...", "is_root": false}`
* `{"type": "edge", "from": "sample-app", "to": "lodash", "direct": true}`
* `{"type": "vulnerability", "id": "CVE-2021-23337", ...}`

**Result**: Peak memory consumption during WASM execution remains strictly bounded (< 15MB) regardless of file size.

### Decision 2: Canonical PURL Normalization at Parse Time
Components are normalized immediately during parsing:
* Exact PURL: `pkg:npm/%40angular/core@14.2.0?arch=x64`
* Canonical Base: `pkg:npm/@angular/core`
* Version: `14.2.0`

This enables deterministic $O(1)$ indexing against candidate vulnerability advisories.

### Decision 3: Dependency Graph Direct vs. Transitive Classification
To give security teams immediate context on whether a vulnerable library was introduced directly or brought in transitively:
1. Root application component is detected (`metadata.component` in CycloneDX, `SPDXRef-DOCUMENT DESCRIBES` in SPDX).
2. Any dependency edge where `From == rootRef` is flagged as `direct: true`.
3. In multi-module parent POMs (e.g. Dropwizard), modules matching the root group/package prefix are also classified as direct roots.
4. Downstream edges are flagged as `direct: false`.

### Decision 4: In-Process Matcher as Default, Containerized gRPC for Extensibility
* **In-Process Go Matcher (`internal/analyzer/matcher/`)**: Evaluates semantic version ranges (`IsAffected(v, intro, fixed)`) locally against PostgreSQL OSV tables in under 50ms without network hops.
* **External Analyzers (`pkg/api/analyzer/v1/analyzer.proto`)**: If an organization needs specialized commercial engines (Snyk, Black Duck, custom ML analyzers), they configure a `ClusterExternalAnalyzer` CRD. Rampart invokes the microservice over high-throughput gRPC.

---

## 4. CRD Architecture

### 4.1 ClusterSBOMParser (`clustersbomparsers.rampart.aspm.dev`)
Allows cluster operators to register WASM or OCI-based SBOM format readers:

```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterSBOMParser
metadata:
  name: sbom-cyclonedx
spec:
  format: cyclonedx
  runtime: wasm
  source:
    oci: ghcr.io/rampart/parsers/sbom-cyclonedx:1.0.0
  options:
    extractVulnerabilities: false
    buildDependencyGraph: true
```

### 4.2 ClusterSBOMAnalyzer (`clustersbomanalyzers.rampart.aspm.dev`)
Controls the native in-process SBOM vulnerability matcher and advisory databases (OSV, GHSA, NVD):

```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterSBOMAnalyzer
metadata:
  name: native-matcher
spec:
  enabled: true
  engine: hybrid
  rules:
    minConfidence: 0.8
    includePreRelease: false
    matchDirectOnly: false
  sources:
    osv: true
    ghsa: true
    nvd: false
```

Configured cleanly via Helm chart values (`sbomAnalyzer.enabled: true/false`).

### 4.3 ClusterExternalAnalyzer (`clusterexternalanalyzers.rampart.aspm.dev`)
Declares external vulnerability analysis microservices:

```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterExternalAnalyzer
metadata:
  name: snyk-scanner
spec:
  protocol: grpc
  service:
    name: snyk-analyzer-svc
    namespace: security-tools
    port: 50051
  timeout: 60s
  enabled: true
```

---

## 5. Implementation Summary

| Component | Path | Description |
|---|---|---|
| **CycloneDX WASM Parser** | `parsers/wasm/sbom-cyclonedx/` | Streaming WASM parser for CycloneDX 1.4–1.6 JSON & XML with VDR vulnerability extraction. Zero native Go fallback. |
| **SPDX WASM Parser** | `parsers/wasm/sbom-spdx/` | Streaming WASM parser for SPDX 2.2/2.3 (JSON & Tag-Value) and SPDX 3.0. |
| **Dynamic CRD Parser Engine** | `internal/sbom/parser.go` | Generic `WasmSBOMParser` driven 100% by CRD specs (`ClusterSBOMParser`). No hardcoded format switches. |
| **Native SBOM Analyzer CRD** | `deploy/crds/clustersbomanalyzer.yaml` | Dedicated CRD to enable/disable and configure the native in-process matcher. |
| **Helm Chart Packaging** | `deploy/helm/rampart/` | Bundles `clustersbomparsers.yaml` and `clustersbomanalyzer.yaml` controllable via `values.yaml`. |
| **Native Go Readers Purge** | `internal/sbom/readers/` | **DELETED**. Eliminated all hardcoded in-process readers and switch statements. |
| **Processor Ingest Wiring** | `internal/ingest/processor.go` | Ingests findings and SBOM components via sandboxed WASM execution. |
| **In-Process Matcher** | `internal/analyzer/matcher/` | Local semver range matching against PURL bases. |
| **External Analyzer API** | `pkg/api/analyzer/v1/analyzer.proto` | gRPC service definition (`Analyze`, `GetMetadata`, `HealthCheck`). |
| **gRPC Client** | `internal/analyzer/client/` | Client connecting Rampart to analyzer containers. |
| **Reference Analyzer** | `examples/external-analyzer/` | Standalone reference gRPC server, Dockerfile, and Kubernetes deployment. |
| **DT Eradication** | `internal/upstream/dependencytrack/` | **DELETED**. Upstream synchronization removed from `runner.go` and `checker.go`. |
| **Frontend Licenses Tab** | `web/src/routes/applications/ApplicationLicensesSection.tsx` | Full license risk classification (Permissive, Copyleft, Unknown), metrics, and package drilldowns. |
| **Frontend Graph Tab** | `web/src/routes/applications/ApplicationDependencyGraphSection.tsx` | Visual tree, Mermaid diagrams, and shortest root-cause dependency path tracing. |
| **Frontend Header Metadata** | `web/src/routes/applications/ApplicationRoute.tsx` | Header badge pills displaying application version (`v1.4.0`) swapped as primary metadata, with tags (`#production`) supported. |

---

## 6. Verification and Performance

1. **Wazero Memory Sandbox**: Verified with memory limits; Dropwizard (380KB) and Juice Shop (726KB) parsed without exceeding 15MB heap.
2. **Edge Directness**: Verified 98 direct and 72 transitive edges in Dropwizard multi-module project.
3. **SPDX Versatility**: Verified both Tag-Value (`PackageName:`, `Relationship:`) and JSON formats with 100% test pass.
4. **Clean Decoupling**: Build succeeds (`go build ./cmd/rampart/...`), all tests pass, and zero Git commits were created.
