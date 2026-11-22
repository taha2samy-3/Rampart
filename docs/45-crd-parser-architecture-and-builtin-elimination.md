# Document 45: Kubernetes CRD Parser Architecture & Root-Level Builtin Elimination

## 1. Executive Summary & Historical Context

A foundational principle of Rampart's cloud-native architecture is that **no scanner parser or SBOM reader is compiled into the binary** (D127 / D141). Every parser reaches the running process externally as an artifact (WASM module or Lua script) described by a Kubernetes Custom Resource:
- `ClusterParser` for cluster-wide report scanners (SARIF, Semgrep, Trivy, Checkov, Gitleaks, Grype, etc.).
- `ClusterSBOMParser` for cluster-wide SBOM readers (CycloneDX, SPDX, Syft).
- `Parser` for tenant-scoped declarative mapping parsers (e.g. `pip-audit`, `acme-audit`).

### The Legacy Anomaly: The `builtin:` Prefix
During the initial migration to Custom Resources, the internal identifier scheme retained an outdated prefix: `builtin:<name>` and `builtin:sbom-<format>`. Developers noted in code that *"builtin says it was installed for the whole cluster; it does not say it is compiled in: nothing is."* However, this created severe architectural contradictions:
1. **Misleading Nomenclature**: Users and auditors reviewing the UI table and API responses observed `builtin:bandit`, `builtin:semgrep`, and `builtin:sbom-cyclonedx`, misinterpreting them as hardcoded compiled-in parsers.
2. **Schema Drift**: Ingestion format hints and CLI switches were polluted with `builtin:` prefixes rather than referencing clean format names or authentic Kubernetes CRD resource names.
3. **Partial Fallbacks**: Lingering fallback checks across `internal/sbom/wasm.go`, `internal/integrations/registry.go`, `internal/ingest/package_parsers.go`, and frontend UI filters kept the obsolete keyword alive in code paths.

Following user direction, Rampart **v0.3.20+ completely purges the word, prefix, and concept of `builtin` from its roots** across all backend packages, SBOM parser handlers, UI tables, API schemas, and test suites.

---

## 2. Architecture Comparison

### Legacy Architecture (Contradictory & Misleading)
```
[ Kubernetes Control Plane ]
  ├── ClusterParser/semgrep       ──> Registered as ID "builtin:semgrep" (Support: "builtin")
  └── ClusterSBOMParser/cyclonedx ──> Registered as ID "builtin:sbom-cyclonedx" (Support: "builtin")
                                            │
                                            ▼
                               [ UI: "builtin:semgrep" ]
```

### Modern Architecture (Kubernetes CRD Native)
```
[ Kubernetes Control Plane ]
  ├── ClusterParser/semgrep       ──> ID: "cluster:semgrep"       (Resource: ClusterParser/semgrep)
  ├── ClusterSBOMParser/cyclonedx ──> ID: "cluster:sbom-cyclonedx" (Resource: ClusterSBOMParser/cyclonedx)
  └── Parser/acme-audit           ──> ID: "mapping:acme-audit"     (Resource: Parser/acme-audit)
                                            │
                                            ▼
                        [ Integrations Registry & Ingest Engine ]
                           - SupportLevel: "cluster" | "certified" | "community"
                           - Parser Format: --parser semgrep (clean format)
                                            │
                                            ▼
                        [ Modern Web UI & Parser Inspector ]
                           - Ref: ClusterParser/semgrep
                           - Ref: ClusterSBOMParser/cyclonedx
                           - Upload Format: --parser <format>
```

---

## 3. Implementation Details by Subsystem

### 3.1. SBOM Parser Engine (`internal/sbom/`)
- **`internal/sbom/wasm.go`**:
  `normalizeFormat(format string)` previously stripped `builtin:` as a fallback. That check has been completely removed. It now normalizes strictly on `cluster:` and `sbom-`:
  ```go
  func normalizeFormat(format string) string {
      format = strings.TrimPrefix(strings.ToLower(format), "cluster:")
      return strings.TrimPrefix(format, "sbom-")
  }
  ```
- **`internal/sbom/parser.go`**:
  `WasmSBOMParser` sets descriptor ID strictly to `cluster:sbom-` + `spec.Format` and support level to `SupportCluster`.

### 3.2. Integration Registry (`internal/integrations/`)
- **`internal/integrations/registry.go`**:
  - Deleted `SupportBuiltin SupportLevel = "builtin"` from Go types.
  - Defined canonical support tiers:
    ```go
    type SupportLevel string

    const (
        SupportCluster   SupportLevel = "cluster"
        SupportCertified SupportLevel = "certified"
        SupportCommunity SupportLevel = "community"
    )
    ```
  - In `GetParser(id string)`, purged all candidate lookups for `builtin:` and `builtin:sbom-`. Resolution now maps canonical `cluster:<name>`, clean format name, `cluster:sbom-<format>`, and `sbom-<format>`.

### 3.3. Ingestion & Package Parsers (`internal/ingest/`)
- **`internal/ingest/package_parsers.go`**:
  - Purged `s.registry.GetParser("builtin:" + engine)`.
  - Purged all `builtin:` and `builtin:sbom-` matchers in `matchName`.
  - In `parserName(p)`, removed `"builtin:"` from prefix stripping lists.
  - Updated `mismatchDetail` to utilize `parserName(actual)` so that format mismatch errors state clean parser names (e.g. `format=semgrep`) without leaking internal prefixes to users.
- **`internal/ingest/gateway_test.go`**:
  - Asserted that 400 responses listing available parsers never leak `cluster:` or `sbom-` prefixes.

### 3.4. Query & Compliance Gate (`internal/query/` & `internal/compliance/`)
- **`internal/query/parsers.go`**:
  - Removed fallback lookups for `builtin:`.
  - API responses for `/api/v1/parsers` explicitly emit `resource_kind` (`ClusterParser`, `ClusterSBOMParser`, `Parser`) and `resource_name`.
- **`internal/query/gate.go`**:
  - `runMatches` stripped of legacy `builtin:` strings.
- **`internal/compliance/compliance.go`**:
  - `CategoriesOf` stripped of legacy `builtin:` strings.

### 3.5. Frontend UI & Types (`web/`)
- **`web/src/api/types.ts`**:
  - `ParserDescriptor.support_level` typed strictly as `'cluster' | 'certified' | 'community'`.
  - Added `resource_kind?: 'ClusterParser' | 'ClusterSBOMParser' | 'Parser'` and `resource_name?: string`.
- **`web/src/routes/parsers/ParserList.tsx`**:
  - Subtitle in `ParserRow` renders `{ref}` (`ClusterParser/bandit`, `ClusterSBOMParser/cyclonedx`, `Parser/acme-audit`).
  - Purged all `builtin:` and `builtin:sbom-` regexes in family determination and filtering.
  - Inspector displays `CRD Resource` and `Upload Format (--parser <name>)`.
- **`web/src/routes/ingestion/UploadDialog.tsx`**:
  - Upload selector values cleaned to `p.id.replace(/^cluster:(sbom-)?/, '')`.
- **`web/dev/mock-server.mjs`**:
  - Mock server aligns with canonical `cluster:` IDs and zero `builtin:`.

---

## 4. Canonical Resource Mapping Table

| Tool / Format | Type | CRD Kind | Canonical ID | UI Reference (`ref`) | Upload Flag |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **bandit** | SAST | `ClusterParser` | `cluster:bandit` | `ClusterParser/bandit` | `--parser bandit` |
| **checkov** | IaC | `ClusterParser` | `cluster:checkov` | `ClusterParser/checkov` | `--parser checkov` |
| **dependencycheck**| SCA | `ClusterParser` | `cluster:dependencycheck` | `ClusterParser/dependencycheck` | `--parser dependencycheck` |
| **genericjson** | SAST | `ClusterParser` | `cluster:genericjson` | `ClusterParser/genericjson` | `--parser genericjson` |
| **gitlab** | SAST | `ClusterParser` | `cluster:gitlab` | `ClusterParser/gitlab` | `--parser gitlab` |
| **gitleaks** | Secrets | `ClusterParser` | `cluster:gitleaks` | `ClusterParser/gitleaks` | `--parser gitleaks` |
| **grype** | SCA | `ClusterParser` | `cluster:grype` | `ClusterParser/grype` | `--parser grype` |
| **kubebench** | Compliance | `ClusterParser` | `cluster:kubebench` | `ClusterParser/kubebench` | `--parser kubebench` |
| **nuclei** | DAST | `ClusterParser` | `cluster:nuclei` | `ClusterParser/nuclei` | `--parser nuclei` |
| **openvex** | VEX | `ClusterParser` | `cluster:openvex` | `ClusterParser/openvex` | `--parser openvex` |
| **prowler** | Compliance | `ClusterParser` | `cluster:prowler` | `ClusterParser/prowler` | `--parser prowler` |
| **sarif** | SAST | `ClusterParser` | `cluster:sarif` | `ClusterParser/sarif` | `--parser sarif` |
| **semgrep** | SAST | `ClusterParser` | `cluster:semgrep` | `ClusterParser/semgrep` | `--parser semgrep` |
| **snyk** | SCA | `ClusterParser` | `cluster:snyk` | `ClusterParser/snyk` | `--parser snyk` |
| **trivy** | SCA | `ClusterParser` | `cluster:trivy` | `ClusterParser/trivy` | `--parser trivy` |
| **trufflehog** | Secrets | `ClusterParser` | `cluster:trufflehog` | `ClusterParser/trufflehog` | `--parser trufflehog` |
| **zap** | DAST | `ClusterParser` | `cluster:zap` | `ClusterParser/zap` | `--parser zap` |
| **cyclonedx** | SBOM | `ClusterSBOMParser` | `cluster:sbom-cyclonedx` | `ClusterSBOMParser/cyclonedx` | `--parser cyclonedx` |
| **spdx** | SBOM | `ClusterSBOMParser` | `cluster:sbom-spdx` | `ClusterSBOMParser/spdx` | `--parser spdx` |
| **syft** | SBOM | `ClusterSBOMParser` | `cluster:sbom-syft` | `ClusterSBOMParser/syft` | `--parser syft` |
| **openvex** | SBOM / VEX | `ClusterSBOMParser` | `cluster:sbom-openvex` | `ClusterSBOMParser/openvex` | `--parser openvex` |

---

## 5. Verification & Zero-Regression Battery

The full verification battery required by Rampart engineering guidelines passed without errors:

1. **Frontend Type & Lint Check**:
   - `bun run typecheck`: 0 errors.
   - `bun run lint`: 0 warnings, 0 errors.
2. **Frontend Vitest Suite**:
   - 45 test files passed, 310 tests passed (including `parsers.test.tsx` and `ingestion.test.tsx`).
3. **Frontend Production Build**:
   - Vite client production bundle built cleanly in 5.37 seconds.
4. **Backend Test Battery**:
   - `internal/integrations/...`: PASS.
   - `internal/query/...`: PASS.
   - `internal/compliance/...`: PASS.
   - `internal/sbom/...`: PASS.
   - `internal/ingest/...`: PASS (parser package, detection, blind server, format mismatch & router tests).
5. **CRD Bundle & Helm Validation**:
   - `python3 hack/crds-bundle.py --check`: 25 CRDs synchronized and validated.
   - `helm lint deploy/helm/rampart`: 0 charts failed.
6. **Codebase Grep Check**:
   - `grep -rnI "builtin" internal/sbom/ internal/integrations/ internal/ingest/ internal/query/parsers* web/src/routes/parsers/`: **0 matches**.
