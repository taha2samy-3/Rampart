# 47. VEX (Vulnerability Exploitability eXchange) Lifecycle Architecture, Dedicated Parsers & Web UI Integration

**Status**: Approved Architecture & Implementation Plan  
**Target Versions**: Rampart v0.3.23+  
**Parity Target**: OWASP Dependency-Track, CISA Minimum Requirements for VEX, OpenVEX 0.2, CycloneDX 1.6 VEX/VDR, CSAF 2.0  

---

## 1. Executive Summary & Problem Context

In modern cloud-native applications, Software Composition Analysis (SCA) scanners frequently report hundreds or thousands of Common Vulnerabilities and Exposures (CVEs) across transitive dependencies. However, empirical security research demonstrates that **over 85% of reported SCA vulnerabilities are not exploitable** in the context of the running application because:
- The vulnerable function, method, or class is never invoked or reachable from the application's execution path.
- The vulnerable submodule (e.g., test suites, documentation builders, CLI utilities) is excluded from production packaging.
- Compensating mitigations (such as WAF rules, container sandboxing, compiler hardening, or network microsegmentation) nullify exploitability.

This gap creates severe **"Alert Fatigue"**, causes development teams to ignore security alerts, and leads to false-positive pipeline failures that disrupt continuous deployment.

```
+-------------------------------------------------------------------------------+
|                             The Alert Fatigue Gap                             |
|                                                                               |
|  [ Raw SCA Scanners ]                                                         |
|  (Trivy, Grype, Snyk, Semgrep)                                                |
|         │                                                                     |
|         ▼                                                                     |
|  500 CVEs Reported  ──> [ Overwhelming Backlog / Broken CI Gates ]            |
|                                                                               |
|  ===========================================================================  |
|                                                                               |
|  [ Authoritative VEX Declarations ]                                           |
|  (OpenVEX, CycloneDX VEX, CSAF 2.0)                                           |
|         │                                                                     |
|         ▼                                                                     |
|  Rampart VEX Engine: Matches (Vulnerability × Component)                     |
|         ├── 420 CVEs: NOT_AFFECTED (vulnerable_code_not_in_execute_path)     |
|         ├──  30 CVEs: NOT_AFFECTED (inline_mitigations_already_exist)         |
|         ├──  10 CVEs: FIXED in current patch baseline                         |
|         └──  40 CVEs: AFFECTED (True Positives requiring immediate action!)   |
|                                                                               |
|  Result: 92% Noise Reduction, Focus on Real Exploitability                    |
+-------------------------------------------------------------------------------+
```

### The Current Architectural Deficiency
Previously in Rampart:
1. **Misclassified Parser in the Parsers Repository**: In `parsers/wasm/openvex`, OpenVEX was implemented as if it were a scanner report parser emitting synthetic `RawFinding` dummy records with `tool_severity: "info"`.
2. **Ingestion Abort Gate**: In Rampart's core ingestion processor (`internal/ingest/processor.go`), uploading an OpenVEX file triggered `ErrCodeVEXDocument` with a hard abort:
   > *"an OpenVEX document is a set of decisions, not a scan report: send it to POST /api/v1/vex"*
3. **Discarded Embedded VEX in SBOMs**: When users uploaded a CycloneDX SBOM that contained both a component inventory and embedded `vulnerabilities.analysis` blocks (a Vulnerability Disclosure Report, or VDR), the SBOM reader extracted components but dropped the exploitability analyses.
4. **UI Blindspot**:
   - `web/src/routes/applications/ApplicationSBOMSection.tsx` provided links to *export* OpenVEX and CycloneDX VEX, but provided **no UI to import/upload VEX documents**.
   - Security analysts had no way to preview the impact of a VEX document via dry-run simulation in the browser.
   - The findings table and detail views lacked visual badges indicating that a finding's status was decided by an authoritative vendor VEX statement.

---

## 2. Industry Standards & Vocabulary Alignment

Rampart adheres to the three major international VEX specifications, maintaining lossless bidirectional mapping with its internal finding lifecycle (docs/03 §4, docs/16 D47).

```
                      +────────────────────────────────────────+
                      |         Rampart Finding State          |
                      |   (StateOpen, StateUnderInvestigation, |
                      |    StateAffected, StateNotAffected,    |
                      |    StateFixed, StateRiskAccepted)      |
                      +──────────────────┬─────────────────────+
                                         │
        ┌────────────────────────────────┼────────────────────────────────┐
        ▼                                ▼                                ▼
+─────────────────+            +──────────────────+             +──────────────────+
|  OpenVEX (0.2)  |            | CycloneDX (1.6)  |             |    CSAF (2.0)    |
|   Chainguard    |            |      OWASP       |             |      OASIS       |
+─────────────────+            +──────────────────+             +──────────────────+
| not_affected    |            | not_affected     |             | known_not_affected
| affected        |            | exploitable      |             | known_affected   |
| fixed           |            | resolved         |             | first_fixed      |
| under_investig. |            | in_triage        |             | under_investigat.|
+─────────────────+            +──────────────────+             +──────────────────+
```

### 2.1. State Mapping Matrix

| Rampart Internal State | OpenVEX 0.2 (`status`) | CycloneDX 1.6 (`analysis.state`) | CSAF 2.0 (`product_status`) | Exploitability Meaning |
|---|---|---|---|---|
| `StateOpen` | `under_investigation` | `in_triage` | `under_investigation` | Vulnerability identified; reachability and exploitability unverified. |
| `StateUnderInvestigation` | `under_investigation` | `in_triage` | `under_investigation` | Active analysis in progress by the security team. |
| `StateAffected` | `affected` | `exploitable` | `known_affected` | Exploitability confirmed; vulnerable code is active and reachable. |
| `StateNotAffected` | `not_affected` | `not_affected` | `known_not_affected` | Verified non-exploitable (requires mandatory justification). |
| `StateFixed` | `fixed` | `resolved` | `first_fixed` | Patched or remediated in the current component version. |
| `StateRiskAccepted` | `affected` (with note) | `exploitable` (`response: will_not_fix`) | `known_affected` | Business risk acceptance (a business decision, not an exploitability assertion). |

### 2.2. Justifications for `not_affected`

When a vulnerability is marked `not_affected`, CISA guidelines and VEX specifications require an authoritative justification. Rampart standardizes on the five canonical OpenVEX terms while preserving lossless round-tripping with CycloneDX's nine justifications via the metadata property `rampart:justification`:

```
+───────────────────────────────────────────────────+──────────────────────────────────────────────────+
| OpenVEX Canonical Justification                   | CycloneDX Justification Mapping                  |
+───────────────────────────────────────────────────+──────────────────────────────────────────────────+
| component_not_present                             | code_not_present                                 |
| vulnerable_code_not_present                       | code_not_present                                 |
| vulnerable_code_not_in_execute_path               | code_not_reachable                               |
| vulnerable_code_cannot_be_controlled_by_adversary | requires_configuration / requires_environment    |
| inline_mitigations_already_exist                  | protected_by_mitigating_control / runtime        |
+───────────────────────────────────────────────────+──────────────────────────────────────────────────+
```

---

## 3. Dependency-Track Parity & Analysis Model

OWASP Dependency-Track is the industry gold standard for Software Bill of Materials (SBOM) and VEX operations. Rampart implements complete functional parity with Dependency-Track's analysis architecture.

### 3.1. The Component-Vulnerability-Project Tuple
In Dependency-Track:
- Analysis is not stored globally against a CVE.
- Analysis is anchored to the specific tuple: `(Project, Component, Vulnerability)` — or in Rampart coordinates: `(Application, Component PURL, Vulnerability ID)`.
- If `log4j-core 2.14.1` is used in Service A (where it is unreachable) and in Service B (where it is reachable via public endpoints), Service A has `NOT_AFFECTED` while Service B remains `AFFECTED`.

### 3.2. Dual Ingestion Mechanics in Dependency-Track
Dependency-Track handles VEX through two distinct ingestion channels:
1. **Channel 1: Standalone VEX Upload (`POST /api/v1/vex`)**:
   - Ingests pure VEX documents (OpenVEX, CycloneDX VEX, CSAF).
   - Validates that the document asserts claims for components already registered in the project.
   - Updates `AnalysisState`, `AnalysisJustification`, `AnalysisResponse`, and audit comments.
2. **Channel 2: Embedded VEX in CycloneDX BOMs (`POST /api/v1/bom`)**:
   - When a build pipeline publishes a CycloneDX SBOM containing both `components[]` and `vulnerabilities[].analysis`:
   - Dependency-Track's parser executes a two-phase ingest:
     - Phase A: Ingest components into inventory.
     - Phase B: Extract `vulnerabilities` and apply the embedded analysis directly to the created findings.

### 3.3. Policy Suppression & CI/CD Governance
When an analysis resolves to `NOT_AFFECTED`:
- The finding is marked **Suppressed** (`is_suppressed = true`).
- Suppressed findings do **not** trigger policy violations or fail quality gates in CI/CD pipelines.
- Suppressed findings are excluded from executive vulnerability metrics, while remaining fully visible in audit logs.

---

## 4. Rampart Target Architecture: The Dedicated VEX Subsystem

Rampart unifies VEX parsing, ingestion, storage, and UI presentation into a cohesive, zero-mock architecture.

```
+──────────────────────────────────────────────────────────────────────────────────────────+
|                                  Rampart VEX Architecture                                |
+──────────────────────────────────────────────────────────────────────────────────────────+
                                           │
          ┌────────────────────────────────┴────────────────────────────────┐
          ▼                                                                 ▼
┌─────────────────────────────────┐                       ┌─────────────────────────────────┐
│     Standalone VEX Ingest       │                       │    Embedded CycloneDX SBOM      │
│   (OpenVEX, CycloneDX, CSAF)    │                       │  (Components + VDR Analysis)    │
│    POST /api/v1/vex             │                       │  POST /api/v1/uploads           │
└────────────────┬────────────────┘                       └────────────────┬────────────────┘
                 │                                                         │
                 ▼                                                         ▼
┌─────────────────────────────────┐                       ┌─────────────────────────────────┐
│       Dedicated VEX Reader      │                       │     CycloneDX SBOM Parser       │
│      (`internal/vex.Parse`)     │                       │   Extracts Components + VEX     │
└────────────────┬────────────────┘                       └────────────────┬────────────────┘
                 │                                                         │
                 │                 ┌───────────────────────────────────────┘
                 ▼                 ▼
+──────────────────────────────────────────────────────────────────────────────────────────+
|                              VEX Matcher & Decision Engine                               |
|                              (`store.VEXMatcher`)                                        |
+──────────────────────────────────────────────────────────────────────────────────────────+
| 1. Match Target: Vulnerability ID & Aliases (CVE, GHSA, OSV)                             |
| 2. Match Target: Component PURL / PurlBase within Target Application                     |
| 3. Precedence Check: Later statements override earlier; protect human manual triage      |
| 4. Record FindingEvent: actor="vex:<author>", justification, impact, action              |
| 5. Update FindingState: StateNotAffected, StateFixed, StateAffected                     |
+──────────────────────────────────────────────────────────────────────────────────────────+
                 │
                 ▼
+──────────────────────────────────────────────────────────────────────────────────────────+
|                           Storage & Policy / CI Gate Sync                                |
|   - PostgreSQL findings & finding_event tables updated                                   |
|   - CI Gate (internal/query/gate.go): Automatically ignores VEX-suppressed findings      |
|   - Live Event Stream: SSE broadcasts update to Web UI                                   |
+──────────────────────────────────────────────────────────────────────────────────────────+
```

### 4.1. The Dedicated VEX Parser vs. Report Scanner Parser
A report scanner parser (`ClusterParser`) translates raw scan results into findings (`RawFinding`). In contrast, a VEX parser translates exploitability assertions into **decisions** on existing findings.

#### Resolution of the WASM Parser Conflict
In the standalone `parsers` repository (`parsers/wasm/openvex`), the parser will be updated to emit canonical VEX statement payloads (`domain.VEXStatement`) rather than dummy findings. Within Rampart's ingestion processor:
- If a standalone VEX document is submitted to `POST /api/v1/uploads`, the router detects the VEX payload and forwards it directly to the VEX application engine rather than throwing `ErrCodeVEXDocument`.

### 4.2. Embedded CycloneDX VDR / VEX Support
When a CycloneDX SBOM is received:
1. `internal/sbom/` extracts all `components` and populates the application's software package inventory.
2. If `vulnerabilities` with `analysis` blocks are present in the document:
   - The engine converts each vulnerability analysis into a `vex.Statement`.
   - The engine automatically applies the statements to the findings discovered or matched for that application during the same run.

### 4.3. Precedence & Conflict Resolution Rules
1. **Timestamp Precedence**: Statements within a document are sorted oldest-to-newest; the latest statement prevails.
2. **Human Overrides**: If a security analyst manually triaged a finding *after* the timestamp of a vendor VEX statement, the human decision is preserved (`stale`), unless the user explicitly forces an overwrite.
3. **Product-Level Assertions**: A statement lacking a specific package/component PURL is flagged as unapplied to prevent unintentional product-wide suppressions.

---

## 5. Web UI & User Experience Specifications

The user interface provides full operational control over VEX workflows, combining self-service management with transparent auditability.

### 5.1. Application VEX Center (`ApplicationVEXSection.tsx`)
Located on the Application details page alongside SBOM management:
- **Download Buttons**: "Export OpenVEX" and "Export CycloneDX VEX".
- **Upload Action**: Prominent "Apply VEX Document" button triggering the VEX Import Modal.

```
+───────────────────────────────────────────────────────────────────────────────+
| [Application: Payment Gateway] > VEX Management                              |
|                                                                               |
|  Current Status: 14 Statements Active (92 Findings Suppressed by Vendor VEX)  |
|                                                                               |
|  [ Download OpenVEX ]  [ Download CycloneDX VEX ]  [ Apply VEX Document ]     |
+───────────────────────────────────────────────────────────────────────────────+
```

### 5.2. Interactive VEX Import Modal with Live Dry-Run Preview
Before any changes are committed to the database, analysts can upload a file and preview its exact impact via a live dry run (`POST /api/v1/vex?application=<id>&dryRun=true`):

```
+───────────────────────────────────────────────────────────────────────────────+
| Apply VEX Document                                                      [ × ] |
+───────────────────────────────────────────────────────────────────────────────+
| Select VEX Document (OpenVEX, CycloneDX VEX, CSAF 2.0 JSON):                 |
| [ 📄 chainguard-enterprise-glibc-2026-11.vex.json                    Browse ] |
|                                                                               |
| Author: Chainguard PSIRT | Timestamp: 2026-11-20 18:30 UTC | Format: OpenVEX  |
|                                                                               |
| ────────────────────────────── Dry-Run Preview ─────────────────────────────  |
| Total Statements: 12   | Matched Findings: 8    | Unchanged: 2                |
| Status Transitions:                                                           |
|  • CVE-2023-4911 (glibc 2.38): OPEN  ──>  NOT_AFFECTED                       |
|    Justification: vulnerable_code_not_in_execute_path                         |
|    Impact: Tunables environment parsing disabled in container runtime.        |
|  • CVE-2023-6246 (glibc 2.38): OPEN  ──>  FIXED                               |
|                                                                               |
| Unmatched Statements (0 in current app inventory): 2                          |
|  ⚠️ pkg:golang/github.com/gin-gonic/gin@v1.9.1 (CVE-2023-39325)               |
|                                                                               |
| [ Cancel ]                                         [ Confirm & Apply (8) ]    |
+───────────────────────────────────────────────────────────────────────────────+
```

### 5.3. Finding List Exploitability Badges
In `web/src/routes/findings/FindingsTable.tsx`:
- Findings suppressed or decided by VEX render with a distinctive badge:
  - `[VEX: Not Affected (Code Not Reachable)]` (in muted gray/teal).
  - `[VEX: Fixed]` (in soft green).
- Filter bar provides a dedicated selector:
  - `All Findings`
  - `Active (Excluding VEX Suppressed)` (Default)
  - `VEX Suppressed Only`
  - `Manual Triage Only`

### 5.4. Finding Detail View: Dedicated VEX Exploitability Card
In `FindingDetailRoute.tsx` and `Inspector.tsx`, when a finding has a VEX decision:
- A dedicated **"VEX Exploitability Assertion"** card renders prominently above the vulnerability overview:
  - **Author**: e.g., `vex:Chainguard PSIRT` or `vex:Red Hat Security Response Team`.
  - **Decision**: `NOT_AFFECTED` with the standard justification badge.
  - **Impact Analysis**: Full vendor statement explaining why the vulnerability cannot be exploited.
  - **Action Statement**: Remediation or operational guidance provided by the supplier.
  - **Audit Provenance**: Ingestion timestamp, original format, and link to raw statement.

---

## 6. Declarative Kubernetes CRD & Automated VEX Feeds

To support enterprise GitOps workflows, Rampart introduces declarative Custom Resource Definitions (CRDs) for automated VEX synchronization.

### 6.1. `ClusterVEXSource` CRD Specification
```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterVEXSource
metadata:
  name: chainguard-vex-feed
spec:
  format: openvex # openvex | cyclonedx | csaf
  schedule: "0 */6 * * *" # Every 6 hours via River job queue
  source:
    http:
      url: "https://packages.cgr.dev/chainguard/vex.json"
      headersSecretRef:
        name: chainguard-credentials
  matching:
    autoApply: true
    trustLevel: "authoritative_vendor"
    scope:
      applicationSelector:
        matchLabels:
          vendor: chainguard
```

### 6.2. Synchronization Engine
- River worker fetches upstream VEX feeds on schedule.
- Validates cryptographic signatures (e.g. Cosign / Sigstore for OpenVEX, minisign for CSAF).
- Executes bulk match against target applications and updates `FindingEvent` timelines.

---

## 7. Phased Implementation & Verification Plan

### Phase 1: CycloneDX Embedded VEX (VDR) Ingestion
- **Target**: `internal/sbom/` and `internal/ingest/package_parsers.go`.
- **Scope**: Extract `vulnerabilities` and `analysis` blocks during CycloneDX SBOM parsing and route statements to `store.VEXMatcher`.
- **Verification**: Unit tests with sample CycloneDX 1.4/1.5/1.6 VDR files.

### Phase 2: Ingest Gateway Smart Routing
- **Target**: `internal/ingest/processor.go` and `internal/query/api.go`.
- **Scope**: Auto-detect standalone VEX documents in `/api/v1/uploads` and seamlessly dispatch to the VEX engine when an `application_id` is present.
- **Verification**: Ingestion integration tests verifying that VEX uploads update existing findings without throwing `ErrCodeVEXDocument`.

### Phase 3: Web UI Application VEX Modal with Live Dry Run
- **Target**: `web/src/routes/applications/` and `web/src/features/vex/`.
- **Scope**: Build `VEXUploadModal.tsx` with dry-run diff preview, file drop zone, and live apply execution.
- **Verification**: Playwright e2e tests and Vitest component tests.

### Phase 4: UI Visual Exploitability Badges & Detail Card
- **Target**: `web/src/routes/findings/FindingDetailRoute.tsx` and `web/src/features/finding-inspector/Inspector.tsx`.
- **Scope**: Render dedicated VEX Exploitability Card with author attribution, justification text, and action statements.
- **Verification**: Visual screenshot tests across `open`, `not_affected`, and `fixed` states.

### Phase 5: Declarative `ClusterVEXSource` CRD & GitOps Sync
- **Target**: `deploy/crds/vexsource.yaml`, `deploy/helm/rampart/crds/`, and `internal/controller/`.
- **Scope**: Register `ClusterVEXSource` CRD, Helm chart values, and River background synchronization job.
- **Verification**: `python3 hack/crds-bundle.py --check` and `helm lint`.

---

## 8. Comprehensive Test Plan & Edge Cases Matrix

To achieve enterprise-grade reliability and zero-mock parity with OWASP Dependency-Track, the VEX implementation is backed by an exhaustive testing battery spanning unit fuzzing, relational database integration, dual-payload ingestion, and browser-driven end-to-end verification.

### 8.1. Test Suites Structure & Responsibilities

```
+──────────────────────────────────────────────────────────────────────────────────────────+
|                                    VEX Test Hierarchy                                    |
+──────────────────────────────────────────────────────────────────────────────────────────+
  ├── [Suite 1: Parser & Schema Fuzzing] (`internal/vex/`)
  │     ├── OpenVEX 0.1 & 0.2 structural variants (bare strings vs object products)
  │     ├── CycloneDX 1.4, 1.5, 1.6 standalone VEX & embedded SBOM VDR
  │     └── CSAF 2.0 OASIS VEX Profile product trees & relationship branches
  │
  ├── [Suite 2: Matching & Scope Isolation] (`internal/store/vex_test.go`)
  │     ├── PURL matching: exact versioned, unversioned base, and subcomponents
  │     ├── Vulnerability alias resolution (CVE <-> GHSA <-> OSV)
  │     └── Tenant & Application strict isolation boundaries
  │
  ├── [Suite 3: Chronological Precedence & State Machine] (`internal/store/vex_test.go`)
  │     ├── Intra-document timestamp sorting (latest statement prevails)
  │     ├── Human manual triage protection (older VEX statements marked `stale`)
  │     └── Authoritative newer vendor statements overriding previous state
  │
  ├── [Suite 4: Dual-Payload Ingestion Pipeline] (`internal/ingest/` & `internal/sbom/`)
  │     ├── CycloneDX SBOM containing both components and embedded VDR analysis
  │     ├── Gateway smart routing: direct VEX upload without ErrCodeVEXDocument
  │     └── Ephemeral runs (PRs/branches) inheriting baseline VEX suppressions
  │
  ├── [Suite 5: CI/CD Quality Gate & Governance] (`internal/query/gate_test.go`)
  │     ├── Build-breaking policy suppression for `not_affected` findings
  │     └── Gate instant failure when VEX marks a suppressed flaw as `affected`
  │
  └── [Suite 6: Interactive Web UI Verification] (Vitest & Playwright E2E)
        ├── `VEXUploadModal`: Dry-run simulation diff preview and live apply
        ├── `FindingsTable`: Exploitability badges and VEX filter dropdown
        ├── `FindingDetailRoute`: Dedicated VEX Exploitability Card
        └── RBAC enforcement: Viewer disabled, Triager/Maintainer enabled
```

---

### 8.2. The Exhaustive 32 Edge Cases Matrix

| Edge Case ID | Dimension | Scenario / Input Condition | Expected System Behavior | Verification Level |
|---|---|---|---|---|
| **EC-01** | Parser Boundaries | Empty payload or 0-byte file uploaded to `/api/v1/vex`. | Returns `400 Bad Request` with `code: "validation"` ("The body is empty"). No worker spawned. | Unit (`vex_test.go`) |
| **EC-02** | Parser Boundaries | Document exceeding 16 MiB (`vex.MaxDocument`). | Returns `413 Payload Too Large` via `io.LimitReader`. Engine does not exhaust memory. | Integration (`query/vex_test.go`) |
| **EC-03** | Parser Boundaries | Malformed JSON syntax (unclosed brackets, truncated text). | Returns `400 Bad Request` citing exact JSON syntax error. No partial DB state created. | Unit (`vex_test.go`) |
| **EC-04** | Parser Boundaries | Valid JSON but unrecognized schema (e.g. SARIF report sent to `/api/v1/vex`). | Returns `400 Bad Request` with `ErrUnknownFormat` ("not OpenVEX or CycloneDX VEX"). | Unit (`vex_test.go`) |
| **EC-05** | Document Semantics | Statement with empty/missing vulnerability ID. | Statement flagged as `rejected` ("the statement names no vulnerability"). Rest of document continues. | Unit (`vex_test.go`) |
| **EC-06** | Vulnerability Aliases | Statement names `GHSA-m95q-7m34-fcv2`, but finding was ingested as `CVE-2023-4911`. | Bidirectional alias lookup via `vulnerability_alias` matches and decides the finding. | DB Integration (`store/vex_test.go`) |
| **EC-07** | Document Semantics | Statement contains invalid status (e.g. `"status": "maybe"` or `"wontfix"`). | Statement marked `rejected` ("status is not an OpenVEX status"). Valid statements proceed. | Unit (`vex_test.go`) |
| **EC-08** | CISA Compliance | Statement claims `not_affected` without providing a justification. | Statement rejected per CISA minimum requirements; finding is NOT suppressed without rationale. | DB Integration (`store/vex_test.go`) |
| **EC-09** | Vocabulary Mapping | CycloneDX document uses `code_not_reachable`; exported to OpenVEX and back. | OpenVEX maps to `vulnerable_code_not_in_execute_path`; roundtrip preserves original in `rampart:justification`. | Unit Roundtrip (`export_test.go`) |
| **EC-10** | Timestamp Formats | Mixed timestamp formats: RFC3339Nano, RFC3339, date-only (`2026-11-21`), and missing timestamps. | Normalized to UTC. Statements without timestamp inherit document metadata timestamp. | Unit (`vex_test.go`) |
| **EC-11** | PURL Matching | Statement has exact versioned PURL `pkg:npm/lodash@4.17.20`. Finding has identical PURL. | Exact match: finding transitioned to VEX state. | DB Integration (`store/vex_test.go`) |
| **EC-12** | PURL Isolation | Statement has `pkg:npm/lodash@4.17.20`. Application finding is `pkg:npm/lodash@4.17.21`. | **MUST NOT match**. Reported in `unmatched`. Prevents unsafe cross-version suppressions. | DB Integration (`store/vex_test.go`) |
| **EC-13** | Base PURL Scoping | Statement targets unversioned base PURL `pkg:npm/lodash`. | Applies to all occurrences of `lodash` within that application. | DB Integration (`store/vex_test.go`) |
| **EC-14** | Product-Only PURL | Statement specifies top-level product only (e.g. `pkg:oci/my-app@sha256:...`) with no packages. | Rejected with reason: *"a decision for a whole product without packages is not applied"*. | DB Integration (`store/vex_test.go`) |
| **EC-15** | Subcomponents | OpenVEX 0.2 object product with container PURL and nested `subcomponents` package PURLs. | Subcomponents narrow the statement scope strictly to the nested package PURLs. | Unit (`vex_test.go`) |
| **EC-16** | Tenant Isolation | Tenant 1 and Tenant 2 both have identical CVEs and PURLs. Tenant 1 imports VEX. | Tenant 1 findings updated; Tenant 2 findings remain untouched (RLS and tenant query isolation). | DB Integration (`store/vex_test.go`) |
| **EC-17** | Application Scope | App A and App B belong to same tenant with identical package. VEX uploaded with `application=App_A`. | App A findings updated; App B findings remain untouched. | DB Integration (`store/vex_test.go`) |
| **EC-18** | Precedence: Order | Same document contains Statement 1 (10:00:00, `affected`) and Statement 2 (10:05:00, `fixed`). | Statements sorted chronologically; latest statement (`fixed`) applied last and wins. | DB Integration (`store/vex_test.go`) |
| **EC-19** | Precedence: Human | Analyst manually triaged finding at 12:00:00 UTC. Vendor VEX statement has timestamp 11:00:00 UTC. | Statement marked `stale` (human decision protected); finding state remains unchanged. | DB Integration (`store/vex_test.go`) |
| **EC-20** | Precedence: Vendor | Analyst triaged finding at 10:00:00 UTC. Authoritative vendor VEX arrives at 14:00:00 UTC marking `affected`. | Newer vendor statement overrides previous state; timeline logs `actor: "vex:<author>"`. | DB Integration (`store/vex_test.go`) |
| **EC-21** | State Reversibility | Finding is `StateNotAffected` via VEX. Vendor later issues updated VEX marking `StateAffected`. | Finding reopened to `StateAffected`; SLA timeline recalculated; notifications dispatched. | DB Integration (`store/vex_test.go`) |
| **EC-22** | Idempotency | The exact same VEX document is imported twice consecutively. | First run: `applied: N`. Second run: `applied: 0, unchanged: N, rejected: 0`. No redundant events. | DB Integration (`store/vex_test.go`) |
| **EC-23** | Ingest: Embedded VDR | CycloneDX SBOM uploaded to `POST /api/v1/uploads` has components AND `vulnerabilities.analysis`. | Packages ingested into inventory AND embedded VEX statements applied to findings in one run. | Ingestion E2E (`processor_test.go`) |
| **EC-24** | Ingest: Smart Gateway | Pure OpenVEX file uploaded to `POST /api/v1/uploads` with `application_id`. | Gateway detects VEX, routes to VEX matcher, returns HTTP 200 with report (no `ErrCodeVEXDocument`). | Ingestion E2E (`gateway_test.go`) |
| **EC-25** | Ephemeral Runs | PR feature branch scanned in ephemeral mode. Baseline has active VEX `not_affected` decision. | Ephemeral run inherits baseline VEX suppression; does not report false-positive blocker. | Ingestion E2E (`ephemeral_test.go`) |
| **EC-26** | CI Gate Suppression | CI gate configured with `fail_on: HIGH`. Finding is High severity, but marked `not_affected` by VEX. | CI gate evaluates to `passed: true` (`suppressed_count: 1`); pipeline succeeds. | Gate Integration (`gate_test.go`) |
| **EC-27** | CI Gate Reopening | VEX statement updates previously suppressed High finding back to `affected`. | CI gate immediately evaluates to `passed: false`; pipeline blocked. | Gate Integration (`gate_test.go`) |
| **EC-28** | UI: Dry-Run Diff | User uploads VEX in `VEXUploadModal` with `dryRun=true`. | Displays exact preview (transitions, unchanged, unmatched) without writing to PostgreSQL. | Vitest (`VEXUploadModal.test.tsx`) |
| **EC-29** | UI: High Volume | VEX document containing 1,000+ statements uploaded in browser. | Dry-run table renders with virtualization/pagination; browser main thread does not freeze. | Vitest (`VEXUploadModal.test.tsx`) |
| **EC-30** | UI: RBAC Locks | User with `viewer` role accesses Application VEX section. | Export buttons enabled; "Apply VEX Document" button disabled with tooltip citing required role. | Vitest (`ApplicationVEXSection.test.tsx`) |
| **EC-31** | UI: Live SSE Sync | VEX applied via modal. Background tabs and other users have finding table open. | SSE event `finding_updated` updates table badges and counters in real time without page reload. | Playwright E2E (`vex-live-sync.spec.ts`) |
| **EC-32** | Detail View Card | Finding opened in `/findings/$id`. Finding was decided by VEX statement. | Renders VEX Exploitability Card with Author, Justification, Impact, and Action statements. | Playwright E2E (`finding-detail-page.spec.ts`) |

---

### 8.3. Verification Execution Guidelines

To satisfy Rampart's mandatory verification guidelines (`AGENTS.md`), any implementation touching the VEX subsystem must pass the following battery:

1. **Go Test Battery**:
   ```bash
   RAMPART_WASM_DIR=$PWD/.cache/wasm go test -race -v ./internal/vex ./internal/store -run "TestVEX.*"
   RAMPART_WASM_DIR=$PWD/.cache/wasm go test -race -v ./internal/ingest -run "TestIngest.*VEX.*"
   RAMPART_WASM_DIR=$PWD/.cache/wasm go test -race -v ./internal/query -run "TestGate.*VEX.*"
   ```
2. **Frontend Test Battery**:
   ```bash
   bun run typecheck
   bun run lint
   bun run test -- src/features/vex src/routes/applications src/routes/findings
   ```
3. **End-to-End Visual Verification**:
   ```bash
   bun run test:e2e -- e2e/vex-upload-and-badges.spec.ts
   ```

