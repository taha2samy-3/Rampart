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
