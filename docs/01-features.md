# 01 — Feature catalogue and priorities

Priority legend, tied to the roadmap in [09-roadmap.md](09-roadmap.md): **P0** = MVP, delivered by the end of Phase 2. **P1** = v1.0, delivered by the end of Phase 4. **P2** = v1.x, after 1.0. **P3** = later or optional module.

## A. Ingestion

| # | Feature | Pri | Notes |
|---|---|---|---|
| A1 | Upload API: presigned object-storage upload + `complete` with Idempotency-Key | P0 | Large reports never pass through the API pod |
| A2 | Direct small upload (multipart ≤ 32 MB) for CI convenience | P0 | |
| A3 | `ReportIngest` CRD for GitOps / operator-driven ingestion | P1 | For objects already in storage; API uploads do not create this resource |
| A4 | SARIF 2.1.0 parser (generic, with per-tool enrichers) | P0 | Covers ~15 tools immediately |
| A5 | CycloneDX 1.4–1.7 SBOM + VDR + VEX parser | P0 | |
| A6 | Native parsers: Trivy, Grype, Semgrep, Gitleaks, Checkov, Nuclei, ZAP, Bandit, Dependency-Check, kube-bench, Prowler (OCSF), Snyk, SonarQube (API), GitLab report schemas, Syft | P0 (Trivy, Grype, Semgrep, Gitleaks) / P1 (rest) | Order by usage; each parser is a Go package with a conformance test fixture |
| A7 | Kubernetes `PolicyReport` / OpenReports / Trivy Operator CRD watcher as a scan source | P2 | Separate `collector` target |
| A8 | OpenVEX / CSAF VEX ingestion that updates triage state | P0 (OpenVEX, CycloneDX VEX) / P1 (CSAF) | CISA's minimum VEX requirements accept any of the three formats; D54 |
| A9 | SPDX 2.3 SBOM parser | P1 | SPDX 3.0 later |
| A10 | Generic JSON findings format (DefectDojo-compatible superset) | P1 | Easy migration path |
| A11 | Declarative parser mappings (`IntegrationPackage`, `runtime: mapping`): record path plus CEL field expressions for JSON, JSONL, CSV, XML | P1 | Tenant admins can add them; see [19-integration-sdk.md](19-integration-sdk.md) |
| A18 | Parser plugins as sandboxed WebAssembly (WASI) modules, packaged as signed OCI artifacts | P1 | Any language; platform admin installs |
| A19 | Declarative API sources (auth, paging, cursor, mapping) and gRPC source plugins | P2 | SonarQube, Snyk, GitHub Code Scanning written this way |
| A12 | Upstream connectors (scheduled API pulls): SonarQube, Snyk, GitHub Code Scanning, GitLab, Wiz, Tenable, Qualys | P2 | Written as declarative sources where the API allows |
| A16 | **Dependency-Track integration**: project discovery and mapping, findings and policy-violation pull, webhook-triggered sync, SBOM forwarding, bidirectional triage sync, FPF file parser | P1 (pull, webhook trigger, triage import, FPF) / P2 (SBOM forwarding, write-back, policy violations) | First-class; see [10-dependency-track-integration.md](10-dependency-track-integration.md) |
| A17 | DefectDojo-compatible import API shim (`/api/v2/import-scan/`, `/reimport-scan/`) | P2 | Lets DT's DefectDojo integration and legacy CI scripts post unchanged |
| A13 | Attestation ingestion: in-toto / SLSA provenance / cosign bundles → verified posture facts | P2 | |
| A14 | Reimport semantics: created / untouched / closed / reactivated, `close_old_findings`, `do_not_reactivate`, field-merge policy | P0 | DefectDojo parity plus the field updates it lacks |
| A15 | DefectDojo migration tool (API v2 export → Rampart import) | P2 | |

## B. Inventory and context

| # | Feature | Pri | Notes |
|---|---|---|---|
| B1 | Tenant → Hierarchy node (N-level, tag-driven) → Application → Service/Component → Environment | P0 (tree, filter, roll-up) / P2 (`HierarchyNode` CRD) | D54 |
| B2 | Asset types: repository, branch, container image (digest), Kubernetes workload, host, URL/endpoint, package (purl), cloud resource | P0 | Stable keys per type |
| B3 | `Application` CRD with selectors mapping k8s workloads/namespaces/labels to applications | P0 | |
| B4 | Ownership: teams, owners, on-call; from CODEOWNERS, Backstage, labels | P1 | |
| B5 | Business context tags with weights: criticality, internet exposure, data classification (PII/PCI/PHI), compliance scope, compensating controls | P0 | Feed risk scoring and SLA |
| B6 | Coverage view: which assets lack SAST/SCA/secrets/container scans in the last N days | P1 | |
| B7 | SBOM inventory per artifact with dependency graph, license data | P1 | |
| B8 | Code-to-cloud linkage: repo → image → workload via provenance, labels and image annotations | P2 | |
| B9 | Asset discovery connectors: GitHub/GitLab orgs, container registries, Kubernetes clusters, Backstage catalog | P2 | |

## C. Findings, dedup, lifecycle

| # | Feature | Pri | Notes |
|---|---|---|---|
| C1 | Canonical `Finding` model with `Occurrence` (per-tool raw record) | P0 | |
| C2 | Deterministic fingerprint per scanner family; configurable `DedupPolicy` | P0 | |
| C3 | Cross-tool correlation (same CVE+purl, same CWE+file+function) producing one finding with many occurrences | P1 (correlation groups, non-destructive) / P2 (merge) |  |
| C4 | Triage state machine using OpenVEX vocabulary: `open`, `under_investigation`, `affected` (confirmed), `not_affected` (+5 justifications), `fixed`, plus `risk_accepted`, `duplicate`, `out_of_scope` | P0 | Exports losslessly to VEX |
| C5 | Risk acceptance with owner, justification, proof, expiry, auto-reactivation, approval flow | P0 / approval P2 | |
| C6 | False-positive memory: triage decisions persist across rescans and branches by fingerprint | P0 | Across tracks of one asset, for new findings only (D54) |
| C7 | Finding groups (by component, rule, file) for bulk ticketing | P1 | |
| C8 | Notes, attachments, mentions, history/timeline | P1 | |
| C9 | Bulk operations API (update status/severity/tags/owner for N findings) | P0 | DefectDojo gap |
| C10 | Similar-findings suggestions | P2 | |

## D. Enrichment and risk

| # | Feature | Pri | Notes |
|---|---|---|---|
| D1 | CVE/GHSA/OSV normalization with alias graph | P0 | |
| D2 | EPSS daily sync; KEV sync (with due dates and ransomware flag) | P0 | |
| D3 | NVD 2.0 and OSV.dev enrichment (CVSS, CWE, references, fixed versions) | P1 (NVD) ; OSV in P0 | Mirrorable (`FeedMirror` CRD) |
| D4 | CVSS v2/v3.1/v4 parse, validate, compute | P1 | MVP scores from severity, KEV and EPSS and keeps vectors as given (D54) |
| D5 | Explainable risk score (0–1000): base severity + factors (EPSS, KEV, exploit maturity, reachability, exposure, data sensitivity, criticality, compensating controls, age) with per-factor contribution shown | P0 | Default weights documented; `RiskPolicy` CRD overrides |
| D6 | SSVC decision output (Track / Track* / Attend / Act) | P2 | |
| D7 | Reachability inputs from external tools (consume, don't compute) | P2 | |
| D8 | Application / hierarchy roll-up scores and posture score | P0 | |

## E. Policy, SLA, automation

| # | Feature | Pri | Notes |
|---|---|---|---|
| E1 | `SLAPolicy` CRD: days per risk band × asset tier; KEV due-date cap; start/restart rules | P0 | |
| E2 | SLA computation, breach detection, countdown, adherence metrics | P0 | |
| E3 | CEL policy engine for auto-triage, severity override, routing, tagging, ticket creation | P2 | MVP and v1.0 ship built-in rules; the generic engine follows |
| E4 | CI gate API: `POST /gate` returns pass/fail with reasons for a commit/image | P0 | Built-in gate rule; `rampart gate` |
| E5 | Runbooks: trigger → filter → actions (ticket, notify, assign, escalate) | P2 | |
| E6 | Rego (OPA) as alternative policy language | P3 | |
| E7 | Exceptions/waivers with scope (asset, rule, CVE) and expiry | P2 | |

## F. Remediation and integrations

| # | Feature | Pri | Notes |
|---|---|---|---|
| F1 | Jira Cloud/Data Center connector: create, update, two-way status sync, comments, custom fields, one ticket per finding or group | P1 | |
| F2 | GitHub Issues / GitLab Issues / Azure Boards connectors | P1 / P2 | |
| F3 | Notifications: Slack, MS Teams, email, generic webhooks (signed), in-app | P1 | Per-event, per-tenant/user routing |
| F4 | `Connector` CRD referencing Kubernetes Secrets | P1 | |
| F5 | ServiceNow (VR), PagerDuty, Linear | P2 | |
| F6 | GitHub Code Scanning SARIF upload (push findings back to repo) and PR annotations | P2 | |
| F7 | Remediation campaigns (group findings into an initiative with progress) | P2 | |
| F8 | Unified `Tracker`, `Notifier` and `Source` contracts with a registry; connector forms generated from each integration's config schema | P1 | Built-ins use the same contracts |
| F9 | Declarative trackers and notifiers (HTTP request templates) | P1 | One or two REST calls, no code |
| F10 | gRPC plugins for trackers and notifiers; integration catalogue with conformance kit and CLI | P1 (catalogue, kit, CLI) / P2 (gRPC plugins) | |

## G. Reporting and UI

| # | Feature | Pri | Notes |
|---|---|---|---|
| G1 | Findings explorer: fast filtering, saved views, column config | P0 (explorer) / P1 (saved views) | |
| G2 | Dashboards: posture score, severity trend, MTTR, SLA adherence, coverage, top risks | P0 (overview) / P1 (full set) | |
| G3 | Compliance mapping views (OWASP, CWE Top 25, ASVS, PCI, ISO, SSDF, CIS, SLSA) | P1 | Data-driven taxonomies |
| G4 | Exports: CSV, JSON, PDF; SBOM (CycloneDX/SPDX); VEX (OpenVEX/CycloneDX); OCSF 2007 | P1 (CSV, JSON, SBOM, VEX, OCSF) / P2 (PDF) | |
| G5 | Scheduled reports via email | P2 | |
| G6 | Web UI as static SPA (React + TypeScript) consuming OpenAPI | P0 | Served separately from ingestion |
| G7 | CLI (`rampart` cobra) for upload, gate, query | P0 | |
| G8 | MCP server for AI assistants | P2 | |

## H. Platform and enterprise

| # | Feature | Pri | Notes |
|---|---|---|---|
| H1 | Multi-tenancy with RLS; tenant ↔ namespace | P0 | |
| H2 | AuthN: OIDC, API tokens with expiry, break-glass admin (P0); CI OIDC federation, SAML (P1); SCIM (P2) | P0 / P1 / P2 | |
| H3 | AuthZ: roles (Viewer, Triager, Maintainer, Owner, Admin) × scopes (hierarchy node / application) | P0 | Custom roles P2 |
| H4 | SCIM 2.0 provisioning | P2 | |
| H5 | Append-only audit log with export API | P0 | |
| H6 | Rate limiting and per-token quotas | P1 | |
| H7 | Retention policies (`RetentionPolicy` CRD); partition drops; raw report removal | P0 (occurrence and event retention job) / P2 (`RetentionPolicy` CRD) | |
| H8 | Helm chart (umbrella: CNPG, SeaweedFS, NATS, Valkey optional) + Kustomize | P0 | |
| H9 | Deployment modes: monolithic (`-target=all`), distributed; KEDA autoscaling | P0 (monolithic) / P1 (simple-scalable) / P2 (distributed, KEDA) | |
| H10 | Operator: reconcile all CRDs, status conditions, finalizers | P0 for the kinds in scope of each phase | |
| H11 | Observability: OpenTelemetry traces/metrics/logs, Prometheus, health/readiness, Grafana dashboards | P0 (metrics, traces, health) / P1 (dashboards, alert rules) | |
| H12 | Air-gapped install: OCI bundle of charts/images, `FeedMirror`, no egress by default | P1 | |
| H13 | Backups/PITR via CNPG; disaster recovery runbook | P1 | |
| H14 | Supply-chain for the product itself: ko/distroless, cosign signatures, SBOM + SLSA provenance | P0 | |
| H15 | Feature flags per tenant | P2 | |
| H16 | Data residency / per-tenant database option | P3 | |
