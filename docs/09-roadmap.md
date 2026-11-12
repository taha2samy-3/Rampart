# 09 — Roadmap and way of working

Rewritten after the design review. Assumes a team of **four to five engineers** (two backend, one platform/Kubernetes, one frontend, one shared on parsers and QA). With a smaller team the phases stretch proportionally; the order does not change.

| Milestone | End of | Meaning |
|---|---|---|
| **MVP** | Phase 2 (week 17) | Every P0 feature. A team can ingest, triage, score, enforce deadlines and gate CI |
| **v1.0** | Phase 4 (week 29) | Every P1 feature. Replaces DefectDojo in production, including Dependency-Track |
| v1.x | Phase 5 | P2 features |

## Status (2026-11-12)

What is built and tested, against the phases below. Everything marked built has automated tests and runs in CI; the kind end-to-end job is written but has not yet run on GitHub.

| Area | State |
|---|---|
| Phase 0: repository, config (D6), logging, OpenTelemetry, ops port | built |
| Phase 0: schema v1 with four roles, RLS, migrations Job, `migrate wait`, partition maintenance | built |
| Phase 0: River jobs (own schema), `internal/config/apply`, operator on controller-runtime (envtest), secret sync (encrypted), Helm chart, Docker Compose | built |
| Phase 0: CI (lint, parallel test suites, envtest, Helm, web, Compose, kind e2e, signing, SBOM, provenance) | built; e2e and publish not yet run on GitHub |
| Phase 0: web shell, login, empty workbench; OIDC sign-in; first administrator | built and verified in a real browser against Dex and PostgreSQL |
| Phase 0: operator finalizers (D21): Application orphaned, ScanSource disabled with its tokens revoked, SLAPolicy removed, Tenant refused while it has data unless `Purge`; NetworkPolicy and `ServiceMonitor` in the chart (D49) | built; finalizers tested with envtest and on PostgreSQL, the chart in CI. Not built: policies for the data services, `Archive`, the name-conflict condition |
| Phase 1: upload API (direct), SARIF and CycloneDX parsers, normalization, fingerprints, merge and close, tracks, ephemeral runs, query API with the grammar (in memory), roles and API tokens | built; the query API still filters in memory |
| Phase 1: presigned upload with a parse worker, object storage client (D34) | built; tested against PostgreSQL, River and SeaweedFS |
| Phase 1: query API on SQL with signed cursors; feed sync (KEV, EPSS, OSV) with aliases (D35) | built; tested on PostgreSQL |
| Phase 1: ingest throughput goal | **withdrawn** (D35): measured at about 130 s for 100k results, not reached; benchmark removed |
| Phase 1: `correlation_key` and correlation groups; ephemeral runs with baseline comparison; parser fuzz tests (D37) | built; tested on PostgreSQL |
| Phase 2: triage actions: state machine with VEX justifications, severity override with reason, tags, notes, timeline, bulk (D38) | built; API tested on PostgreSQL, UI (Change state dialog, timeline) tested with Vitest and checked in a browser. Not built: severity and tag editing in the UI, risk acceptance |
| Phase 2: risk acceptance with owner, expiry, optional approval, revoke, expiry sweeper; tenant settings (D39) | built; API tested on PostgreSQL, UI (request dialog, Workflow page) tested with Vitest. Not built: notifications, SLA pause, exceptions by selector |
| Phase 2: stored risk score, band and SLA; re-score on feed changes; SLA breach sweep; pause on risk acceptance; restart on reactivation (D40) | built; tested on PostgreSQL. Not built: `RiskPolicy` and `SLAPolicy` objects, `businessDays`, SLA notifications |
| Phase 2: `SLAPolicy` custom resource (operator, CRD, `rampart apply`, recompute on change) (D41) | built; tested with envtest and on PostgreSQL. Not built: `ClusterSLAPolicy`, per-application selection, `RiskPolicy` (needs CEL) |
| Phase 2: Overview and Applications pages with live aggregates, SLA adherence, MTTR, coverage, trend (D43) | built; tested on PostgreSQL and with Vitest, checked in a browser. Not built: snapshot trend table, newly exploited |
| Phase 2: "Reported by" on a finding: every tool that reported it, when it first and last did, whether it still does, and the same issue found by other tools (D44) | built; tested on PostgreSQL and with Vitest, checked in a browser. Not built: a column in the table, a per-run link |
| Phase 2: in-app notifications for deadline breach, due soon, and risk acceptance ending or ended; bell in the top bar (D45) | built; tested on PostgreSQL and with Vitest, checked in a browser. Not built: routing, digests, other channels (Phase 3) |
| Phase 2: append-only audit log of every mutating call, `GET /audit` with filters, paging and CSV/NDJSON export, Administration page (D46) | built; tested on PostgreSQL (including that the roles cannot change a row) and with Vitest, checked in a browser. Not built: before/after values, retention |
| Phase 2: VEX import (OpenVEX, CycloneDX) deciding findings with precedence and dry run; export in both formats, lossless; `rampart vex`; refuses a VEX as a scan report (D47) | built; tested on PostgreSQL, the CLI and the round trip. Not built: CSAF, import UI |
| Phase 2: roles maintainer and owner; per-application access bindings enforced on triage, bulk, VEX and risk acceptance; Access screen (D48) | built; tested on PostgreSQL and with Vitest. Not built: restricting reads, the `AccessBinding` CRD, groups, hierarchy scopes |
| Phase 2: Compliance: OWASP Top 10 2021 and CWE Top 25 by weakness, PCI DSS 4.0.1 req. 6, ISO 27001 A.8 and NIST SSDF by kind of scan; status open / clear / not assessed with evidence; CSV export; page (D52) | built; tested on PostgreSQL and with Vitest, checked in a browser. Not built: ASVS, CIS, SLSA, per-application tab, stored history |
| Phase 2: native parsers: Trivy, Grype, Semgrep, Gitleaks, TruffleHog (D42), with secrets never stored and TruffleHog verification in the score | built; fuzzed and tested on PostgreSQL. Not built: detect-secrets, image name from the report |
| Phase 2: CI gate (`POST /api/v1/gate`, `rampart gate`) with the built-in new-critical rule (D37) | built; tested on PostgreSQL |
| Phase 1: ingest run page in the UI (D37) | built; Vitest with axe, checked in a browser against the dev mock |
| Phase 1: `RekeyJob`: a GHSA-keyed finding moves to its CVE's key after the alias arrives, merging with an existing one; the old key still finds it (D50) | built; tested on PostgreSQL. Not built: alias expiry, other categories |
| Phase 2: retention: stale occurrences, old resolved findings, run results, old finding keys, raw reports (7 days when they name secrets), abandoned uploads, and the event and audit months, with minimums from PCI DSS 10.5.1 and an audit entry per tenant; partitions created ahead by `rampart maintenance` (Helm CronJob) (D53) | built; tested on PostgreSQL, the chart rendered in CI, Vitest. Not built: the `RetentionPolicy` resource, per-tenant periods, notification retention, GDPR purge by asset |
| Phase 1: unreadable records with their position on the run page, the close step skipped on them, and the raw report for maintainers with an audit entry (D51) | built; tested on PostgreSQL and with Vitest. Not built: recoverable records in SARIF, CycloneDX, SPDX and Syft; retention |

## Phase −1 — Decisions and spikes (week 1)

- Confirm the decisions that get baked into code: name, API group, module path, license, minimum Kubernetes and PostgreSQL ([16](16-implementation-decisions.md) D7).
- Spikes with written results:
  1. Ingest throughput: 100k SARIF results through staging, merge and occurrence upsert on the reference hardware (D28).
  2. `COPY` into the staging table plus `INSERT … SELECT` into RLS tables as a non-owner role.
  3. River behind PgBouncer: direct connection for the notifier, poll-only fallback.
  4. Helm install order with bundled CloudNativePG and SeaweedFS.
  5. Streaming SARIF parse with a token walk, memory under 256 MiB for a 500 MiB file.
  6. (Before Phase 3) Mapping engine speed: streaming path selection with CEL at 100k records; `wazero` throughput for a WASI parser.
- **Exit**: decisions recorded as ADRs; spike numbers replace the goals in D28 or the goals are changed.

## Phase 0 — Foundations (weeks 2–5)

- Repository layout, `cmd/rampart -target`, configuration (D6), logging, OpenTelemetry, ops port.
- Integration contracts and registry (`internal/integrations`) and the canonical JSON Schemas; built-in parsers are written against them from the start.
- Schema v1 from [12](12-database-schema.md) with its delta table, four database roles, RLS, migrations Job and `migrate wait`, partition maintenance job.
- River integration; job and event abstractions; per-tenant concurrency cap.
- `internal/config/apply`; operator with `Tenant`, `Application`, `ScanSource` reconcilers; `rampart apply -f` for file mode; envtest.
- Secret material sync (operator → encrypted table).
- Helm chart (monolithic, bundled CNPG and SeaweedFS) and Docker Compose with seed resources.
- CI: lint, unit, testcontainers, envtest, cross-tenant leak test harness, ko build, cosign, SBOM, SLSA provenance.
- Frontend: app shell, tokens and base components from [13](13-frontend.md) §6, login screen against the static OIDC provider.
- **Exit**: `helm install` works; applying an `Application` shows `Ready=True`; `rampart -target=all` boots from Compose with a usable default tenant; a user can log in and see an empty workbench.

## Phase 1 — Ingest core (weeks 6–11)

- Upload API (presigned, direct, size and hash verification), idempotency, `ingest_run` lifecycle.
- Parsers: SARIF (token walk, enrichers for Semgrep, Trivy, Gitleaks) and CycloneDX (SBOM and VDR).
- Normalization, fingerprint specification (D11), assets, versions and tracks (D10), merge and close (D13), ephemeral runs.
- Enrichment from OSV, KEV and EPSS; tenant-local vulnerability and rule tables (D19).
- Query API with the filter grammar (D16), cursors, the supported filter and sort matrix.
- Workbench: query bar, facets, table with score bar, docked inspector, ingest run page.
- Auth: one OIDC provider from config, roles `viewer`, `triager`, `admin` at tenant scope, API tokens, `rampart login --token`, `rampart upload`.
- **Exit**: golden tests prove rescans dedupe, close and reactivate correctly, including concurrent and out-of-order runs; EPSS and KEV visible on findings; cross-tenant leak test green.

## Phase 2 — Triage, risk, deadlines → MVP (weeks 12–17)

- Detection and disposition model (D18), triage actions, bulk operations, notes, timeline.
- Risk acceptance with expiry and approval; VEX import and export (OpenVEX, CycloneDX).
- `RiskPolicy` and `SLAPolicy` CRDs with cluster defaults; scoring engine in the `policy` target; deadlines, breach sweep; aggregate read models.
- Built-in automation: one CI gate rule and `rampart gate --expect`, ticket-on-critical placeholder (no connector yet).
- Scoped RBAC, `AccessBinding` and `IdentityProvider` CRDs, device login for the CLI, audit log.
- Taxonomies (OWASP Top 10 2021 and 2025, CWE Top 25, PCI DSS, ISO 27001, SSDF) and compliance views.
- Native parsers: Trivy, Grype, Semgrep, Gitleaks. Retention job for occurrences and events.
- Overview page, application pages, risk acceptance and administration screens.
- **Exit (MVP)**: an analyst triages end to end in the UI; deadlines breach and notify in-app; the gate blocks a pipeline on new critical findings; every P0 row in [01](01-features.md) is done.

## Phase 3 — Workflow and integrations (weeks 18–24)

- Connectors: Jira (two-way, transitions create requests not states), GitHub Issues, Slack, Microsoft Teams, email, signed webhooks; `Connector` CRD; notification routing with digests.
- **Dependency-Track**: FPF parser, REST client and connector with permission probe, portfolio and project sync with mapping rules and the unmapped-projects screen, webhook trigger with trailing debounce, triage import, gate linking (D23).
- **Integration SDK, part 1** ([19-integration-sdk.md](19-integration-sdk.md)): mapping engine and `IntegrationPackage` (`runtime: mapping`); unified `Tracker`, `Notifier` and `Source` contracts with a registry; declarative notifiers and trackers; conformance kit for parsers; connector forms generated from config schemas.
- Parsers wave 2, written as mappings wherever the format allows: Checkov, Nuclei, ZAP, Bandit, Dependency-Check, kube-bench, Prowler (OCSF), Snyk, Syft, GitLab report schemas, SPDX, Generic JSON.
- Correlation groups, finding groups and one ticket per group, saved views, exports (CSV, JSON, SBOM, VEX, OCSF), live updates (SSE).
- CI OIDC federation with token exchange and the mass-close guard (D22); rate limiting and per-token quotas; NVD enrichment; ownership from CODEOWNERS; SBOM inventory views.
- Grafana dashboards and alert rules.
- **Exit**: a team can run its CI ingestion and Jira workflow on Rampart and see Dependency-Track findings under the same score and deadlines.

## Phase 4 — Hardening → v1.0 (weeks 25–29)

- Simple-scalable mode supported; high availability; backup, point-in-time recovery and a tested disaster-recovery runbook.
- Air-gapped install: OCI bundle, `ClusterFeedMirror`, egress deny.
- SAML; identity-provider screens.
- **Integration SDK, part 2**: WebAssembly parser plugins, signed OCI packages, `rampart integration` CLI, the public catalogue repository and the catalogue page in the UI.
- Performance validation of the query SLO on the 5M-finding dataset; parser fuzzing; external security review; upgrade and rollback tests across one minor version.
- Arabic locale; documentation site; CRD reference.
- **Exit**: v1.0 tagged; every P1 row done; signed images with SBOM and provenance; no open critical or high findings in our own tenant.

## Phase 5 — v1.x

- Generic CEL policy engine with simulate mode; `Policy`, `Exception`, `DedupPolicy`, `RetentionPolicy`, `HierarchyNode` CRDs.
- Distributed mode with KEDA; NATS event bus; Valkey; optional ClickHouse or OpenSearch read store.
- Dependency-Track SBOM forwarding, triage write-back, policy violations; DefectDojo-compatible shim and migration tool.
- `collector` target for PolicyReport, OpenReports and Trivy Operator reports; `ClusterScanSource`.
- Cross-tool merge; attestation verification (in-toto, SLSA, cosign) and code-to-cloud edges.
- SCIM, custom roles, tenant self-service and quotas.
- **Integration SDK, part 3**: declarative API sources (SonarQube, GitHub Code Scanning, GitLab, Snyk written this way), gRPC plugins for sources, trackers and notifiers, Python and TypeScript SDKs.
- MCP server, SSVC, scheduled PDF reports, remediation campaigns.
- `v1beta1` CRDs with conversion webhook.

## How we work

- **Decisions before code.** A phase starts with the ADRs it needs, then an OpenAPI diff, then implementation. [16](16-implementation-decisions.md) is the current normative baseline.
- **Vertical slices from Phase 1 on.** A change ships parser, merge, API and UI for one narrow thing, with fixtures and a golden test. Phase 0 is the one infrastructure-only phase, and it still ends with a login screen.
- **Fixtures are the specification.** `internal/parsers/<name>/testdata/<tool-version>/` holds real, sanitized scanner outputs. A parser is fixtures, a golden canonical output and a fingerprint-stability test.
- **Budgets are tests.** The query benchmark runs nightly against a seeded 5M-finding database. Ingest has no throughput budget (D35).
- **Kubernetes-first loop**: `kind` plus Tilt or Skaffold; `-target=all` for fast iteration.
- **Untrusted input everywhere**: fuzz tests for parsers, size, depth and time limits, no XML entity expansion, security review for every connector.
- Conventional commits, semantic versioning, generated changelog; CRDs and API keep one minor version of deprecation overlap.

## Open decisions for the team

1. Confirm or change the name, API group and module path (D7). Everything in these documents uses `rampart`.
2. License: Apache-2.0 proposed. Define open-core boundaries, if any.
3. First ticketing connector after Jira: GitHub Issues is assumed; GitLab Issues if the first users need it.
4. Whether the UI needs a manual upload screen in the MVP (assumed: yes, a simple one).
5. Team size and start date, which fix the calendar.
