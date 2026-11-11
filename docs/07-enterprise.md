# 07 — Enterprise requirements: tenancy, identity, security, operations

## 1. Multi-tenancy

- **Model**: `Tenant` CRD (cluster-scoped) ↔ the namespaces it lists (one by default) ↔ `tenant_id` in Postgres. All tenant tables have `tenant_id` as the first column of every index.
- **Isolation levels**:
  - *Shared* (default): shared DB with Row-Level Security. The application DB role has `FORCE ROW LEVEL SECURITY` policies; each transaction sets `app.tenant_id` via `set_config(..., true)` so it works under PgBouncer transaction pooling. Code still filters explicitly; RLS is the backstop.
  - *Dedicated DB* (P3): per-tenant CNPG cluster, selected by the tenant row; same code path through a connection router.
- **Quotas**: per-tenant ingests/hour, report bytes, API RPS, retention tier; enforced at the gateway and scheduler.
- **Hierarchy / business units**: `HierarchyNode` trees inside a tenant (ArmorCode Hierarchies). Every finding and SLA report is scoped by node; dashboards filter by node.
- **MSSP mode**: a global admin role can list tenants; no cross-tenant data joins exist in the schema.

## 2. Identity and access

- **AuthN**:
  - Humans: OIDC Authorization Code + PKCE (Okta, Entra, Keycloak, Google, GitHub). SAML 2.0 in-process (`crewjam/saml`) for IdPs without OIDC; Dex or Keycloak only as brokers for LDAP.
  - Machines: API tokens (`rpt_<prefix>_<secret>`, stored as SHA-256, scoped, expiring), Kubernetes ServiceAccount TokenReview for in-cluster callers, GitHub/GitLab OIDC federation for CI (no static secrets: trust the CI provider's OIDC issuer, map `repository`/`project_path` claims to a `ScanSource`).
  - MFA is delegated to the IdP.
- **AuthZ**: roles × scopes.

| Role | Can |
|---|---|
| viewer | read findings/assets/dashboards in scope |
| triager | + change state, verified, severity override with reason, notes, request risk acceptance |
| maintainer | + approve risk acceptance, manage applications, policies, groups, tickets |
| owner | + manage scan sources, connectors, access bindings in scope |
| admin (tenant) | everything in the tenant, tokens, retention, audit export |
| platform-admin | tenants, feed mirrors, cluster policies |

  Scope = tenant, hierarchy node (inherits down), or application. Bindings come from `AccessBinding` CRs and/or SCIM groups. Evaluated with casbin (RBAC with domains); policy cached per request. Attribute checks ("owner of the finding may…") are explicit in handlers.
- **SCIM 2.0** (P2): `/scim/v2/Users` and `/Groups`; groups map to teams; deprovisioning disables users and revokes tokens.
- **Audit**: append-only `audit_event` table (partitioned by month, no UPDATE/DELETE grants), covering auth events, every mutating API call, policy actions, connector pushes, admin changes. Export API (`GET /api/v1/audit?since=`) with cursor; optional streaming to a webhook / NATS subject for SIEM.

## 3. Data protection

- Secrets: the source of truth is a Kubernetes Secret referenced by name (or a file in non-Kubernetes installs). The operator copies the referenced material into the envelope-encrypted `secret_material` table (AES-256-GCM, per-tenant data key wrapped by KMS or a mounted master key) so that targets without Kubernetes access can use it. Nothing is stored in plain text.
- Raw reports in object storage with SSE; bucket per tenant optional; presigned URLs expire in 15 minutes.
- Secrets findings: the matched secret is stored only as a hash (`secret_hash`) plus a redacted preview (first/last 2 chars); raw report retention for secret scanners defaults to 7 days.
- PII in findings (emails in Gitleaks output etc.) is subject to the retention policy; a `purge` endpoint per asset exists for GDPR requests.
- TLS everywhere; mTLS between targets in distributed mode optional via mesh.

## 4. Operations

- **Install**: Helm umbrella chart (`charts/rampart`) with sub-charts CNPG (Postgres), MinIO, Valkey, NATS toggled by `mode` and `bundled.*` flags; Kustomize overlays for the operator; OLM bundle optional for OpenShift.
- **Upgrades**: Helm `pre-upgrade` hook Job runs migrations; migrations are backward compatible for one minor version (expand/contract), so rolling pods on different versions is safe.
- **HA**: every target stateless except the operator/scheduler leader (Lease election); CNPG 3-instance cluster with synchronous replica optional; MinIO distributed or external S3.
- **Scaling**: KEDA `ScaledObject` per worker target on River queue depth (Postgres scaler) or JetStream lag; HPA on CPU/RPS for gateway and query-api.
- **Backups / DR**: CNPG Barman to object storage, PITR; raw reports are reproducible inputs so they can be excluded from backups; DR runbook in `docs/ops/`.
- **Observability**: OTel traces across gateway → job → connector with the ingest run id as a baggage item; Prometheus metrics (`rampart_ingest_runs_total`, `rampart_findings_open{tenant,band}`, `rampart_sla_breaches_total`, `rampart_parser_duration_seconds{family}`, River queue metrics, controller-runtime metrics); Grafana dashboards shipped in the chart; alert rules for queue age, failed ingests, feed staleness.
- **Air-gapped**: OCI bundle (`rampart-bundle.tar`) containing images, chart, CRDs, feed snapshots; `ClusterFeedMirror.egress: deny`; `rampart feeds snapshot` / `rampart feeds import` CLI.
- **Rate limiting**: per token and per tenant token buckets in Valkey (or in-process in monolithic mode); `429` with `Retry-After`; upload size limits per tenant.
- **Retention**: `RetentionPolicy`; occurrences and events partitioned monthly so expiry is a partition drop; S3 lifecycle rules generated by the operator for bundled MinIO.

## 5. Product supply chain (we eat our own food)

- Build with `ko` (or buildx) → distroless `static:nonroot`, multi-arch (amd64/arm64).
- Sign images and chart with cosign (keyless, GitHub OIDC); attach CycloneDX SBOM and SLSA v1 provenance; publish a `cosign verify` policy snippet.
- CI runs Trivy, Semgrep, Gitleaks, govulncheck, Scorecard and uploads the results into a public demo Rampart tenant; releases are gated by our own `Policy` gate.
- Security policy, CVE disclosure process and VEX documents published per release.

## 6. Compliance mappings shipped

Data-driven taxonomies (versioned JSON in `internal/taxonomy/data/`): OWASP Top 10 2021 and 2025 (CWE lists), CWE Top 25 (2023–2025), OWASP ASVS 5.0 via OpenCRE, OWASP API Top 10 2023, PCI DSS 4.0.1 req 6/11, ISO/IEC 27001:2022 Annex A.8, NIST SSDF 1.1, SOC 2 CC6–CC8, CIS Benchmarks (ids pass through from scanners), SLSA levels, OpenSSF Scorecard checks. Reports: "controls with open findings", "coverage per control", evidence bundle (findings + acceptance history + scan runs) as ZIP/JSON.
