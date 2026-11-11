# Research: Kubernetes-native design patterns

Research date: 2026-11-10.

---

## 1. Prior art: Kubernetes-native security-result CRDs

### Trivy Operator (`aquasecurity.github.io/v1alpha1`)
CRDs: `VulnerabilityReport`, `ConfigAuditReport`, `ExposedSecretReport`, `RbacAssessmentReport`, `ClusterRbacAssessmentReport`, `InfraAssessmentReport`, `SbomReport`, `ClusterComplianceReport`. No `spec`/`status` split: whole payload under `report{scanner, registry, artifact, os, updateTimestamp, summary{criticalCount, highCount, ...}, vulnerabilities[]{vulnerabilityID, severity, resource, installedVersion, fixedVersion, cvss, packagePURL, ...}}`. Namespaced, named after workload+container, ownerRef to workload. `ClusterComplianceReport` is the exception with `spec` (control mapping, cron) + `status` (results). https://aquasecurity.github.io/trivy-operator/latest/docs/crds/

### Policy WG `PolicyReport` → OpenReports
`wgpolicyk8s.io/v1alpha2` `PolicyReport` / `ClusterPolicyReport` (being archived; successor **OpenReports** `Report` / `ClusterReport`, https://github.com/openreports/reports-api). Shape: `scope` (ObjectReference), `source`, `summary{pass, fail, warn, error, skip}`, `results[]{policy, rule, category, severity (critical|high|medium|low|info), result (pass|fail|warn|error|skip), message, timestamp, properties (map), resources[]}`. Producers: Kyverno, Trivy Operator, Falco (via Falcosidekick), Kubewarden, jsPolicy, Netchecks, Tracee. Consumers: Policy Reporter, Fairwinds Insights.

**Takeaway**: PolicyReport/OpenReports is the de-facto interchange schema for Kubernetes findings. Consume it as an ingestion source; do not reinvent it.

### Other designs
- **Kyverno reports-server**: aggregated API server serving `wgpolicyk8s.io` reports from PostgreSQL instead of etcd. Rationale: etcd ~8 GB ceiling, reports are analytical data, "find every report with CVSS ≥ 8" requires fetching all reports via k8s API. ~70% etcd reduction at 10k reports. https://github.com/kyverno/reports-server
- **Kubescape storage**: aggregated API server storing `VulnerabilityManifest`, SBOMs, `ApplicationProfile` as Gob files on a volume + SQLite metadata; LIST returns metadata only. https://github.com/kubescape/storage
- **secureCodeBox**: `Scan` → `ScanType` → `ParseDefinition` CRDs; raw and parsed findings in S3, not CRs. https://docs.securecodebox.io/docs/api/crds
- **OpenShift Compliance Operator**: `ComplianceSuite` → `ComplianceScan` → one `ComplianceCheckResult` CR per rule; raw ARF to PVC.
- **Dependency-Track**: v4 apiserver + static frontend; v5 "Hyades" decomposes into apiserver, frontend, notification-publisher, repository-meta-analyzer, vulnerability-analyzer over Kafka. Air-gapped: mirror NVD/OSV/KEV internally. https://dependencytrack.github.io/hyades/
- **OpenClarity/VMClarity**: single API server is the only DB-talking component; scanners report via OpenAPI; Helm, no CRDs.
- **Starboard** hit "etcdserver: request is too large" on big reports.

### Why not store bulk findings in etcd
- Per-object limit: etcd `--max-request-bytes` default 1.5 MiB; apiserver ~3 MiB body limit. https://etcd.io/docs/v3.5/dev-guide/limit/
- Total quota: default 2 GiB, practical max 8 GB; exceeding → cluster read-only ("mvcc: database space exceeded"). Hourly rescans × many images fill quota in days. https://www.aquasec.com/blog/when-security-scans-break-the-brain-solving-trivys-etcd-exhaustion-problem/
- Watch/list cost: watch cache per type per apiserver replica; re-list storms spike apiserver RSS; any `Get`/`List` in controller-runtime loads every object of that type into operator memory via informer.
- No query capability: label/field selectors only; no CVSS filter, joins, aggregation.
- Kubernetes guidance on when *not* to use a CR: "stores large data (more than a few KB per object, or thousands of objects)", "high-bandwidth access", "operations are not CRUD-like". https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/#should-i-add-a-custom-resource-to-my-kubernetes-cluster

**Consensus**: CRDs for configuration/desired state and small bounded summaries; a real database for findings; optionally an aggregated API server later for `kubectl get` over DB-backed reports.

## 2. Operator best practices (kubebuilder + controller-runtime)

- **Versions**: Kubebuilder v4.x (v4.11 scaffolds controller-runtime v0.23); controller-runtime v0.22 added native SSA (`client.Apply`), `ReconciliationTimeout`. https://book.kubebuilder.io/
- **CRD versioning**: start `v1alpha1`; one storage version; hub-and-spoke conversion webhook when needed (needs cert-manager). Avoid conversion webhooks until truly needed; add fields additively.
- **CEL vs webhooks**: `x-kubernetes-validations` (GA 1.29) runs in apiserver, no TLS; `self`/`oldSelf` transition rules for immutability, `messageExpression`, cost budgeting. Marker: `+kubebuilder:validation:XValidation:rule="...",message="..."`. OpenAPI `default:` for defaulting. Reserve webhooks for validations needing external state, or surface as `Ready=False` condition instead.
- **Status & conditions**: `+kubebuilder:subresource:status`; `metadata.generation` bumps only on spec change; `metav1.Condition{Type, Status, Reason, Message, ObservedGeneration, LastTransitionTime}` via `meta.SetStatusCondition`; always set `status.observedGeneration`. https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties
- **Good practices**: idempotent reconcile, one controller per Kind, standard conditions, structured logging. https://book.kubebuilder.io/reference/good-practices
- **Finalizers** for external cleanup; **ownerReferences** via `controllerutil.SetControllerReference`.
- **Server-side apply**: fully-specified intent with own field manager, `force=true` for owned fields.
- **Workqueue**: default limiter = max(per-item exponential 5ms→1000s, global token bucket); `MaxConcurrentReconciles`; return errors for backoff; `RequeueAfter` for polling.
- **Leader election** via Lease; metrics `controller_runtime_reconcile_total/errors_total/time_seconds`, `workqueue_depth`.
- **Cache scoping**: restrict informers by namespace/label; `metadata-only` watches for Secrets.
- **Multi-tenancy**: namespace-scoped CRs as tenant boundary; cluster-scoped variants (`ClusterRiskPolicy`) for defaults resolved namespace-first then cluster (secureCodeBox ADR-0012).
- **Aggregated API server vs CRD**: CRDs lack custom storage, protobuf, extra subresources. Use CRDs for config; aggregated server only later for DB-backed `kubectl get findings`.
- **OLM**: v1 uses `ClusterExtension`; Helm installs Tech Preview. Ship Helm primary, OLM bundle optional.

## 3. Reference architecture (modular, event-driven, Go)

Components (each a `-target`):
1. **ingest-gateway**: authn, idempotency, presigned-URL issuance, writes upload row + outbox event.
2. **parser/normalizer workers**: pull raw report from object storage, parse, emit normalized findings in batches.
3. **dedup/correlation**: fingerprint, upsert, state transitions, link to assets.
4. **enrichment workers**: NVD/OSV/EPSS/KEV against locally mirrored feeds; cache.
5. **risk/policy engine**: scoring + CEL/Rego → SLA deadlines, severities, suppressions.
6. **notification/integration workers**: Jira/Slack/webhooks from outbox events with retries.
7. **query/read API**: read-optimized endpoints over Postgres (+ optional ClickHouse/OpenSearch).
8. **web UI**: static SPA served by API binary or nginx sidecar.
9. **scheduler**: periodic jobs (feed sync, retention, rescans).
10. **operator**: reconciles CRDs → DB config rows, creates Jobs/CronJobs, reports conditions.

**Messaging**: best default is **Postgres as the queue** (River: transactional enqueue with pgx, unique jobs, periodic jobs, retries, batch insert — https://riverqueue.com/docs; or pgmq). Zero extra infra; jobs commit atomically with findings (transactional outbox for free). Pluggable `EventBus` interface with **NATS JetStream** as second implementation for high-throughput/multi-cluster fan-out (single Go binary, at-least-once with `Nats-Msg-Id` dedup, KV + Object Store, Helm chart, KEDA scaler). Kafka is overkill for small installs (Hyades experience); Redis Streams durability depends on config; RabbitMQ brings no advantage over NATS for Go.

**Storage**: PostgreSQL via **CloudNativePG** (Cluster CRD, HA, `-rw/-ro` services, Barman backups, PITR, PgBouncer Pooler). Object storage (S3/MinIO; SeaweedFS/Garage for small) for raw reports and SBOMs. Valkey for cache/rate-limit. Optional ClickHouse/OpenSearch for analytics and full-text. Light **CQRS**: same DB, read models refreshed by outbox consumers, not heavy joins at request time.

## 4. Go ecosystem choices

- **HTTP**: `net/http` 1.22+ `ServeMux` or **chi**; OpenAPI via **Huma** (code-first, OpenAPI 3.1) or **oapi-codegen** / **ogen** (spec-first); Connect-go for internal gRPC+JSON.
- **DB**: pgx/v5 + sqlc (`:copyfrom` for bulk) + goose (embedded migrations) or Atlas. River for jobs.
- **Auth**: `coreos/go-oidc`; RBAC via **casbin** (embedded) or **OpenFGA** (CNCF incubating, ReBAC) for asset-level sharing.
- **Policy**: **cel-go** embedded (same language as k8s validation and Kyverno CEL; sandboxed, cost-bounded); OPA/Rego optional second engine.
- **Observability**: OTel Go (traces/metrics stable, logs RC with `otelslog`), Prometheus exporter, `slog`, `logr` adapter in operator.
- **CLI/config**: cobra + koanf.
- **Codegen**: controller-gen for CRDs/RBAC; `+kubebuilder:printcolumn`.
- **Packaging**: Helm umbrella chart (CNPG/NATS/MinIO sub-charts toggled off by default) + Kustomize; **ko** (`--platform=all`, distroless `static:nonroot`, auto SPDX SBOM) or buildx + syft; cosign sign + attest. Product should ship its own CycloneDX SBOM and be ingestible by itself.

## 5. Scaling and multi-tenancy

- **Tenant model**: `tenant_id` column + Postgres **RLS** (`set_config('app.tenant_id', $1, true)` per transaction; app role must not be table owner; RLS as backstop, still filter explicitly). Map tenants to namespaces for CRDs/RBAC.
- **Uploads**: presigned PUT (≤5 GB) or multipart; `complete` call carries **Idempotency-Key** (unique index) so retries return same ingest id; sha256 content hash dedupes identical re-uploads.
- **Dedup at scale**: stable fingerprint = hash(tenant, asset, scanner family, rule/CVE id, normalized location/purl); batch `INSERT … ON CONFLICT (tenant_id, fingerprint) DO UPDATE` with `CopyFrom`; per-tenant bloom filter / Valkey set to short-circuit; stage into unlogged tables then merge.
- **Workers**: stateless Deployments scaled by **KEDA** on River queue depth (Postgres scaler) or JetStream lag (scale to zero). Backpressure: bounded queues, 429 + `Retry-After`, per-tenant token buckets.
- **Retention**: periodic job deleting resolved findings / raw reports past policy; partition findings by month; S3 lifecycle rules.

## 6. Air-gapped and single-binary vs microservices

Loki and Mimir compile every component into one binary; `-target=all` runs all in-process (monolithic), `-target=ingester` etc. runs one per process (microservices), with "simple scalable" as intermediate; state in shared storage so modes switch with little config change. https://grafana.com/docs/loki/latest/get-started/deployment-modes/

Why it fits: one image to scan, sign, mirror, support; `docker run aspm -target=all` quickstart; Helm `mode: monolithic|distributed`; the same queue abstraction works in-process (River on one Postgres) or across pods (NATS). Dependency-Track shows the minimal split (apiserver + static frontend) that even monolithic mode should keep.

Air-gap checklist: mirror NVD, OSV per-ecosystem `all.zip`, KEV, EPSS to an internal HTTP server / OCI registry; configurable feed URLs in a `FeedMirror` CR; bundle Trivy DB as OCI artifact; ship charts + images as OCI bundle; no outbound calls by default.

## 7. CRD design ideas

Group `aspm.example.io/v1alpha1`, namespaced unless noted; each has `spec` + `status{conditions[], observedGeneration}`:
- **ScanSource / Integration**: where reports come from (CI webhook, Trivy Operator CRs, registry, Git); `spec.type`, `spec.credentialsRef`, `spec.schedule`; status `Ready`, `LastSyncTime`.
- **IngestionPolicy**: accepted formats, max size, auto-close rules, namespace/label → Application mapping.
- **DedupPolicy**: fingerprint fields per scanner family, merge windows.
- **RiskPolicy / SLAPolicy**: CEL expressions for score; SLA days per severity; cluster-scoped defaults.
- **Application / Asset**: inventory; `spec.selector` mapping to workloads; status counts summary only, never findings.
- **Connector**: Jira/Slack/webhook config referencing Secrets; connectivity conditions.
- **ReportIngest**: job-like CR per upload: `spec.source`, `spec.objectRef{bucket, key, sha256}`, `spec.format`; status phase `Pending|Parsing|Deduping|Completed|Failed`, counts; TTL.
- **ScheduledScan**: cron + ScanSource ref; operator creates CronJob/Job.
- **RetentionPolicy**, **FeedMirror**.

CRDs vs DB rows: CRDs = declarative, small, human-edited, GitOps-able config and summaries; DB rows = findings, inventory details, enrichment, audit log, tickets, users. Operator bridges: reconciles CRs into config tables (keyed by `namespace/name/uid`), writes back conditions and bounded summary numbers with SSA. Consume `PolicyReport`/`VulnerabilityReport` from managed clusters as `ScanSource.type=kubernetes` so existing Trivy/Kyverno/Falco installs feed the platform without agents.

## Key sources
- Trivy Operator CRDs: https://aquasecurity.github.io/trivy-operator/latest/docs/crds/
- PolicyReport: https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report · OpenReports: https://github.com/openreports/reports-api · Kyverno reports-server: https://github.com/kyverno/reports-server
- Kubescape storage: https://github.com/kubescape/storage · secureCodeBox: https://docs.securecodebox.io/docs/api/crds
- Dependency-Track Hyades: https://dependencytrack.github.io/hyades/ · air-gapped: https://dependencytrack.github.io/docs/next/guides/administration/running-air-gapped/
- etcd limits: https://etcd.io/docs/v3.5/dev-guide/limit/
- Kubebuilder: https://book.kubebuilder.io/ · SSA: https://kubernetes.io/docs/reference/using-api/server-side-apply/ · CEL: https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation-rules
- Loki modes: https://grafana.com/docs/loki/latest/get-started/deployment-modes/
- NATS JetStream: https://docs.nats.io/nats-concepts/jetstream · River: https://riverqueue.com/docs · KEDA: https://keda.sh/docs/latest/scalers/ · CloudNativePG: https://cloudnative-pg.io/docs/current/
- RLS: https://aws.amazon.com/blogs/database/multi-tenant-data-isolation-with-postgresql-row-level-security · Huma: https://huma.rocks/ · sqlc: https://docs.sqlc.dev/
