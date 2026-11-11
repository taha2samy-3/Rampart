# ADR 0001 — CRDs hold configuration and summaries; findings live in PostgreSQL

Status: accepted · Date: 2026-11-10

## Context
We want a Kubernetes-native platform with its own CRDs. Trivy Operator and Starboard store full reports as custom resources and hit etcd limits (1.5 MiB per object, 2–8 GB total, cluster goes read-only when exceeded), watch fan-out memory, and no query capability. Kyverno moved reports to a Postgres-backed aggregated API server for the same reasons. Kubernetes docs advise against CRs for large data or thousands of objects.

## Decision
- CRDs (`Tenant`, `Application`, `ScanSource`, `ReportIngest`, `DedupPolicy`, `RiskPolicy`, `SLAPolicy`, `Policy`, `Exception`, `Connector`, `RetentionPolicy`, `ClusterFeedMirror`, `AccessBinding`, `ScheduledScan`) carry desired state and bounded status (conditions, counters, ids, timestamps).
- Findings, occurrences, vulnerabilities, events, audit rows live in PostgreSQL.
- The operator reconciles CRs into config tables and writes status back with server-side apply. No CR may contain per-finding data.
- `ReportIngest` is the only "job-like" CR; it carries a pointer to an object in the tenant's storage prefix, never the payload, and has a TTL. It is created by users or GitOps only. API uploads never create custom resources, so upload volume cannot load etcd.
- Consuming `PolicyReport`/OpenReports/Trivy CRs from managed clusters is done by a separate `collector` target after v1.0, not inside the operator.
- An aggregated API server exposing `findings` over Postgres is a possible future addition, not part of v1.

## Consequences
- `kubectl get applications` shows risk and counts; `kubectl get findings` does not exist in v1.
- GitOps works for all configuration; data is backed up through CNPG, not etcd.
- The operator needs database access; it is the only component that reads or writes Rampart CRs and Secrets.
