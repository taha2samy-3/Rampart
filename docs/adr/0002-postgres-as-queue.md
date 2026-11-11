# ADR 0002 — PostgreSQL (River) is the default job queue and event bus; NATS JetStream is an optional adapter

Status: accepted · Date: 2026-11-10

## Context
The pipeline (parse → merge → enrich → policy → notify) is a chain of retryable jobs with state, not a high-fan-out stream. The platform must install in minutes on a small cluster and also scale. Kafka needs Strimzi/Redpanda (Dependency-Track Hyades experience); Redis Streams durability depends on persistence config; RabbitMQ adds Erlang without a Go-side advantage over NATS.

## Decision
- Define `internal/events.EventBus` and `internal/jobs` abstractions.
- Default implementation: **River** on the same PostgreSQL. Jobs are inserted in the same transaction as the state change they depend on (transactional outbox). Unique jobs keyed by `(kind, ingest_run_id)` make retries idempotent. Periodic jobs cover feed sync, SLA sweeps, retention.
- Optional implementation: **NATS JetStream** for external fan-out (SIEM, multi-cluster, webhooks at scale), enabled by Helm `eventBus.type=nats`. Internal pipeline stays on River even when NATS is on; NATS mirrors domain events.
- Scaling: KEDA Postgres scaler on River queue depth per queue (`parse`, `enrich`, `policy`, `notify`, `dtrack-sync`, `dtrack-push`, `maintenance`).
- The pipeline emits one event per run and scope, not one job per finding, so queue volume follows the number of reports. River's notifier uses a direct database connection; behind PgBouncer alone it runs in poll-only mode.

## Consequences
- Zero extra infrastructure for the default install; one backup covers data and queue.
- Queue throughput is bounded by Postgres; River handles thousands of jobs/s, sufficient for ingestion where each job is a whole report, not a finding.
- If Postgres becomes the bottleneck, the abstraction allows moving the pipeline to NATS without touching domain code.
