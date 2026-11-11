# ADR 0004 — One binary, many targets (Loki/Mimir deployment model); write path and read path are separate targets

Status: accepted · Date: 2026-11-10

## Context
The user requires component separation (the part that receives reports is not the part that displays them) and a cloud-native design that runs on Kubernetes, while an evaluation install must stay simple. Grafana Loki/Mimir compile all components into one binary and select with `-target`, allowing monolithic, simple-scalable and microservices modes from the same image.

## Decision
- Single Go binary `rampart` and single image. Targets: `ingest-gateway`, `parser`, `enrich`, `policy`, `notify`, `sync`, `query-api`, `web-ui`, `operator`, `scheduler`, `mcp`, and composites `all`, `write`, `read`.
- Hard boundaries in code: `ingest`/`parsers` packages are never imported by `query`; `query-api` serves UI queries and commands and never parses reports; `ingest-gateway` never serves UI data; only `operator` imports `controller-runtime`.
- Helm `mode: monolithic | simple-scalable | distributed` selects Deployments, Services and Ingress routing by path prefix (`/ingest`, `/hooks` → gateway; `/api`, `/auth`, `/scim` → query-api; `/` → web-ui).
- State lives in Postgres and object storage, so switching modes requires no data migration.

## Consequences
- One artifact to build, sign, scan, mirror and support.
- Independent scaling and RBAC per target in distributed mode; KEDA on worker targets.
- Slightly larger image than per-service builds; acceptable (static Go binary, distroless).
