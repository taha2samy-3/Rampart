# Implementation Plan: Phase 1 (Ingest Core) Complete

## Overview
Complete Phase 1 (Ingest Core) for Rampart ASPM according to the architecture specification, roadmap (`09-roadmap.md`), and normative decisions (`16-implementation-decisions.md`). This builds the remaining Phase 1 deliverables: presigned uploads with a background parse worker, object storage client integration, threat intelligence feed sync (OSV, KEV, EPSS) with tenant-local tables (D19), the SQL query builder with signed keyset cursors (D16, D28), and the ingest benchmark.

> **CRITICAL RESTRICTION**: A Kubernetes cluster is connected to the environment. It must NEVER be accessed or used under any circumstances whatsoever. All work and tests use unit tests, in-memory mocks, and local testcontainers only.

---

## Architecture Decisions
- **D2 & D9 (Presigned Upload & Parse Worker)**: `POST /ingest/v1/uploads` issues presigned PUT URL with Content-Length signed in; `POST /uploads/{id}/complete` verifies size and sha256 against object storage, sets upload to completed, creates `ingest_run(queued)` and enqueues `ParseJob` in one transaction. Parse worker streams from object store, parses, normalizes, merges and closes.
- **D13 & D18 (Merge, Close & Disposition)**: 5 000 rows per batch, advisory lock per scope, classification into created/updated/untouched/reactivated via `content_hash`, upserting occurrences, close step marks absent occurrences and fixes active findings with no occurrences, while preserving non-active states (`not_affected`, `risk_accepted`, etc.) with `detection=absent`.
- **D14 & D19 (Intelligence & Feed Sync)**: Official feeds (OSV, KEV, EPSS) write to global `vulnerability`, `vulnerability_alias`, and `rule` tables using `rampart_system`. Unknown findings from tenant reports create tenant-local stubs in `vulnerability_local` and `rule_local` so tenants never mutate global tables.
- **D16 & D28 (SQL Query Builder & Keyset Cursors)**: Translate `grammar.Query` into parameterized SQL `WHERE` clauses matching all Phase 1 fields (`state`, `severity`, `risk`, `score`, `category`, `scanner`, `rule`, `cve`, `cwe`, `app`, `asset`, `assettype`, `env`, `track`, `path`, `purl`, `tag`, `owner`, `kev`, `fix`, `sla`, `age`, `seen`, `source`, `run`). Support sort keys (`-score`, `score`, `-seen`, `-age`, `age`, `severity`) and HMAC-signed cursors encoding `(sort_values, id)` for efficient keyset pagination without full-table in-memory filtering.
- **Ingest Benchmark**: Benchmark 100k findings ingestion, deduplication, rescan, and cross-tenant isolation in automated tests.

---

## Task List

### Phase 1.1: Object Storage & Background Parse Worker Integration
- [ ] Task 1: Wire Object Storage client into `targets.Runner` and `Gateway`
- [ ] Task 2: Implement and wire the background Parse Worker for both River (Postgres) and in-memory queue
- [ ] Task 3: Comprehensive tests for presigned upload -> PUT -> complete -> parse worker lifecycle

### Phase 1.2: Threat Intelligence & Feed Sync (OSV, KEV, EPSS) & Local Tables
- [ ] Task 4: Implement feed sync service for CISA KEV JSON, FIRST EPSS CSV, and OSV API/dumps
- [ ] Task 5: Implement `vulnerability_local` and `rule_local` store persistence during merge (D19)
- [ ] Task 6: Add CLI command / background scheduler job for feed sync and write comprehensive tests

### Phase 1.3: SQL Query Builder with Keyset Signed Cursors
- [ ] Task 7: Build `internal/query/sqlbuilder` compiling `grammar.Query` into parameterized SQL with Phase 1 fields and sort matrix
- [ ] Task 8: Implement HMAC-signed keyset cursor pagination (`(sort_value, id)`) in SQL
- [ ] Task 9: Connect `sqlbuilder` to `store.PostgresStore` and replace in-memory query filtering in `internal/query/api.go`
- [ ] Task 10: Tests for SQL query builder, sorting matrix, and cursor pagination

### Phase 1.4: Ingest Benchmark & Validation
- [ ] Task 11: Implement Ingest Benchmark test (100k findings, rescan dedupe, close, reactivate, out-of-order, concurrent)
- [ ] Task 12: Run complete test suite and verify cross-tenant leak test

---

## Risks and Mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| Connected cluster touched by accident | High | Enforce `--operator=off` and unit/container testing; do not execute `kubectl` or cluster commands |
| SQL injection in dynamic query builder | High | Use positional parameters (`$1, $2, ...`) exclusively for all user-supplied values |
| Keyset pagination boundary edge cases with nulls or ties | Med | Combine sort column with unique `id` tie-breaker in SQL comparison |
| Memory exhaustion during large feed downloads | Med | Stream parser (`json.Decoder`, `csv.Reader`) with bounded batch inserts |

