# Phase 1 Todo List

## Phase 1.1: Object Storage & Background Parse Worker Integration
- [ ] Task 1: Wire Object Storage client into `targets.Runner` and `Gateway` (supports S3 / SeaweedFS and In-Memory)
- [ ] Task 2: Implement and wire the background Parse Worker for both River (Postgres) and in-memory queue
- [ ] Task 3: Comprehensive tests for presigned upload -> PUT -> complete -> parse worker lifecycle

## Checkpoint 1: Ingestion Pipeline End-to-End
- [ ] Presigned upload, object storage, and parse worker tests pass cleanly.

## Phase 1.2: Threat Intelligence & Feed Sync (OSV, KEV, EPSS) & Local Tables
- [ ] Task 4: Implement feed sync service for CISA KEV JSON, FIRST EPSS CSV, and OSV
- [ ] Task 5: Implement `vulnerability_local` and `rule_local` persistence during merge (D19)
- [ ] Task 6: Add CLI command (`rampart feeds sync`) / background scheduler job and tests

## Checkpoint 2: Intelligence & Feeds
- [ ] Feed sync and tenant-local table tests pass cleanly.

## Phase 1.3: SQL Query Builder with Keyset Signed Cursors
- [ ] Task 7: Build `internal/query/sqlbuilder` compiling `grammar.Query` into parameterized SQL with all Phase 1 fields
- [ ] Task 8: Implement HMAC-signed keyset cursor pagination in SQL
- [ ] Task 9: Connect `sqlbuilder` to `store.PostgresStore` and replace in-memory query filtering in `internal/query/api.go`
- [ ] Task 10: Tests for SQL query builder, sorting matrix, and cursor pagination

## Checkpoint 3: Query Engine
- [ ] Query API tests pass without in-memory full-table filtering.

## Phase 1.4: Ingest Benchmark & Final Validation
- [ ] Task 11: Implement Ingest Benchmark test (100k findings, rescan dedupe, close, reactivate, out-of-order, concurrent)
- [ ] Task 12: Run complete test suite and verify cross-tenant leak test

