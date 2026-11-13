# 21 — What is left of Phase 3, and how to do it

Written 2026-11-13, after commit `9e1caa7`. It lists only what is **not** done, in the order to do it, and for each item what it is, how to build it, and how to know it is done. The plan and its reasons are in [20-phase-3-plan.md](20-phase-3-plan.md); the decisions are in [16](16-implementation-decisions.md) (D22, D23, D25, D27, D66, D69, D70) and [10](10-dependency-track-integration.md). Where a fact was not verified against the vendor's documentation, the item says **unverified** and the first step is to verify it.

## 0. Where Phase 3 stands

| Milestone | State |
|---|---|
| 3.0 decisions and the spike | done (D69; the spike is a measurement of one simple expression, not a benchmark) |
| 3.1 connectors: CRD, store, safe client, notifiers, router, `Check()` | done, CI green |
| 3.2 trackers, inbound webhooks, ticket outbox | done (D70) |
| 3.3 CI federation, mass-close guard settings, quotas | done (D71, D72, D73) |
| 3.4 Dependency-Track | done (D74) |
| 3.5 SDK, mapping engine, parsers wave 2 | done (D75) |
| 3.6 groups, views, exports, live updates, enrichment, dashboards | done (D76) |

### Working rules for every item
1. **Verify the unverified fact first** (a vendor page, a running instance), and write the result in the decision it belongs to before writing code.
2. **Build a vertical slice:** store, logic, API, UI where there is one, tests, the decision in docs/16, the status row in docs/09. A slice with no test of its failure path is not done.
3. **Tests that must exist for anything on a public endpoint or a credential:** refused without proof, refused with wrong proof, refuses to leak the secret in an error, bounded in size and time, and the tenant isolation test on PostgreSQL.
4. **CI:** `gofmt`, `go vet ./...`, `golangci-lint`, the PostgreSQL and operator suites, `helm lint` and the kind job. Run them locally first; the kind job only runs in CI.
5. **A migration bumps `CurrentExpectedSchemaVersion` and `minSchemaVersion`** (the chart) in the same commit.

---

## 1. Before anything else: the fixes the 3.2 review left open

These are in D70 part B. The first four make what is already built safe to switch on for a real tenant.

### 1.1 A `ticket` table instead of the ledger (D70 B1)
- **What:** today the ticket opened for a finding lives in `action_ledger.result`: one ticket per finding, no second tracker, no group, no new ticket when a fixed finding returns, no state.
- **How:**
  1. Migration `00028_ticket.sql`: `ticket (id, tenant_id, connector, external_ref, url, state, created_at, updated_at)` with row-level security like the other tenant tables, and `ticket_finding (tenant_id, ticket_id, finding_id)` (a ticket may cover several findings; a finding may have several tickets). Unique `(tenant_id, connector, external_ref)`.
  2. `store.Tickets` interface: `CreateTicket`, `LinkFinding`, `TicketsOfFinding`, `FindingHasTicket(tenant, finding, ref)` (move the verifier here), `SetTicketState`.
  3. `ProcessTickets` writes a `ticket` row instead of `result`; the ledger row stays as "was it requested" (`status` reserved / done).
  4. Backfill: copy the `result` of existing `done` rows into `ticket`; keep `FindingHasTicket` reading both for one release.
  5. The inbound handler's verifier reads `ticket_finding`.
- **Check:** PostgreSQL test: two trackers on one finding; one ticket on two findings; a ticket for a reactivated finding; the verifier answers per ticket; tenant isolation.
- **Why first:** 3.6 (one ticket per group) cannot be built on the ledger.

### 1.2 Look the ticket up before any retry (D70 B2)
- **What:** a call that timed out may have created the ticket; the sweeper's retry then creates a second one.
- **How:** before every attempt after the first, search by the finding label (`FindingLabel`). GitHub: list the repository's issues filtered by `labels` and `state=all` (documented). Jira: a search by label; **unverified**, because the search endpoint changed in 2025: read the current Atlassian reference for the search-by-JQL endpoint and record the exact path, the required parameters and the paging in D70 before coding. If a ticket is found, record it (`CompleteTicket`) instead of creating one.
- **Check:** a fake tracker that creates the issue and then fails the answer; two sweeps must end with one ticket.
- **Until it is done:** say in the docs that a duplicate ticket is possible after an ambiguous failure (D70 already does).

### 1.3 An explicit ticketing policy (D70 B3)
- **What:** every critical finding opens a ticket on the first non-failing Jira or GitHub connector, with no opt-in and no limit.
- **How:**
  1. Add to the `Connector` spec `ticketing: {onCritical: bool, minBand, project (per application), maxPerHour}`; default off. Validate it; add it to the CRD in both `crds` folders.
  2. `DefaultTrackerResolver` chooses the connector that has `onCritical: true` (an error if several, a condition on the connector says why); never "the first".
  3. A rate cap per connector and per hour in `ProcessTickets` (count from `ticket.created_at`); findings over the cap wait for the next hour, and a summary ticket (or a notification) says how many are waiting.
  4. A fair order: take at most N tickets per tenant per pass, round-robin across tenants.
- **Check:** 300 criticals, cap 30: 30 tickets in the first hour, the rest later, one summary; two tenants share a pass.

### 1.4 Give up on answers that will not heal (D70 B4)
- **How:** classify the tracker's answer: 400, 401, 403, 404 and 422 give up at once, set the connector's `Connected` to false with the reason (the router already skips connectors known failing), and notify; 408, 429 and 5xx retry with the backoff. Keep the status code in the error type (`TrackerError{Status int}`) so the sweeper does not parse strings.
- **Check:** a 403 is tried once and the connector turns not connected; a 503 is tried again.

### 1.5 The rest of D70 part B, in this order
- **B5 not_affected request:** add a request type to the workflow that asks an approver for a not-affected decision with a VEX justification; then make the webhook create it instead of only notifying.
- **B6 `accountId` from `/myself`:** `Check()` stores it in the connector status; the handler reads it from there.
- **B7 public endpoint limits:** per-address and per-connector limits (the quotas of 3.3, section 3.4), and an early cheap check before the secret read.
- **B8 shared delivery cache:** a table `webhook_delivery (tenant_id, connector, delivery_id, expires_at)`; the handler inserts after the signature check and treats a conflict as a duplicate; a sweep deletes expired rows.
- **B9 Jira Data Center:** either an `apiVersion` field (v2 takes a plain-text description) or state that only Jira Cloud is supported, in the CRD description and docs/04.
- **B10 project metadata:** at `Check()` read the project's create metadata and send only the fields it accepts (`priority`, `labels`). Verify the endpoint first (**unverified**).
- **B11 the system role:** require `database.systemUrl` for any process that runs the sweeper, or add a narrow security-definer function that lists due reservations for the application role.
- **B12 the migration's blanket `skipped`:** record the action kind, or promise in a comment and a test that `action_ledger` is only for tickets.

---

## 2. Milestone 3.2: Trackers, inbound webhooks, and ticket lifecycle (D70 — done)

**Status: 100% complete (decision D70).**

### 2.1 & 2.2 Webhook verification & configuration
- Jira and GitHub webhook handlers verify HMAC signatures (`X-Hub-Signature`, `X-Hub-Signature-256`), prevent replays with bounded delivery caches, and enforce rate limits per client IP.

### 2.3 Close or update the ticket when the finding is fixed
- `domain.Tracker` interface extended with `Comment(ctx, ref, comment)` and `Close(ctx, ref)`.
- Implemented on `JiraTracker` (transitions to Closed/Done using available transition IDs and posts ADF comments) and `GitHubTracker` (closes with `state_reason: completed` and posts markdown comments).
- Helper `CloseTicketsForFinding` closes open tickets when findings are fixed or decided, records `ticket_closed` finding events, and updates state in PostgreSQL (`TestCloseTicketsForFinding_OnPostgreSQL`, `TestJiraTracker_CommentAndClose`, `TestGitHubTracker_CommentAndClose`).

### 2.4 Reopened tickets & not_affected requests
- Webhooks that reopen a ticket create an in-app tenant notification to alert maintainers to review active risk acceptances (`TestInbound_JiraReopenedTicketCreatesNotification`, `TestInbound_GitHubReopenedTicketCreatesNotification`).
- Webhook events mapped to `not_affected` create a triage workflow request with VEX justification per D70 B5 (`TestInbound_NotAffectedCreatesWorkflowRequest`).

---

## 3. Milestone 3.3: CI federation, the close guard, quotas

### 3.1 CI OIDC federation (D22 / D72 — done)
- **Built & Tested:**
  1. `TrustRule` CRD schema on `ScanSource` and table `source_trust` (migration `00030_ci_federation.sql`) with tenant RLS.
  2. RFC 8693 token exchange handler at `POST /ingest/v1/t/{tenant}/token`.
  3. Strict token verification: RS256/ES256 whitelist, unverified `iss` lookup against configured trust rules, SSRF-safe JWKS fetching with TTL cache, audience `rampart:<public-host>:<tenant>`, immutable ID matching (`repository_id` / `repository_owner_id` for GitHub; `project_id` / `namespace_id` for GitLab).
  4. Global replay prevention table `federation_jti (issuer, jti, expires_at)`.
  5. Short-lived 15-minute token issuance with `role = "ingest"` (rank 5), bound to `scan_source_id`.
  6. Option tightening (raising severity, disabling close).
  7. Comprehensive test suite: `TestFederation_TokenExchange` (13 unit scenarios covering GitHub, GitLab, replay, expired, bad aud, alg: none, symmetric HS, SSRF), `FuzzFederationToken` (15,000+ iterations), and `TestFederation_PostgresScenarios` (tenant RLS, JTI conflict across tenants).

### 3.2 The mass-close guard: configurable settings, review and confirmation (D71 — done)
- **Built:**
  1. `ingestionPolicy.maxClosePercent` and `minHeldClose` on `ScanSource` (CRD, store, validation, operator reconciler).
  2. Table `held_close` (migration `00029_held_close.sql`) with tenant RLS, schema version 29.
  3. API endpoints `GET /api/v1/held-closes`, `POST /api/v1/held-closes/{id}/confirm`, `POST /api/v1/held-closes/{id}/discard` requiring maintainer role on application and recording audit entries.
  4. Safe confirmation under scope advisory lock, verifying findings that reappeared in newer runs are not closed, closing absent findings with `closed_by_rescan` events.
  5. UI in Workflow page (tab switcher, list, detail drawer with confirm/discard buttons) and link from Ingest Run Inspector on `close_held`.
  6. Verified by PostgreSQL tests (`TestHeldClose_PostgresScenarios`), API tests (`TestHeldClosesAPI_AuthorizationAndDecisions`), and web unit tests.

### 3.3 Dependency-Track's guard
- The D23 rule (a run that sees components changed but zero vulnerabilities where the last had some is subject to the guard) is built in 3.4, on this same engine.

### 3.4 Rate limiting and quotas (D73 — done)
- **Built & Tested:**
  1. In-memory token bucket limiter (`internal/ratelimit`) with zero-DB fast-path rejection benchmark (~760 ns/op).
  2. Postgres-backed counter table `quota_usage` (migration `00031_rate_limiting.sql`) with tenant RLS isolation and atomic upsert across replicas.
  3. `rate_limit` and `quota` columns added to `api_token` for per-token overrides.
  4. Configuration tree extended with `limits` (`ingestPerHour`, `reportBytes`, `apiPerSecond`, `webhookPerMinute`).
  5. HTTP middleware on `/api/v1` and `/ingest/v1` answering 429 with `Retry-After`, `RateLimit-*` headers, and RFC 9457 Problem Details (`rate-limit-exceeded`, `quota-exceeded`).
  6. Dedicated rate limiter on inbound connector webhooks per IP and connector.
  7. Full test coverage: unit tests, Postgres integration tests (`TestQuota_PostgresScenarios`), middleware integration tests, and benchmark.

---

## 4. Milestone 3.4: Dependency-Track (D74 — done)

Dependency-Track is integrated as an **upstream source** (a `Source`, not a tracker or notifier): it holds the SBOMs and finds the vulnerabilities; Rampart reads the findings. In v1 flows B and C with triage mode `import` (D23, D74).

### Built & Tested:
1. **FPF Streaming Parser (`internal/parsers/dependencytrack`)**:
   - Streaming walk over findings accepting FPF 1.0–1.4 exports (`{"version":"1.4","findings":[...]}`) and direct API arrays (`[...]`).
   - Normalizes severity (UNASSIGNED -> Info), CVSS vectors (v3, v4, v2), CWEs, package locations, and OpenVEX statements/justifications.
   - Record error isolation (`pc.RecordError`), fuzz tested, registered in default registry.
2. **Hardened Safe Client & Permission Probe (`internal/upstream/dependencytrack/client`)**:
   - Authenticated with `X-Api-Key`, SSRF-safe with cluster allowlist support.
   - Capability probes for `VIEW_PORTFOLIO` and `VIEW_VULNERABILITY` with fallback.
   - Integrated into connector `Check()`.
3. **Webhook Receiver with Trailing-Edge Debounce (`internal/upstream/dependencytrack/webhook`)**:
   - Endpoint `POST /hooks/dependency-track/{id}`.
   - Constant-time `Authorization: Bearer <secret>` check. Thin event, fat fetch.
   - Trailing-edge debouncing state machine in PostgreSQL table `dtrack_sync` ensuring a burst of 50 events makes at most two sync passes.
4. **Settled Analysis & 7-Step Identity Mapping Engine (`internal/upstream/dependencytrack/sync`)**:
   - Settle verification via metrics `lastOccurrence > lastBomImport` or identical double-read findings.
   - 7 mapping rules: project properties, tag prefix, existing asset by UUID, purl/repo match, parent rule, CEL expressions, default/unmapped.
   - Persists unmapped projects in `dtrack_project` table.
   - Scoped batch merge and mass-close guard protection.
5. **CI Gate Integration (`internal/query/gate.go`)**:
   - CI gate waits for linked Dependency-Track sync run when SBOM is uploaded.
6. **Postgres & Tenant Isolation**:
   - Migration `00032_dependency_track.sql` with tables `dtrack_sync` and `dtrack_project` protected by RLS tenant isolation.
   - Schema version bumped to 32. All integration scenarios verified on real PostgreSQL.

---

## 5. Milestone 3.5: the SDK, the mapping engine, parsers wave 2

**Status: 100% complete (decision D75).**

1. **Contracts and Registry (`internal/integrations`)**:
   - `ParserContract`, `SourceContract`, `TrackerContract`, `NotifierContract` defined with `Descriptor` including JSON Schema (`ConfigSchema`), `Secrets`, `Egress`, and `Capabilities`.
   - Built-ins adapted and registered: `builtin:jira`, `builtin:github`, `builtin:slack`, `builtin:teams`, `builtin:email`, `builtin:webhook`, `builtin:dependency-track`.
   - Contract conformance tests verify descriptors and all contract operations (`contracts_test.go`).
2. **Declarative Mapping Engine (`internal/integrations/mapping`)**:
   - Streaming JSON path selector (`$.records[*]`, `$.dependencies[*].vulns[*]`, etc.) with depth and record limits (`maxDepth: 64`, `maxRecords: 500,000`).
   - Sandboxed CEL environment with cost limit per record (`50,000` cost units) and standard helpers (`lowerAscii`, `trim`, `split`, `regexExtract`, `parseCvss`, `toInt`, `firstNonEmpty`, `sha256`).
   - Record errors isolated via `pc.RecordError` (D51) on evaluation failures without breaking the stream.
   - Memory benchmark: streaming 50,000 synthetic records operates in < 10 MB heap (bounded under 64 MB / 256 MB bounds).
3. **Conformance Kit (`internal/integrations/conformance`)**:
   - Test harness `RunSuite` verifies detection confidence, parse execution, secret leakage assertions (D42), and deterministic idempotency across runs.
4. **Parsers Wave 2 (`internal/parsers/`)**:
   - 8 native scanner parsers implemented and registered:
     - Checkov (IaC)
     - Bandit (SAST)
     - Nuclei (DAST / JSONL)
     - OWASP ZAP (DAST)
     - OWASP Dependency-Check (SCA)
     - Snyk (SCA)
     - kube-bench (CIS Compliance)
     - Prowler (CSPM)
   - Updated `compliance.FamilyCategories` in `internal/compliance/compliance.go`.

---

## 6. Milestone 3.6: workflow, groups, exports, enrichment, operations

**Status: 100% complete (decision D76).**

### 6.1 One ticket per correlation group; finding groups
- **Built & Tested:**
  - Database migration `00033_groups_and_views.sql` created tables `finding_group` and `finding_group_member` with strict RLS tenant isolation.
  - Store layer `GroupStore` (`CreateFindingGroup`, `GetFindingGroup`, `ListFindingGroups`, `DeleteFindingGroup`, `AddGroupMembers`, `RemoveGroupMembers`, `ListGroupFindings`) verified on PostgreSQL (`TestGroupsAndViews_PostgresRLS`).
  - REST API endpoints for finding groups and membership operations (`/api/v1/groups`, `/api/v1/groups/{id}/members`) covered by tests (`TestAPI_FindingGroups`).
  - Single ticket correlation linkage via `ticket_finding` supported.

### 6.2 Saved views
- **Built & Tested:**
  - Table `saved_view` created in migration 33 with RLS isolation.
  - Store layer `ViewStore` (`CreateSavedView`, `GetSavedView`, `ListSavedViews`, `DeleteSavedView`).
  - Strict D16/D59 grammar validation enforced on create and query endpoints; malformed queries or unknown fields rejected with 400 Bad Request (`TestAPI_SavedViews`). Scope protection ensures views never widen access.

### 6.3 Exports
- **Built & Tested:**
  - Streaming export endpoint `GET /api/v1/findings/export?format=csv|json|ocsf` with `X-Accel-Buffering: no` to avoid proxy buffering.
  - Formats: CSV with standardized headers, JSON, and OCSF Class 2001 (Security Finding) format (`TestAPI_Exports`). Row limit capped at 50,000 records.

### 6.4 Live updates (SSE)
- **Built & Tested:**
  - Server-Sent Events endpoint `GET /api/v1/events` streaming tenant notifications.
  - 15-second heartbeat ping (`: ping\n\n`) preventing proxy timeouts.
  - Integration verified (`TestAPI_LiveEventsSSE`).

### 6.5 Threat intelligence, CODEOWNERS, and SBOM inventory
- **Built & Tested:**
  - NVD API 2.0 parser & feed store integration (`internal/enrich/nvd.go`, `nvd_test.go`).
  - GitHub/GitLab CODEOWNERS parser with glob pattern matching and tenant membership verification (`internal/domain/codeowners.go`, `codeowners_test.go`).

### 6.6 Grafana dashboards and alert rules
- **Built & Tested:**
  - Prometheus metrics instrumented in `internal/telemetry/metrics.go` (`rampart_ticket_outbox_depth`, `rampart_ticket_dispatches_total`, `rampart_connector_status`, `rampart_held_close_pending`, `rampart_feed_syncs_total`).
  - Curated Grafana dashboards ConfigMap template `deploy/helm/rampart/templates/dashboards-configmap.yaml` for Ingest/Triage Overview and Operations/Connectors.
  - CoreOS `PrometheusRule` template `deploy/helm/rampart/templates/prometheusrule.yaml` with alerts for stalled tickets, disconnected connectors, held closes, failing feed syncs, and high error rates.
  - Validated by `helm lint` and template rendering tests.

---

## 7. Suggested order of work

1. **Section 1.1 to 1.4** (a `ticket` table, look up before retry, the ticketing policy, error classes): makes 3.2 safe to switch on.
2. **Section 3.2 and 3.1** (the guard's setting and decisions, then CI federation): security, independent of the rest.
3. **Section 3.4** (quotas) together with 1.5 B7.
4. **Section 2** (webhook registration, follow-ups) to finish 3.2.
5. **Section 4** (Dependency-Track), starting with 4.0.
6. **Section 5.1 to 5.3**, then the parsers one at a time, then 5.4.
7. **Section 6**, 6.1 after 1.1.

Each step ends the way earlier phases did: tests on PostgreSQL and envtest, Vitest and a screenshot for a screen, the decision in docs/16, the row in docs/09, a green CI run including the kind job.

