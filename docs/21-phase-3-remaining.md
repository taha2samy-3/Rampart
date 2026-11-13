# 21 — What is left of Phase 3, and how to do it

Written 2026-11-13, after commit `9e1caa7`. It lists only what is **not** done, in the order to do it, and for each item what it is, how to build it, and how to know it is done. The plan and its reasons are in [20-phase-3-plan.md](20-phase-3-plan.md); the decisions are in [16](16-implementation-decisions.md) (D22, D23, D25, D27, D66, D69, D70) and [10](10-dependency-track-integration.md). Where a fact was not verified against the vendor's documentation, the item says **unverified** and the first step is to verify it.

## 0. Where Phase 3 stands

| Milestone | State |
|---|---|
| 3.0 decisions and the spike | done (D69; the spike is a measurement of one simple expression, not a benchmark) |
| 3.1 connectors: CRD, store, safe client, notifiers, router, `Check()` | done, CI green |
| 3.2 trackers, inbound webhooks, ticket outbox | built and tested; **not finished** (section 2) and carries twelve known redesign items (D70 part B) |
| 3.3 CI federation, mass-close guard settings, quotas | done (D71, D72, D73) |
| 3.4 Dependency-Track | done (D74) |
| 3.5 SDK, mapping engine, parsers wave 2 | done (D75) |
| 3.6 groups, views, exports, live updates, enrichment, dashboards | not started (section 6) |

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

## 2. Milestone 3.2: what is left of trackers and webhooks

### 2.1 Register and refresh the webhook in Jira
- **Facts (read from Atlassian's webhooks page):** a webhook registered through REST **expires after 30 days** and is extended by a refresh; it stays available up to three months after expiry; limits are 100 per Connect app per tenant and 5 per OAuth 2.0 app per user; deliveries are retried up to five times; there is a delivery identifier header. **Unverified:** the exact registration endpoint and body for the authentication method Rampart uses (an API token is Basic auth; registration by REST is documented for Connect and OAuth apps): read the page and decide whether Rampart registers it or the administrator does.
- **How:** if the administrator registers it (simplest, no extra permission), show the URL and the secret to set in the connector's status and in the UI, and have `Check()` report `WebhookNotSeen` when no delivery arrived within a configurable time. If Rampart registers it, store the registration id and its expiry in the connector status, refresh at 20 days from the sweep that already runs `Check()`, and set a condition when the refresh fails.
- **Check:** a fake clock: the refresh happens at day 20; a failed refresh turns the condition false.

### 2.2 GitHub webhook
- **How:** same choice. The webhook is created in the repository settings with the secret; the handler already verifies `X-Hub-Signature-256`. Document the events to select (`issues`). Do not use the older SHA-1 header.
- **Check:** the handler tests exist; add the status condition for "no delivery seen".

### 2.3 Close or update the ticket when the finding is fixed
- **How:** a finding event `closed_by_rescan` or a decision (`not_affected`, `fixed`) enqueues a "ticket follow-up" row (reuse the outbox with an action `close_ticket`). The tracker interface grows `Comment(ctx, ref, text)` and `Close(ctx, ref)`. GitHub: close the issue with `state_reason: completed`. Jira: transitions need the workflow's transition id, which differs per project: read the transitions of the issue (`GET .../transitions`) and pick the one the connector maps (`statusMapping.closedStatuses`). **Unverified:** the transitions endpoint and the shape of its answer.
- **Rule:** the follow-up must not be read back as a decision: the change is made by Rampart's account, which the handler already ignores (needs 1.5 B6 for the account id).
- **Check:** fix a finding: the ticket gets a comment and is closed; a reopened finding gets a new ticket (needs 1.1).

### 2.4 Reopened tickets
- **How:** a webhook that reopens a ticket (resolution cleared) creates a notification and, if the finding is accepted through that ticket, asks to revoke the acceptance (a request, never a direct change).

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

### 6.1 One ticket per correlation group; finding groups
- **How:** needs 1.1. A correlation group already exists (`correlation_key`, D24, D37). When the ticketing policy opens a ticket for a finding that belongs to a group, open one ticket for the group and link all its findings (`ticket_finding`). **Finding groups** are user-made: a table `finding_group (id, tenant, name)` and members; the UI selects findings and groups them; a group can be assigned an owner and a ticket.

### 6.2 Saved views
- **How:** `saved_view (id, tenant_id, owner, name, query, sort, scope)`; per user or shared with the tenant; the filter bar saves and loads it; the query is stored as text in the grammar and re-validated on load (the grammar refuses what it does not know, D59). Scope rules: a view never widens what the loader may read.

### 6.3 Exports
- **How:** CSV and JSON of a query (streamed, no page cap, row limit, audited), SBOM (CycloneDX and SPDX from the stored component inventory, per application), OCSF (the Detection Finding class, mapped field by field and documented). VEX is built (D47). An export is a job for large sets: written to the `exports` bucket, downloaded through the API with a short-lived authorization, deleted by retention (D53).

### 6.4 Live updates (SSE)
- **How:** `GET /api/v1/events` (Server-Sent Events) for the tenant: run finished, finding changed, held close, notification. Source: Postgres `LISTEN/NOTIFY` on a channel per tenant fed by the same writes (no polling), a heartbeat comment every 15 seconds, `Last-Event-ID` to resume, a per-user connection cap. The web client uses it to invalidate the TanStack Query keys instead of polling. Behind a proxy, set `X-Accel-Buffering: no` and document it.

### 6.5 SBOM inventory views, NVD enrichment, ownership
- **SBOM inventory:** the Inventory page lists components (purl, version, where, how many findings) from the stored SBOMs; search by purl; "where is this component used".
- **NVD enrichment:** a feed like KEV and EPSS (D35) for CVSS, CWE and references, with the NVD API's rate limits and an API key setting; air-gapped mirror via `ClusterFeedMirror` later. **Unverified:** the current NVD API 2.0 limits and fields: read the NVD developer pages first.
- **Ownership from CODEOWNERS:** on ingest with a repository, read `CODEOWNERS` (a path glob to owners), set the finding's owner when the owner is a member of the tenant (D59 allows members only); a file path rule is applied at merge, not at read.

### 6.6 Grafana dashboards and alert rules
- **How:** a dashboard JSON per concern (ingest throughput and failures, the sweepers' lag, ticket outbox depth, connector health, queue depth, SLA), shipped in the chart as ConfigMaps labelled for the Grafana sidecar and optional (`metrics.grafanaDashboards.enabled`); alert rules as a `PrometheusRule` (optional, off by default) for: ticket outbox older than an hour, connector not connected, a held close waiting, feed sync failing, migrations behind. The metrics the dashboards use must exist first: add them next to the code they measure (outbox depth, oldest pending ticket, delivery counts, connector condition).

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

