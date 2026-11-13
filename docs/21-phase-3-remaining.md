# 21 — What is left of Phase 3, and how to do it

Written 2026-11-13, after commit `9e1caa7`. It lists only what is **not** done, in the order to do it, and for each item what it is, how to build it, and how to know it is done. The plan and its reasons are in [20-phase-3-plan.md](20-phase-3-plan.md); the decisions are in [16](16-implementation-decisions.md) (D22, D23, D25, D27, D66, D69, D70) and [10](10-dependency-track-integration.md). Where a fact was not verified against the vendor's documentation, the item says **unverified** and the first step is to verify it.

## 0. Where Phase 3 stands

| Milestone | State |
|---|---|
| 3.0 decisions and the spike | done (D69; the spike is a measurement of one simple expression, not a benchmark) |
| 3.1 connectors: CRD, store, safe client, notifiers, router, `Check()` | done, CI green |
| 3.2 trackers, inbound webhooks, ticket outbox | built and tested; **not finished** (section 2) and carries twelve known redesign items (D70 part B) |
| 3.3 CI federation, mass-close guard settings, quotas | CI federation (D72) and mass-close guard (D71) done; quotas remaining (section 3.4) |
| 3.4 Dependency-Track | not started (section 4) |
| 3.5 SDK, mapping engine, parsers wave 2 | not started (section 5) |
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

### 3.4 Rate limiting and quotas
- **What:** limits per token and per tenant; only the login has a limit today.
- **How:**
  1. A small `ratelimit` package: token bucket per key, in memory per process; a Postgres-backed counter for quotas that must hold across replicas (uploads per hour, bytes per day) in a table `quota_usage (tenant_id, key, window_start, used)` updated with `INSERT ... ON CONFLICT DO UPDATE`.
  2. Limits in the configuration (`limits.ingestPerHour`, `limits.reportBytes`, `limits.apiPerSecond`) and per token on `api_token` (`rate_limit`, `quota`).
  3. Middleware on `/api/v1` and `/ingest/v1`, answering **429 with `Retry-After`** and the RFC 9457 problem body; the CLI already understands 429 (retry with backoff).
  4. The public webhook endpoint of 2.x gets its own tighter limit per address and per connector.
- **Check:** a burst is limited and recovers; two replicas share a quota; the limit is per token and per tenant, not global; a limited call does not touch the database (benchmark it).

---

## 4. Milestone 3.4: Dependency-Track

Dependency-Track stays an **upstream source** (a `Source`, not a tracker or notifier): it holds the SBOMs and finds the vulnerabilities; Rampart reads the findings. In v1 only flows B and C, with triage mode `import` (D23). Rampart does not upload SBOMs or poll processing tokens in v1.

### 4.0 First task: a real Dependency-Track 4.x
- **How:** run DT 4.x in a container in CI (or record real answers as fixtures, the version in the file name). Settle, and write into docs/10 section 8: paging on `/api/v1/project` and the finding endpoint (parameters, 1-based or not, `X-Total-Count`, `X-Total-Count-Type`; mirrored specs say 1-based, default page size 100, and DT's own v5 notes say some v4 endpoints ignored paging); the field names of `BOM_PROCESSED`; whether `properties` and `tags` are filled in the single-project answer; whether `/api/v1/team/self` lists the key's permissions; whether `lastOccurrence` moves after analysis. Check 5.x compatibility (5.2.1 exists) and decide whether it needs its own client.
- **Done when:** docs/10 section 8 has no "not verified" left that the client depends on.

### 4.1 The FPF parser
- **How:** `internal/parsers/dependencytrack`: stream the document (D15 style: token walk, no full decode), map `component`, `vulnerability`, `analysis`, `attribution` to a `RawFinding` (category `sca`, canonical id by D11, purl from the component), keep the DT component and vulnerability UUIDs for later. Accept FPF 1.0 to 1.4 (export produces 1.4). Fixtures from the real instance of 4.0; fuzz test; a record it cannot read is a record error (D51).

### 4.2 The client and the permission probe
- **How:** use the safe client with the platform allow-list (a Dependency-Track inside the cluster is a private address over http: the allow-list of D69 is how it is permitted). Auth header `X-Api-Key`. Permissions: `VIEW_PORTFOLIO` (projects, BOM export), `VIEW_VULNERABILITY` (findings, FPF export), `VIEW_POLICY_VIOLATION`; `BOM_UPLOAD` only for forwarding (not v1). The probe: if `/team/self` lists permissions use it; otherwise call a harmless endpoint per permission. A missing permission sets `Connected=False/missingPermissions` and pauses the flows that need it.

### 4.3 The webhook (flow B)
- **Facts:** the publisher cannot send arbitrary headers and does not sign the body; it can send one authentication header (Basic, Bearer or a token header). So the rule is set to send `Authorization: Bearer <secret>`, compared in constant time; the payload is only a hint ("thin event, fat fetch"): read the project uuid and nothing else.
- **How:** `POST /hooks/dependency-track/{id}` (an opaque id per source, not a name); verify; enqueue `DTrackProjectSync(project)` with **trailing-edge debounce**: an event during a running sync sets a dirty flag and causes exactly one more sync (a row `dtrack_sync (project, state, dirty, next_at)` and a River job keyed by project). Return 202. `BOM_PROCESSING_FAILED` and `BOM_VALIDATION_FAILED` mark the linked run failed.
- **Check:** a burst of 50 events makes two syncs; a wrong secret is refused and remembers nothing; the same rules as the other public endpoint (size, limits).

### 4.4 Settled analysis
- **Facts:** there is **no analysis-complete event** in 4.14.6; `BOM_PROCESSED` fires when processing is done, not when analysis is. The processing token needs `BOM_UPLOAD`.
- **How:** after a `BOM_PROCESSED` (or a periodic pull), read the project's findings twice, a back-off apart, and treat the project as settled when both reads are identical; give up after a bound and sync what there is, marking the run so. If 4.0 shows `lastOccurrence` moves after analysis, use it as an extra signal. The mass-close guard (3.2) is the safety net: a run that would drop most findings is held.

### 4.5 Portfolio sync (flow C), mapping and the unmapped screen
- **How:** a job pages the projects; for each, apply the source's mapping rules in order (the seven in docs/10: project property, tag, purl match, name rule, CEL rule, default application, unmapped); upsert the asset (`dtrack_project_uuid` stored); enqueue a project sync when `lastBomImport` or the metrics changed since the cursor. **Unmapped projects** are listed with the reason; a screen under Integrations shows them and lets an administrator map one (a request that writes the mapping, audited). Findings go through the normal merge with reimport-close scoped to the project.
- **Check:** a project that matches no rule is listed and not merged; a mapped one is merged under the right application; a project that vanished is not mass-closed.

### 4.6 The CI gate waits for Dependency-Track
- **How:** the gate (`internal/query/gate.go`) learns a source of type Dependency-Track: when the pipeline's SBOM run is linked to a sync (a `linked_run` recorded when the project is identified), the gate waits for that sync as well as for the SBOM run; the gate's reasons name it.

### 4.7 Triage import and, later, write-back
- v1: import only. An imported upstream decision that needs approval is stored as a pending upstream decision (one per finding), never pushed back (D23). Write-back, SBOM forwarding and the DefectDojo-compatible shim stay after v1.0.

---

## 5. Milestone 3.5: the SDK, the mapping engine, parsers wave 2

### 5.1 The contracts and the registry
- **How:** in `internal/integrations`, define `TrackerContract`, `NotifierContract`, `SourceContract` beside `ParserContract` (docs/19 section 3: `Describe`, `Check`, `Discover`, `Pull`, `PushTriage`, `ParseEvent`, `CreateIssue`, `UpdateIssue`, `GetIssues`, `Send`); register the built-in Jira, GitHub, Slack, Teams, email, webhook and Dependency-Track against them so the router and the sweeper resolve through the registry instead of switch statements. The `Descriptor` carries the config schema (JSON Schema) so the UI can draw the connector form.
- **Check:** a conformance test per contract that every built-in passes.

### 5.2 The mapping engine
- **What:** a declarative parser (`runtime: mapping`): a YAML document that says how to read a report with a streaming path selection and how to build a `RawFinding` with CEL expressions (variables `rec`, `dep`, `doc`, `ctx`).
- **State:** the CEL library is already a dependency (policies, D63). The spike (D69) measured one simple expression over 100,000 small synthetic records at about 1.3 s and a negligible heap; it did **not** measure a full mapping with regular expressions, 500 MiB files or a WebAssembly runtime.
- **How:** (1) a streaming selector (a JSON path with `[]` and `*`, a token walk, one record at a time, depth and record limits `maxDepth: 64`, `maxRecords: 500000`); (2) a CEL environment with a cost limit per expression and the helpers (`lowerAscii`, `trim`, `split`, `regexExtract`, `parseCvss`, `toInt`, `sha256`), compiled once per mapping; (3) a loader and validator for the YAML (unknown keys refused); (4) fingerprint and severity through the same normalisation as the native parsers, so a mapping and a native parser agree on keys; (5) a mapping that changes fingerprints needs a version bump and the old version stays loadable (`finding_key_alias`, D50).
- **Measure before declaring it done:** a real report of 500 MiB through a real mapping with several expressions, memory capped at 256 MiB, recorded in D69's spike section with the limits of the measurement.
- **Check:** a mapping reproduces a native parser's output on the same fixture (the golden test of the conformance kit); a malicious expression hits the cost limit; a record it cannot read is a record error (D51).

### 5.3 The conformance kit
- **How:** `rampart integration test <dir>`: reads `testdata/<tool-version>/` (input, expected canonical output, expected keys), runs a parser or mapping, and checks the golden output, fingerprint stability (the same input twice, and a reordered input), the size and depth limits, and that no secret reaches the output. The built-in parsers run under it in CI.

### 5.4 Connector forms from the config schema
- **How:** the `Descriptor`'s JSON Schema drives a generic form in the UI (text, secret reference, list, enum); the server validates with the same schema. Secrets are references, never values.

### 5.5 Parsers wave 2
- **Order by use and by how well the format is specified:** Checkov (JSON), Bandit (JSON), Nuclei (JSONL), OWASP ZAP (JSON), Dependency-Check (JSON), Snyk (JSON), kube-bench (JSON), Prowler (OCSF JSON), the GitLab report schemas, Generic JSON (through the mapping engine). Already built: SARIF, CycloneDX, SPDX, Syft, OpenVEX, Trivy, Grype, Semgrep, Gitleaks, TruffleHog.
- **For each:** real, sanitised fixtures from a named tool version under `testdata/<tool-version>/`; a golden canonical output; a fingerprint-stability test; a fuzz test; record errors (D51); secrets never stored (D42); a mapping where the format allows, a native parser where it needs state (kube-bench's check groups, Prowler's OCSF nesting). Add the scanner family to `compliance.FamilyCategories` (D52) so Compliance knows what it evidences.

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

