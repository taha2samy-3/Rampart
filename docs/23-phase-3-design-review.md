# 23 — Phase 3 design review: decisions to change, and connectors as plugins

Status: proposal, written 2026-11-16. Nothing here is normative. Each item that is accepted becomes a D-section in [16](16-implementation-decisions.md) and a row in [09](09-roadmap.md); an item that is rejected says why here.

The review answers three questions:
1. Which Phase 3 design decisions should change (sections 1 and 2)?
2. Can the Dependency-Track integration be built from [10](10-dependency-track-integration.md), D23 and D74 as they are written (section 3)?
3. Does the code let a new connector be installed and run as a plugin, whatever it is, and if not, what design would (sections 5 and 6)?

## 0. How this review was done, and what each judgement rests on

**What was read.**
- **Documents:** every file in `docs/`: 00 to 22, the six ADRs, and research 01 to 04. Docs 06, 08, 14 and 18 and research 01, 02 and 04 were searched for Phase 3 topics rather than read line by line, because they contain none.
- **Code (section 5 only):**
  - `internal/integrations` (registry, built-in adapters, default registry)
  - `internal/domain/connector.go`
  - `internal/connectors` (router, notifiers, tracker resolver, tickets, inbound handler, checker)
  - `internal/upstream/dependencytrack` (client, sync, settle, mapping, webhook)
  - `internal/ingest/processor.go`
  - `internal/query/api.go` and `dtrack.go`
  - `internal/targets/runner.go`
  - `deploy/crds/connector.yaml` and `scansource.yaml`
  - `web/src/routes/integrations/ConnectorCatalogueDialog.tsx`, which is uncommitted work in progress.

  Sections 1 to 3 rest on the documents alone.

**What was not done.** No code was changed. No build, test or cluster command was run. Statements about runtime behaviour come from reading the code and could be confirmed with a test.

**What each judgement rests on, in this order:**
1. **The project's own normative documents.** [16](16-implementation-decisions.md) wins over older documents (its own rule). [19](19-integration-sdk.md) is the design for integrations and plugins. [10](10-dependency-track-integration.md) is the design for Dependency-Track. The ADRs record accepted architecture. Code that contradicts these is a finding. So is a document that contradicts a normative decision.
2. **The vendor's primary source.** Dependency-Track was checked against the Java sources of the `4.14.6` tag, because doc 10 targets 4.x and docs/20 names 4.14.6 as the latest 4.x tag. Vendor documentation pages are used where no source code is available.
3. **Standards and established guidance:** OWASP cheat sheets, RFCs, IETF drafts (marked as drafts), the OCSF schema, OpenID Connect.
4. **How comparable products do it**, used as support, not as authority: DefectDojo, Brinqa, and HashiCorp's plugin system.

**Priorities.**
- **P1:** a security hole, or a wrong result in production.
- **P2:** a contradiction with a normative decision or with another document, so two people would build two different things.
- **P3:** wording and names.

## 1. Connectors (D69, D70, D73, docs/22 part 3)

### C1 (P1) The SSRF allowlist must belong to tenants, not to the platform
- **Status: done (D77, 2026-11-16).** Built as below, with tenant ids (not slugs) and connector types; several rules per install are not built yet.
- **Now** (D69): a platform administrator allows CIDRs and host patterns (`*.svc`, `*.internal`). The allowlist applies to every tenant, and internal HTTP may be switched on for those hosts.
- **Problem**: on a shared install every tenant's connector inherits the exception. Suppose `*.svc.cluster.local` is allowed for an in-cluster Dependency-Track. Then any tenant admin can point a webhook connector at `kubernetes.default.svc`, the bundled object store, or any internal admin endpoint. The always-blocked list (metadata, loopback, link-local) does not cover cluster service addresses, which are ordinary private ranges.
- **Change**:
  - Each allowlist entry names the tenants it applies to (`tenants: [...]`, or `"*"` written explicitly) and the integrations it serves (`integrations: [builtin:dependency-track]`).
  - Hosts are exact `host:port`. A wildcard is allowed only under a domain the platform admin controls.
  - The default is empty.
  - The connector's status names the entry that let it through.
- **Basis**: OWASP SSRF Prevention Cheat Sheet (allow-list per use case, deny the internal network for user-supplied URLs).

### C2 (P1) Inbound webhooks go back to `/hooks/{type}/{opaque id}` on the gateway
- **Status: done for Jira and GitHub (D78, 2026-11-16).** Dependency-Track's hook is part of the K5 slice.
- **Now** (D70, D73 §4; code: `internal/query/api.go:219`): `POST /api/v1/t/{tenant}/connectors/{name}/webhook`.
- **Problem**: docs 04, 11 and 15 put public callbacks under `/hooks` on `ingest-gateway`. Doc 04 has `status.webhookURL: …/hooks/jira/0193…`, doc 11 has the hooks table, and doc 15 has the route split. The `/api/v1` path causes three problems:
  - In distributed mode the Ingress sends it to `query-api`.
  - It puts unauthenticated routes inside the prefix whose rule is "session or API token".
  - The URL carries a tenant id and a guessable connector name.

  Dependency-Track is documented the right way (`/hooks/dependency-track/{scanSourceId}`).
- **Change**: `POST /hooks/{integration}/{connectorId}`, where the id is the connector row's UUID. The tenant is read from that row, never from the path. Keep the D70 order (size, signature, duplicates, payload) and D73's early limiter. Correct doc 11's hooks table too: its Dependency-Track row still puts the secret in the path. Section 6 makes this route generic for every integration.
- **Basis**: docs 04, 11 and 15; D27 (`ingest-gateway` serves the write path and its callbacks).

### C3 (P1) Rate limits must hold across replicas and must know the real client address
- **Now** (D73): in-memory token buckets per process. Unauthenticated callers are keyed by client IP; webhooks by `(ip, connector)`.
- **Problems**:
  1. With N replicas the effective limit is N times the configured one. Doc 07 §4 planned Valkey for this, with in-process buckets only in monolithic mode.
  2. Nothing says where the client IP comes from. Behind an ingress it is the ingress's address, so every caller shares one bucket, unless `X-Forwarded-For` is read. If that header is accepted from anyone, it can be forged.
  3. D70 B7 asked for a per-address **and** a per-connector limit. Keying on `(ip, connector)` lets a flood from many addresses through.
- **Change**:
  - State the mode. Monolithic: in-process. Simple-scalable and distributed: Valkey when configured, else PostgreSQL for the coarse limits. Say plainly that an in-memory bucket is per replica.
  - Add `server.trustedProxies` (CIDRs). Forwarded headers are read only from those peers: RFC 7239 `Forwarded`, or the rightmost `X-Forwarded-For` entry that is not a trusted proxy.
  - Add a per-connector cap that does not depend on the address.
- **Basis**: doc 07 §4; doc 15 (Valkey for rate limits); RFC 7239.

### C4 (P1) A token's limit may only tighten the tenant's
- **Status: done for the token rule and the table of limits (D79, 2026-11-16).** `Tenant.spec.quotas` and `ScanSource.maxReportBytes` are recorded there as not built; federated tokens are counted on the tenant counter.
- **Now** (D73): `api_token.rate_limit` and `api_token.quota` override the global defaults.
- **Problem**: whoever can create a token can raise their own tenant above the platform's limit. The limits also live in five places, with no rule for which one wins:

  | Where | Value |
  |---|---|
  | `Tenant.spec.quotas` (doc 04) | `maxIngestsPerHour: 500`, `maxReportBytes: 1Gi` |
  | `ScanSource.ingestionPolicy.maxReportBytes` | 512 MiB |
  | `ingest.maxReportBytes` (D6) | 512 MiB |
  | `limits.reportBytes` (D73) | 50 MiB |
  | direct upload (01 A2, doc 11) | 32 MB |

- **Change**: the effective limit is the smallest of the platform default, `Tenant.spec.quotas`, the `ScanSource` and the token. Federated tokens live 15 minutes, so ingest quotas count per scan source and per tenant, never per token. Write the table of limits once (in a D-section) and point every document at it.
- **Basis**: D22's rule "clients may tighten, never loosen", applied to limits.

### C5 (P1) Decide who may create a connector before building the catalogue dialog
- **Now**: doc 20 §9.3 item 8 left this open ("decide whether the UI or API may create connectors … and write it down"), and no D-section decided it. docs/22 part 3 plans a setup dialog that takes URLs and credentials. The dialog in the working tree has three problems (section 5, K7):
  - it reports a successful connection without calling the server;
  - it marks the new connector `Connected=True` in the browser only;
  - it generates YAML the CRD does not accept.
- **Problem**: today a connector is a resource, and only the operator reads Secrets and writes `secret_material` (D1). A UI path means `query-api` writes encrypted secrets. No decision covers that path:
  - which role may do it;
  - what is audited;
  - write-only fields and rotation;
  - the conflict with a resource of the same name (`NameTakenByUI`, D21, not built);
  - validation shared with the operator (D3: one library).
- **Change (proposal)**: allow it, as doc 13 §4 already describes ("objects created in the UI offer Export as YAML"):
  - The tenant `owner` role (doc 07) creates, edits and deletes connectors. Every change is audited, never with secret values.
  - `POST /api/v1/connectors` validates with the same function the operator uses: the integration's config schema (section 6). The row is `managed_by = ui`.
  - Secret fields are write-only. A secret is sent once and encrypted with the tenant's data key into `secret_material`. It is never returned; the form shows only "set" or "not set".
  - A resource with the same name gets `Ready=False` with reason `NameTakenByUI`.
  - "Test connection" calls the server, which runs the integration's `Check` (doc 19 §3: side-effect free, at most 10 seconds) and returns its real result.
  - The form is rendered from `GET /api/v1/integrations` (doc 11), never hand-written per type.
  - Adding Dependency-Track creates both the `Connector` and the `ScanSource` (docs 04 and 10 §8).
- **Basis**: D1, D3, D21; doc 07 role table; doc 13 §4; doc 19 §3 and §8.

### C6 (P2) One contract per kind
- **Now**: the documents name two tracker interfaces: `domain.Tracker` (`Comment`, `Close`; docs/21 §2.3) and `integrations.TrackerContract` (`Check`, `Create`, `Update`, `Get`; D75, doc 19 §3). The code has a third shape for notifiers (K2).
- **Problem**: doc 19 §8 says built-ins implement the same contracts as everything else. With parallel interfaces, the sweeper's close and comment live outside the SDK. A declarative or plugin tracker can then open a ticket but never close it, and `issuedraft.v1.json` cannot say "close".
- **Change**: one interface per kind in `internal/integrations`. Add a desired state (`open | resolved`) and a comment to `IssueDraft`, or add `Comment` and `Close` to the contract, the schema and the declarative tracker. Remove the other interfaces.
- **Basis**: doc 19 §3 and §8.

### C7 (P2) Write how D70 part B was resolved into docs/16
- **Now**: D70 part B (twelve items) still reads "known to be wrong … needs redesign", and part C still reads "not built". docs/21 §0 and commit `10484a9` say both are done.
- **Problem**: the normative document does not say what was chosen:
  - the `ticketing` fields and defaults;
  - which connector wins when several opt in;
  - the hourly cap and the summary ticket;
  - fairness across tenants;
  - Jira Data Center (B9);
  - the create-metadata endpoint (B10);
  - the system-role choice (B11);
  - the ledger rule (B12);
  - the shared delivery table (B8).
- **Change**: a D-section (or a D70 part D) with each outcome and its source. Mark docs/21 sections 1 and 7 as history.
- **Basis**: the working rule of this project: every decision, and its reason, lives in docs/16.

### C8 (P2) Finding groups and "one ticket per group"
- **Now** (D76): manual groups, with no application; "a group can be tracked by a single outbound ticket in `ticket_finding`".
- **Problems**:
  - Docs 12 and 03 give a group an `application_id`, a `group_by` and a key. Doc 07 gives groups to the `maintainer` of a scope, and D48 checks decisions per application. A group without an application has no rule for who may create it, add another application's findings to it, or open a ticket for it.
  - "One ticket per correlation group" (D24, roadmap 3.6) is not designed.
  - `POST /groups/{id}/ticket` (doc 11) does not exist, and docs/22's "one-click dispatch" names no endpoint and no connector.
- **Change**:
  - Groups keep `application_id`. It may be null only for a tenant-wide group, which needs `admin`.
  - Adding a finding needs `triager` on that finding's application.
  - The sweeper groups due reservations by `correlation_key` and opens one ticket, linked to every member.
  - `POST /groups/{id}/ticket {connector}` needs `maintainer` on every application in the group.
- **Basis**: docs 03, 07, 11, 12; D24, D48.

### C9 (P3) Outbound webhook signature
- **Now**: doc 04 uses `X-Rampart-Signature-256`, doc 11 uses `X-Rampart-Signature: sha256=<hmac>`. Either way the HMAC covers the body only.
- **Change**: one header set, with a delivery id and a timestamp inside the signed string, so a receiver can refuse a replay.
- **Basis**: the Standard Webhooks specification (`webhook-id`, `webhook-timestamp`, `webhook-signature`). Slack signs its own requests with a timestamp in the same way (docs/20 §4).

### C10 (P3) Names that differ between documents
- **Connector type**: `dependencyTrack` (04, 10), `dependencytrack` (D69), `dependency-track` (D75 registry, family), `dtrack` (D74 gate). D17 says resources use camelCase and rows use snake_case. The scanner family is a third name, and the integration id (section 6) a fourth; say which is which.
- **`direction`**: three values in D69 and doc 04, two in docs/20 §9.3.
- **`sonarqube`** is still listed in D69 and in `domain.ConnectorType`, although docs/20 §9.3 item 1 removed unbuilt types.
- **Deep links**: `/t/<tenant>/applications/<appName>` (D69) against `/applications/<appID>` (docs/20 §9.7).
- **E-mail body cap**: 16 KiB (D69) against 64 KiB (docs/20 §9.6).
- **Problem type**: `rate-limited` (D17) against `rate-limit-exceeded` (D73).
- **RateLimit headers** (D73, doc 11): `RateLimit-Limit`, `-Remaining` and `-Reset` come from drafts up to -06. From draft-07 (2023) to draft-11 (May 2026) the draft defines `RateLimit-Policy` and `RateLimit`. It is still a draft, so name the version sent.

## 2. Other Phase 3 decisions

### H1 (P1) Confirming a held close must run the close step of D13
- **Now** (D71 §4): for each held finding, check whether a newer run of the same scope saw it again; otherwise move the open absent findings to `fixed`.
- **Problems**:
  - D13 keeps a finding open while **another source** still reports it. The confirm checks only the same scope.
  - D13's step 1 (the scope's occurrences become `present = false`) is not mentioned.
  - Nothing supersedes a hold, so D76's alert "held close pending > 1 h" fires for ever.
- **Change**:
  - On confirm: if a run of the same scope completed after the held run, mark the hold `superseded` and change nothing. Otherwise run D13's close step for that scope with the held run's id.
  - A newer completed run supersedes any pending hold of its scope.
  - Reconsider `completed_with_errors` for a held run (D22): it is a guard, not an error.
- **Basis**: D13 (rules and SQL), D18, D22.

### H2 (P1) Federation: the upload context comes from the token
- **Status (2026-11-16):** the binding is done (D80). Item 1 done as a guard that keeps ingest tokens off every query route except the gate (D81); item 2 was already built (D81); the presigned path now applies the token's options (D81). Item 3 (optional trust-rule conditions) is not built.
- **Missing** in D72: a rule that a federated upload's `repository`, `branch`/`ref` and `commit` **are** the token's, and that a different value in the request is refused. The ref is the client's to state (D30). Without this rule, a feature-branch run can upload with `branch=main` and close `main`'s findings.
- **Also**:
  1. Check ingest as a scope, not as rank 5 below `viewer`: any check `role >= ingest` admits every viewer.
  2. Rate-limit refetching the key set on an unknown `kid`, per issuer.
  3. Allow optional trust-rule conditions on `ref`, `ref_protected` and `environment`.
- **Basis**: D22, D30; OpenID Connect Core §10.1.1; the `jwks-rsa` library's `jwksRequestsPerMinute` option as an example of the limit; GitHub's OIDC reference (define conditions beyond the repository).

### E1 (P1) Exports
- **OCSF class**: D76 writes class 2001 (Security Finding). ADR 0003, research/03 §8 and 01 G4 chose 2007 (Application Security Posture Finding), and 2001 is deprecated in favour of 2002, 2003 and 2004. Use 2002 for `sca` and `container` findings and 2007 for code findings, or 2007 for everything. Check the class against the OCSF version targeted, and write that version in `metadata.version`.
- **CSV**: defuse cells that start with `=`, `+`, `-`, `@`, a tab or a CR, as D46 does for the audit export.
- **Size**: docs 02 §4, 11 and 13 say a long export answers `202` with an operation and a signed link. D76 streams through the API and stops at 50,000 rows without telling the client. Return `X-Next-Cursor` or a problem response when the stream stops, and use the operation path for anything larger.
- **Missing**: the SBOM export (01 G4).
- **Basis**: ADR 0003, research/03; OCSF schema; OWASP CSV Injection; D46.

### S1 (P2) Live updates
- **Now**: D76 serves `GET /api/v1/events`. Docs 11 and 13 specify `GET /api/v1/stream?topics=`, filtered by scope, coalesced, and falling back to polling.
- **Missing**:
  - one path name;
  - fan-out to every `query-api` replica (`LISTEN/NOTIFY` needs `database.directUrl` (D4) and does not work through PgBouncer);
  - scope filtering;
  - a cap on streams per session;
  - `Last-Event-ID`;
  - the server write timeout that would cut a long-lived stream.
- **Basis**: docs 11 §Reporting, 13 §3; D4; D48.

### M1 (P2) Status of 3.4, 3.5 and 3.6
docs/21 marks all three milestones 100 % done. Against doc 19 §13, doc 09 and the code (section 5), the following are missing:
- **3.4:** the Dependency-Track sync and webhook are not wired into the running server (K5).
- **3.5:**
  - `IntegrationPackage`;
  - declarative trackers and notifiers;
  - wave 2 as mappings (the mapping engine has no caller outside its tests);
  - GitLab report schemas and Generic JSON;
  - the conformance checks of doc 19 §9;
  - real built-in tracker, notifier and source adapters (K1).
- **3.6:**
  - the SBOM export and inventory views;
  - for CODEOWNERS: the source of the file, how `@user` and `@org/team` become members, and GitLab sections;
  - the NVD API key and mirror.

Correct the status in docs/21 and docs/09.

### R1 (P3) Tables that grow with nothing to clean them
`federation_jti`, `quota_usage`, the webhook delivery table (D70 B8), decided `held_close` rows and `dtrack_sync` have no owner for deleting old rows. D53's list should name them.

### X1 (P3) Documents not updated
- Doc 12's delta table stops at migration 21. D74 and D70 B1 depart from doc 12's `upstream_project` and `ticket_link` without saying so.
- Doc 10 has two sections numbered 8. Doc 11 still shows the Dependency-Track secret in the path.
- Doc 07 §2 still maps CI federation by names; D22 uses immutable ids.
- D71 to D76 have no `Sources:` line.
- docs/22:
  - Part 4 drops PostgreSQL, envtest, kind and Playwright, and the D-section and the 09 row (D61, docs/21 rules).
  - Part 1 uses `/api/v1/dtrack/...` instead of doc 11's `/sources/{id}/unmapped` and `/sources/{id}/map`.

## 3. Dependency-Track: can it be built from the documents as written?

**Short answer: yes for the overall shape, not yet for four details.** The following parts of the design are sound:
- the division of work;
- the two resources: `Connector` for the endpoint and key, `ScanSource` of type `apiPull` for filters, mapping, webhook and triage;
- the v1 flows: B (webhook as a hint, "thin event, fat fetch") and C (pull);
- the trailing debounce;
- the seven mapping rules;
- the reimport rules of doc 10 §5;
- the permission table.

They match the market. DefectDojo receives FPF exports that DT pushes on a schedule. Connectors such as Brinqa's pull projects, components and vulnerabilities over the REST API with an `X-Api-Key`. The four details below (DT1 to DT4) would make a faithful build wrong. They were checked against the Java sources of the `4.14.6` tag on 2026-11-16.

### DT1 (P1) "Settled" is read from the wrong field, and BOM_PROCESSED comes before the analysis
**Found in the sources:**
- `BomUploadProcessingTask` queues the vulnerability-analysis event, then sends `BOM_PROCESSED`, and dispatches the analysis only afterwards. A sync started by `BOM_PROCESSED` reads the project before its new components are analysed.
- `NotificationGroup` has no analysis-complete group, which confirms doc 10. It does have `NEW_VULNERABILITIES_SUMMARY` and `NEW_POLICY_VIOLATIONS_SUMMARY`, but those are scheduled digests.
- The analysis event carries the BOM's token (`setChainIdentifier(ctx.token)`). The processing token therefore covers the analysis, but only an upload Rampart makes itself (flow A) has that token.
- `VulnerabilityAnalysisTask.analyzeProject` runs the analyzers synchronously and then sets **`Project.lastVulnerabilityAnalysis`**. It does so for every analysis level, except a project with no components or an analyzer that throws. The field is in the project's JSON (`VIEW_PORTFOLIO`).
- The same task dispatches the metrics update only for periodic analysis. So `ProjectMetrics.lastOccurrence`, the signal D23, D74 and the code use, does not move when a BOM's analysis ends.

**Change** (replaces the settle rule of D23 and D74 §5):
- A project is settled when `lastVulnerabilityAnalysis >= lastBomImport`, read from `GET /api/v1/project/{uuid}`. A project with no components is settled.
- If a project is not settled, retry with back-off up to a bound (for example 30 minutes). After the bound, sync anyway, mark the run `analysis_unsettled`, and keep the mass-close guard.
- Edge case: an analysis that started before the latest import can finish after it and look settled. The next event, the debounce and the schedule correct this.
- Drop `lastOccurrence` and the "two identical reads" rule: two reads taken before the analysis starts are also identical.
- The 30-minute schedule and the daily full reconcile of doc 10 Flow C are part of v1, because DT sends nothing when an analysis ends.

### DT2 (P1) The finding endpoint is not paged
**Found:** `GET /api/v1/finding/project/{uuid}`:
- reads every finding of the project (`qm.getFindings(project, suppressed)`);
- ignores `pageNumber` and `pageSize`;
- sets `X-Total-Count` to the size of that list;
- filters by `source` in memory;
- needs `VIEW_VULNERABILITY`.

**Problem:** D69 and docs/20 §5 say the client "loops until returning fewer items than `pageSize`". On this endpoint, that loop never ends or reads everything again.

**Change:**
- Page only on `/api/v1/project`.
- Read the finding list once, streamed, with a byte cap that **fails** the run when exceeded (not one that cuts the list; see K6).
- Check the record count against `X-Total-Count`.

### DT3 (P1) One asset key
The documents and the code give three different keys:

| Source | Key |
|---|---|
| D10 (normative) | `dtrack://<connector>/<project name>`, with the version as `asset_version` |
| Doc 10 §3 | `dtrack://<connector>/<project-uuid>` |
| D74, and the code (`sync/syncer.go:115`) | `dtrack://<sourceID>/<projectUUID>` |

- Keying by scan source: two scan sources on one DT make two findings for one DT finding.
- Keying by UUID: every DT project version has its own UUID, so each release becomes a new asset, and D10's tracks and closing stop working.

**Change:** follow D10. `versions: latest` syncs the version with `isLatest` (exists from DT 4.12); `versions: all` keeps each version as a track.

### DT4 (P1) The gate cannot wait for DT in v1 unless the link is defined
D23's `linked_run` exists only with flow A (after v1.0). In v1 the pipeline uploads to DT itself (D39). D74 §6 does not say what links a build to a sync run.

**Change: pick one and write it down.**
- **(a)** The pipeline sets the DT project version to the commit, or a project property such as `rampart.commit`. The gate matches a settled sync run of that project whose `lastBomImport` is after the build started.
- **(b)** In v1 the gate does not wait for DT and says so in its reasons.

### DT5 (P2) An imported DT decision is a request unless the source trusts it
Doc 10 §6 and D23 make an imported `not_affected` or `risk_accepted` a pending upstream decision, unless `triageSync.trustUpstreamDecisions: true`. D74 does not say whether imported decisions decide. Write it, with the default `false`; D27 already refuses the same for tickets.

### DT6 (P2) The unmapped-projects API and tables are generic
Use doc 11's `GET /sources/{id}/unmapped` and `POST /sources/{id}/map`, which serve any `Source` and name the DT instance. The code mounts `/api/v1/dtrack/unmapped` and `/api/v1/dtrack/projects/{uuid}/map` (`internal/query/api.go:195-196`). Record any departure from doc 12's `upstream_project`.

### DT7 Verified now, and what is still to test
**Closed by the 4.14.6 sources:**
- `/api/v1/team/self` answers `TeamSelfResponse {uuid, name, permissions}`.
- `isLatest` exists from 4.12.
- `properties` and `tags` are in the default fetch group.
- There is no analysis-complete notification.

**Still to test against a running DT** (testcontainers, doc 10 §10):
- that `lastVulnerabilityAnalysis` moves after an upload, read with a read-only key;
- the field names of `BOM_PROCESSED`;
- whether `/api/v1/project` paging starts at 0 or 1;
- DT 5.x.

**For a builder:** follow doc 10 for the shape, D10 for the asset key, this section for the settle rule and the finding read, and section 6 for where the code goes. The code that exists today does not run in the server (K5), so building it means wiring it as well as fixing it.

## 4. Order of work

1. **Security:** C1, C2, C4, C5, H2. C5 must come before the catalogue dialog is finished.
2. **Wrong results:** DT1 to DT4, H1, and K6.
3. **Truthful status:** C7 and M1.
4. **The plugin design (section 6), in its own order**, because it changes where C2, C5, C6 and DT6 land.
5. C3, C8, E1, S1, DT5.
6. The P3 items.

## 5. Code review: connectors and Dependency-Track, against "a connector can be installed and run as a plugin"

**The goal, as the user stated it:** when a new tool appears, it can be installed and run as a connector without changing the core, whatever kind of tool it is. Doc 19 already designs exactly this: four tiers, one set of contracts, a registry, forms from `ConfigSchema`, `IntegrationPackage`, and gRPC and WebAssembly plugins. **The code does not follow doc 19 yet.** Today every connector is compiled into the core, behind type switches in seven files. The findings, with the evidence for each:

### K1 (P1) The built-in tracker, notifier and source adapters in the registry are placeholders
`internal/integrations/builtin_adapters.go`:
- `JiraTrackerAdapter.Create` returns a fixed key `RAMPART-101` and the URL `https://jira.example.com/browse/…` (lines 57-70).
- `GitHubTrackerAdapter.Create` returns issue `42` (lines 133-141).
- Every `GenericNotifierAdapter.Send` sends nothing (lines 285-290).
- `DependencyTrackSourceAdapter.Discover` and `Pull` yield a made-up project and a made-up `CVE-2026-9999` (lines 334-352).

`DefaultRegistry()` registers them, but nothing outside `contracts_test.go` calls `GetTracker`, `GetNotifier` or `GetSource`. The real connectors in `internal/connectors` do not go through the registry. D75's "all built-in connectors are adapted to the contracts" therefore does not hold. The contract tests pass against the placeholders, so they prove nothing about the real connectors.

The descriptors also disagree with the resource they claim to describe:

| Descriptor | Says | The CRD and the domain model say |
|---|---|---|
| Jira | `project` | `defaultProject` |
| Slack | `channel` | `defaultChannel` and `tokenSecretRef` |
| Teams | "incoming webhook URL", egress `*.webhook.office.com` | a Workflows URL (D69) |
| E-mail, webhook, Dependency-Track | egress `*` | — |

A form generated from these schemas would build connectors the server refuses.

**Basis**: doc 19 §8 ("Tier 3 is not a separate world … implement the interfaces in §3 and register in `internal/integrations/registry`"); D75.

### K2 (P2) Three interfaces where doc 19 has one per kind
- **Trackers:** `domain.Tracker` (`internal/domain/connector.go:15-22`: `CreateIssue`, `FindIssueByLabel`, `Comment`, `Close`, `Check`), used by the ticket sweeper; and `integrations.TrackerContract` (`registry.go:102-108`), used only by tests.
- **Notifiers:** `connectors.Notifier` (`notifiers.go:48`: `Send` only), used by the router; and `integrations.NotifierContract`.
- **Sources:** the DT syncer (`upstream/dependencytrack/sync`) implements no `SourceContract`.

**Basis**: doc 19 §3; C6.

### K3 (P1) The connector model is a closed list of types
- `ConnectorSpec` (`internal/domain/connector.go`) has one typed block per type (`jira`, `github`, `slack`, `teams`, `email`, `webhook`, `dependencyTrack`).
- The CRD fixes the list as an `enum` (`deploy/crds/connector.yaml:40-47`).
- Adding a type means editing the domain model (52 references to the per-type names), the router (31), the checker (15), the operator reconciler (10), the tracker resolver (9), the inbound handler (9), the ticket code (1), the CRD in two folders, and the UI. That is a release of the core for every new tool.
- There is no `plugin` type, no generic `config` block, and no `IntegrationPackage`. Doc 04 and doc 19 §7 both promise `Connector.spec.type: plugin` with a `config` block validated against the package's `configSchema`.

**Basis**: doc 19 §1 ("every new tool needed a change to the core repository and a release; that caps the catalogue") and §7; doc 04 `IntegrationPackage`.

### K4 (P1) Notifications are sent inside the ingest run, and failures are dropped
- `internal/ingest/processor.go:362` calls `RouteIngestRunFindings` synchronously. The router sends to every connector and waits for all of them (`router.go:88-129`). A slow chat service therefore holds the ingest worker.
- A failed send is logged and lost: there is no retry and no record.
- docs/20 §9.6 item 7 recorded this as "tracked for 3.2", and it is still the case.
- When the findings cannot be loaded, the processor makes up stand-in findings with new random ids (`processor.go:350-359`). Their deep links point at findings that do not exist.

**Change**: one River job per (connector, message), inserted in the transaction that decides it (ADR 0002's outbox, D25's per-run event), with the same retry and give-up rules as the ticket sweeper (D70 A6).

**Basis**: ADR 0002; D25; D70 A6; docs/20 §9.6.

### K5 (P1) The Dependency-Track sync and webhook do not run in the server
- No package outside `internal/upstream/dependencytrack` imports `sync` or `webhook`. Only the connector checker uses the client.
- No route serves `/hooks/dependency-track/{id}`.
- Nothing calls `SyncPortfolio`.
- No schedule exists.
- The `ScanSource` CRD (`deploy/crds/scansource.yaml`) has no `connector`, `schedule` or `dependencyTrack` block, so the doc 10 §8 configuration (project filters, mapping rules, webhook, triage sync) cannot be expressed.
- `MappingConfig` (`sync/mapping.go:22`) is filled only by tests.
- What runs today: the FPF parser (an uploaded export), the connector check, and the two `/api/v1/dtrack` endpoints over a table that nothing fills.

**Basis**: doc 10 §8 and §9; D74 ("Milestone 3.4 implements the production integration").

### K6 (P1) The Dependency-Track code that exists repeats DT1 to DT3, and cuts large answers silently
- **Settle** (`sync/settle.go:36-44`): uses `ProjectMetrics.LastOccurrence` and then double reads, with a default bound of 10 seconds. That is DT1.
- **Asset key** (`sync/syncer.go:115`): `dtrack://<sourceID>/<projectUUID>`. That is DT3.
- **Response cap** (`client/client.go:44`): every response is read with `io.ReadAll(io.LimitReader(resp.Body, 10 MiB))`. A project whose finding list is larger is cut at 10 MiB **with no error**. The rest of the list never arrives, and depending on how the parser handles the broken end, findings may be closed as absent.
- **Memory:** `GetFindings` returns the whole body as bytes, and the settle check reads it at least twice and compares the bytes, so D74's "streaming" claim does not hold on this path.
- **Concurrency:** syncs start as bare goroutines with `context.Background()` (`webhook/webhook.go:180-183`; `sync/syncer.go:109, 223, 269`). They are not River jobs on the `dtrack-sync` queue (doc 10 §9, ADR 0002), so they are lost on restart, unbounded in number, outside the per-tenant fairness of D25, and never cancelled.

**Change**:
- Read the stream with a cap that fails the run (D35 refuses oversize feeds rather than cutting them; do the same here).
- Run syncs as River jobs.
- Apply DT1 and DT3.

**Basis**: doc 10 §5 ("the run closes nothing if any page of the pull failed") and §9; D25; D35; ADR 0002.

### K7 (P2) The catalogue dialog in the working tree promises what the server never did
`web/src/routes/integrations/ConnectorCatalogueDialog.tsx` (uncommitted):
- The catalogue is a fixed list in the component (line 15), not `GET /api/v1/integrations`.
- "Test connection" waits 700 ms and prints "Connection verified: Remote endpoint returned HTTP 200 OK with valid credentials" without calling anything (lines 112-118).
- Save adds the connector to the page with `Connected=True` and never calls the server (lines 143-166).
- The generated YAML fails against the CRD:
  - `enabled` and `url` are not fields for Slack, GitHub or e-mail;
  - GitHub gets `repository` instead of `owner` and `repo`;
  - Slack gets `channel` instead of `defaultChannel` and `tokenSecretRef`;
  - every type gets `credentialsSecretRef`;
  - `namespace: rampart-system` is not a tenant namespace (D20).

A screen that says "connected" when nothing was checked is worse than no screen. Section 6 and C5 give the server side this dialog needs.

**Basis**: doc 13 §4 (forms from the config schema); doc 19 §8; D20; D41's rule that a setting the system does not apply must say so, not appear applied.

### K8 (P3) What is already right and should be kept
- **Safe outbound client:** one client for every connector call, with SSRF checks at dial time (`connectors/client.go`, response size limited at line 220). This belongs in the core, under every plugin.
- **Secret handling:** secrets read from `secret_material` per call, under per-connector key names.
- **Ticket outbox and sweeper:** D70 A6, B1 to B4.
- **Routing filters and digests:** D25, D69.
- **The FPF parser.**
- **The DT client's permission probe and SSRF allowlist use.**
- **The mapping engine:** streaming selector and CEL with a cost limit, although it has no production caller.

These are the parts the plugin design in section 6 wraps, not replaces.

## 6. Proposed design: every connector is an integration, and every integration can be a plugin

This is doc 19 made concrete for the code that exists. It changes no decision of doc 19; it says where each existing piece goes.

### 6.1 The rule
**The core never switches on a connector type.** It knows four kinds: parser, source, tracker and notifier. It calls their contracts and owns everything around them: scheduling, retries, rate limits, secrets, tenancy, SSRF, audit, approval. An integration only translates.

**Test of the rule:** a search for `switch conn.Type` or `ConnectorTypeJira` outside the built-in integration packages finds nothing.

### 6.2 One contract per kind (doc 19 §3)
- `TrackerContract` gains what the sweeper uses today: `FindByLabel` (D70 B2), and close and comment (C6). `domain.Tracker` is deleted.
- `NotifierContract.Send` takes the canonical `Message`. `connectors.Notifier` is deleted.
- `SourceContract` (`Check`, `Discover`, `Pull`) has the optional `EventReceiver` and `TriageWriter`.
- `IssueEventReceiver` is the optional interface for two-way trackers.
- Every contract call receives a `Config` (the connector's validated configuration) and a `Secrets` accessor that can read only that connector's declared secrets.

### 6.3 Built-ins register their real implementations
- `internal/connectors/jira`, `/github`, `/slack`, `/teams`, `/email` and `/webhook`, and `internal/upstream/dependencytrack`, each implement their contract and register in `DefaultRegistry()`.
- The placeholders of K1 are deleted.
- Each descriptor's `ConfigSchema` is generated from the same Go config struct the code decodes into, so the form, the validation and the code cannot drift apart (K1's table shows what happens when they are written twice).
- The conformance kit (doc 19 §9) runs against the real implementations, with recorded HTTP exchanges.

### 6.4 The connector resource becomes open
```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata: {name: chat-sec, namespace: team-payments}
spec:
  integration: builtin:slack          # any registered id: builtin:jira, acme-redmine, google-chat …
  config:                             # validated against the integration's ConfigSchema
    defaultChannel: "#appsec"
  secrets:                            # names come from the descriptor's Secrets list
    token: {secretRef: {name: slack-bot, key: token}}
  routing: {minSeverity: high}        # core features stay typed
  ticketing: {onCritical: true}       # accepted only when the integration is a tracker
status:
  conditions: [{type: Ready, status: "True"}, {type: Connected, status: "True", reason: CheckPassed}]
  integration: {version: 1.0.0, supportLevel: builtin}
```
- `spec.config` is `x-kubernetes-preserve-unknown-fields` in the CRD. The operator and `POST /api/v1/connectors` validate it with the same function against the integration's `ConfigSchema` (JSON Schema 2020-12).
- An unknown `integration` is `Ready=False` with reason `UnknownIntegration`. An invalid config is `InvalidSpec` with the schema error (as D41 and D55 do).
- `direction` is derived from the integration's kinds and capabilities instead of being typed by hand.
- The typed blocks (`jira:`, `slack:` …) stay accepted while the version is `v1alpha1` and are converted to `integration` and `config` on reconcile. Doc 04 §7 allows additive changes only in `v1alpha1`, and existing resources must keep working.
- Secret sync in the operator reads the secret names from the descriptor instead of from per-type code.

### 6.5 The core services call contracts only
| Today | After |
|---|---|
| The router builds notifiers in a type switch and sends inline from the ingest worker (K4) | The router selects connectors by routing rules, inserts one River job per (connector, message); the job calls `NotifierContract.Send` with retries and give-up |
| The tracker resolver switches on Jira and GitHub | The sweeper picks the connector with `ticketing.onCritical` and calls `TrackerContract` |
| The inbound handler parses Jira and GitHub payloads by type | `POST /hooks/{integration}/{connectorId}` on the gateway. The core verifies the signature with the scheme the descriptor declares (`hmac-sha256` with a named header, `bearer`, `basic`), then hands the body to the integration's `IssueEventReceiver` or `EventReceiver`. What comes back is a status (trackers) or a list of project references (sources), never a decision (D27) |
| The checker switches on type | The checker calls `Check` (side-effect free, at most 10 seconds) and writes `Connected` |
| The DT syncer runs as goroutines and is not wired (K5, K6) | A generic source runner in the `sync` target: River jobs per (source, project) on a `source-sync` queue, the schedule from the `ScanSource`, the trailing debounce of D23 generalized to `upstream_project` and `upstream_cursor` (doc 12), and the results through the normal merge and close step with the mass-close guard. Dependency-Track is its first `SourceContract` |

### 6.6 How a new tool is installed, by tier (doc 19 §2)
| Tier | What is installed | Who | Runs where | Phase in doc 19 |
|---|---|---|---|---|
| 1 declarative | an `IntegrationPackage` YAML: a parser mapping, or a tracker or notifier defined as HTTP requests | tenant admin (data only) | inside `parser`, `notify` or `sync`, through the mapping and declarative engines | 3 |
| 2 plugin | a signed OCI package with a WebAssembly parser, or a gRPC service (`rampart.plugin.v1`) for sources, trackers and notifiers, in any language | platform admin | WebAssembly inside `parser`; gRPC as its own Deployment with its own NetworkPolicy; the core sends config and secrets per call over mTLS | 4 (WebAssembly), 5 (gRPC) |
| 3 built-in | Go in the core repository | maintainers | the owning target | — |

- **Why gRPC and not Go's `plugin` package:**
  - Go's `.so` plugins must be built with the same toolchain, the same build tags and the same versions of every shared dependency as the host;
  - they cannot be unloaded;
  - they share the host's memory with no sandbox (the "Warnings" section of the `plugin` package documentation).
  - A separate process speaking gRPC is the pattern HashiCorp's `go-plugin` uses for Terraform providers and Vault plugins: any language, crash isolation, and its own identity.
- **Decision for the user:** doc 19 puts gRPC plugins in Phase 5. "Install whatever tool appears" for sources, trackers and notifiers that YAML cannot describe needs tier 2. Either keep Phase 5, with tier 1 covering most tools from Phase 3 (doc 19 §14 estimates four in five), or bring the gRPC host forward to Phase 4.
- **Security** stays as doc 19 §11 says, with C1 added: an integration's egress is the hosts it declares, intersected with the tenant's allowlist entries.

### 6.7 The UI
- `GET /api/v1/integrations` lists every registered integration of every kind with its descriptor (doc 11). The endpoint `GET /api/v1/parsers` built in commit `3bedfc0` becomes the `kind=parser` filter of it.
- The catalogue and the connector form are rendered from `ConfigSchema` and `Secrets`.
- "Test connection" calls the server's `Check`.
- Saving follows C5.
- A connector managed by a resource is read-only with "View YAML" (doc 13 §4).

### 6.8 Order of work, each step a vertical slice that keeps everything running
1. **Contracts:** one contract per kind (6.2). The real built-ins register; the placeholders go. No behaviour change.
2. **Open resource:** the generic `Connector` (`integration`, `config`, `secrets`) with schema validation, and the conversion of the typed blocks (6.4).
3. **Core services:** notification delivery as River jobs, the sweeper, the checker, and inbound `/hooks/{integration}/{id}` through contracts (6.5, K4, C2). The type switches are deleted.
4. **Sources:** the generic source runner, and Dependency-Track as a `SourceContract` with DT1 to DT3 and K6 fixed and the `ScanSource` configuration of doc 10 §8 in the CRD (6.5, K5).
5. **UI:** `GET /api/v1/integrations`, the schema-driven form, server-side check and write-only secrets (6.7, C5).
6. **Tier 1:** `IntegrationPackage` for declarative notifiers, trackers and parser mappings. This is the first install that needs no release.
7. **Tier 2:** the gRPC plugin host, in the phase the user chooses (6.6).

**Acceptance test for "installable as a plugin":** a new notifier, for example the Google Chat example of doc 19 §6, is applied as an `IntegrationPackage` with no change to Go code, the CRD or the UI. It then appears in the catalogue, its form renders, its `Check` runs, and a test notification arrives at a fake receiver. The same test, with a recorded API, runs for a declarative source.

## Sources

- **Project documents:** docs 00 to 22; ADR 0001 to 0006; research/03 (OCSF, standards).
- **Dependency-Track 4.14.6 sources, read 2026-11-16:**
  - `notification/NotificationGroup.java`
  - `tasks/BomUploadProcessingTask.java`
  - `tasks/VulnerabilityAnalysisTask.java`
  - `model/Project.java`
  - `resources/v1/FindingResource.java`
  - `resources/v1/TeamResource.java`
  - `resources/v1/vo/TeamSelfResponse.java`

  (https://github.com/DependencyTrack/dependency-track/tree/4.14.6)
- **Dependency-Track, DefectDojo integration:** https://docs.dependencytrack.org/integrations/defectdojo/
- **Brinqa, Dependency-Track connector:** https://docs.brinqa.com/docs/connectors/dependency-track
- **OWASP:**
  - Server-Side Request Forgery Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
  - CSV Injection: https://owasp.org/www-community/attacks/CSV_Injection
- **RFCs, drafts and specifications:**
  - RFC 7239, Forwarded HTTP Extension.
  - IETF draft-ietf-httpapi-ratelimit-headers, drafts -07 and -11: https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/
  - Standard Webhooks specification: https://www.standardwebhooks.com/
  - OpenID Connect Core 1.0 §10.1.1: https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
  - OCSF schema, Findings category: https://schema.ocsf.io/
- **Splunk, "Elevating Security: The Growing Importance of OCSF":** says Security Finding (2001) is deprecated in favour of the newer finding classes.
- **GitHub, OpenID Connect reference:** https://docs.github.com/en/actions/reference/security/oidc
- **Go, `plugin` package, "Warnings":** https://pkg.go.dev/plugin
- **HashiCorp, go-plugin (plugins over gRPC as separate processes):** https://github.com/hashicorp/go-plugin
