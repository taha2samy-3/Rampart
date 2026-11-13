# 20 — Phase 3 plan: workflow and integrations

Status: plan, written 2026-11-13. It refines the Phase 3 list in [09-roadmap.md](09-roadmap.md) and does not replace it; the normative decisions stay in [16-implementation-decisions.md](16-implementation-decisions.md) (D22, D23, D24, D25, D27, D66). Every external fact below was read from the vendor's own documentation on the date above, with the page named. Where a page could not be read, the item says **not verified** and is a task of the milestone that needs it, not an assumption.

## 1. What Phase 3 is, and what it is not

- **Built-in connectors run in the existing process.** Jira, GitHub Issues, Slack, Teams, email, webhooks and Dependency-Track are Go code inside the one `rampart` binary and image, in the `notify` and `sync` targets (docs/02, docs/15). `-target=all` runs them in the same pod. A `Connector` resource is configuration (type, address, a reference to a Secret); it is not a workload, and nothing new is deployed per connector.
- **gRPC plugins are not in Phase 3.** The `rampart.plugin.v1` service of docs/19 is for third-party plugins that run as their own Deployment. It is Phase 5 (Integration SDK part 3).
- **Why in-process is acceptable.** Egress is restricted by the NetworkPolicy of D49; each connector reads only the Secret it names; responses are size-limited, schema-checked and untrusted; target addresses are checked against private and link-local ranges (SSRF) before any call; and in distributed mode `notify` is its own Deployment, so a fault in a connector cannot stop `query-api`.

## 2. What the first plan got wrong, and the fix

| # | Claim in the first plan | Finding | Fix |
|---|---|---|---|
| 1 | Mapping engine "under 256 MiB for a 500 MiB file" | docs/09 Phase −1 spike 6 (CEL at 100k records, `wazero`) is required **before** Phase 3 and was skipped. The number is a goal, not a measurement | Milestone 3.0 runs the spike and writes the result in docs/16 before any mapping-engine code |
| 2 | Compute and store `correlation_key` for correlation groups | Built (D24, D37). Only "one ticket per group" and user-made **finding groups** are new | 3.6 builds those two |
| 3 | Syft and SPDX are wave-2 parsers | `internal/parsers/syft` and `spdx` exist | Wave 2 lists only what is missing (section 7) |
| 4 | VEX export is new | Built (D47) | Dropped from the exports item; CSV, JSON, SBOM and OCSF remain |
| 5 | Dependency-Track endpoints and permission names stated as fact | docs/10 marked them "(confirm)" | Verified against 4.14.6 and written into docs/10 section 8; section 5 lists what is still open |
| 6 | Avoid Jira loops with an `Updated-By: rampart` or "Origin" header | No such header exists in Jira's documentation | Section 4: compare the actor of the change with our own account, and keep a hash of the last state we pushed (D23's sync record) |
| 7 | Webhook secret in the URL path | The publisher can send one authentication header (Bearer or a token header) but no arbitrary headers and no signature | The secret goes in the `Authorization: Bearer` header the rule sends (section 5, docs/10) |
| 8 | Missing bullets of the roadmap | Rate limiting and per-token quotas, SBOM inventory views, Grafana dashboards and alert rules were not in the plan | Added in 3.6 |
| 9 | `approve-domain` endpoint and `IsTenantAllowed` in the OIDC callback are Phase 3 | They belong to Phase 2 bullet 5 (identity), outside this phase | Tracked there; the callback check is cheap and may be taken with 3.3 |
| 10 | Federation last | D22 is a security control and does not depend on the connectors | Moved to 3.3, before Dependency-Track |

## 3. Milestones

| | Content | Needs |
|---|---|---|
| **3.0** | Spike 6 measured and recorded; the open vendor facts below checked; one decision (D69) for the connector model: contracts, secret handling, SSRF rules, retry and rate-limit behaviour | nothing |
| **3.1** | `Connector` CRD, migration `00026_connector.sql` with row-level security like the other tenant tables, store, reconciler with a periodic `Check()` and the status conditions of docs/04; Slack, Teams and signed-webhook notifiers; routing of the in-app notifications of D45 to connectors; digests above 20 findings per run (D25) | 3.0 |
| **3.2** | Jira and GitHub Issues trackers; the `ticket-on-critical` placeholder (D66) opens a real issue through the `action_ledger` reservation it already makes; inbound webhooks (signed) turn a ticket's resolution into a **request** (D27), never a state | 3.1 |
| **3.3** | CI OIDC federation and token exchange (D22); the mass-close guard; rate limiting and per-token quotas | nothing |
| **3.4** | Dependency-Track 4.x (D23, docs/10; settle-detection task first): FPF parser, client with a permission probe, portfolio and project sync, the unmapped-projects screen, webhook with trailing debounce, triage import, gate linking | 3.0, 3.3 |
| **3.5** | Integration SDK part 1: `Tracker`, `Notifier`, `Source` contracts and registry, the mapping engine, conformance kit, connector forms from config schemas; parsers wave 2 | 3.0 spike |
| **3.6** | One ticket per correlation group, finding groups, saved views, exports (CSV, JSON, SBOM, OCSF), live updates (SSE), SBOM inventory views, NVD enrichment, ownership from CODEOWNERS, Grafana dashboards and alert rules | 3.2 |

Each milestone ends as the earlier phases did: tests on PostgreSQL and envtest, Vitest for screens, a screenshot, a decision in docs/16, and a green CI run.

## 4. Connectors: verified facts and decisions

Sources: Atlassian, Slack, Microsoft and GitHub documentation, read on 2026-11-13.

**Jira Cloud**
- Webhooks registered by an administrator or through REST can carry a `secret`; Jira then sends `X-Hub-Signature` as `method=signature`, an HMAC over the body ([webhooks](https://developer.atlassian.com/cloud/jira/platform/webhooks/)). Connect apps are signed with their `sharedSecret`; OAuth 2.0 apps with a bearer JWT. **Decision:** verify the signature before parsing; refuse an unsigned delivery.
- Payloads carry `webhookEvent`, `timestamp`, `user` (with `accountType`) and, on `jira:issue_updated`, `changelog.items[]` with `field`, `from`, `fromString`, `to`, `toString`. `X-Atlassian-Webhook-Identifier` identifies a delivery, to deduplicate retries.
- **No loop-avoidance flag is documented.** `X-Atlassian-Webhook-Trace` exists for Connect apps. **Decision:** ignore a change whose `user.accountId` is our own, **and** keep per `(finding, ticket)` the hash of what we last pushed (D23); a change that leaves the hash as it was is ours.
- REST-registered webhooks **expire after 30 days** and are extended by a refresh of 30 more; a webhook stays available up to three months after expiry. Limits: 100 per Connect app per tenant, 5 per OAuth 2.0 app per user; 20 concurrent deliveries per tenant and host; five retries. **Decision:** the connector's `Check()` refreshes the registration well before 30 days and says in status when it could not.
- Rate limits: HTTP 429 with `Retry-After` in seconds; quota exhaustion blocks until the next hourly reset; burst limits per endpoint ([rate limiting](https://developer.atlassian.com/cloud/jira/platform/rate-limiting/)). **Decision:** exponential backoff with jitter, `Retry-After` as the minimum, at most four retries, and only for idempotent calls; creating a ticket is made idempotent by the `action_ledger` reservation plus a label that carries the finding id.
- **Verified:** `POST /rest/api/3/issue` requires `description` formatted strictly in **Atlassian Document Format (ADF)** JSON (`type: doc, version: 1, content: [...]`). `priority` is passed as an object (`{name: "High"}`), `labels` as an array of strings (`["label1", "label2"]`), and `customfield_XXXXX` as string, select object, or ADF depending on custom field type. (Alternatively, API v2 `POST /rest/api/2/issue` accepts raw text strings). **Decision:** The tracker formats `description` as standard ADF document nodes (`paragraph` and `text` with marks for links) for Jira API v3, with a helper for clean ADF encoding. To be verified with the first live call or fixture.

**Slack**
- Incoming webhooks are bound to one channel, cannot override channel or icon, cannot delete what they posted and do not return the message `ts`. **Decision:** use `chat.postMessage` (a channel per call, returns `ts`, lets a digest be updated). Limits: 50 blocks per message, 3,000 characters in a section's text, about one message per second per channel ([blocks](https://docs.slack.dev/reference/block-kit/blocks/), [postMessage](https://docs.slack.dev/reference/methods/chat.postMessage)).
- Inbound requests (interactive buttons, if used) are verified with `v0=` + HMAC-SHA256 of `v0:{timestamp}:{raw body}`, compared in constant time, and refused if the timestamp is more than 5 minutes off ([verifying requests](https://docs.slack.dev/authentication/verifying-requests-from-slack)).

**Microsoft Teams**
- Microsoft 365 connectors (legacy incoming webhooks) were permanently retired and blocked by Microsoft in **May 2026** (rollout window 18–22 May 2026); the replacement is a Workflows / Power Automate flow with the trigger "When a Teams webhook request is received" ([Microsoft Docs](https://learn.microsoft.com/en-us/microsoftteams/m365-custom-connectors)). **Decision:** the Teams notifier targets the Workflows webhook only and posts the documented payload (`type: message`, an `attachments` entry of type `application/vnd.microsoft.card.adaptive`). No inbound limit is documented; Microsoft's message-post action is limited to about 28 KB, so a digest is truncated with a link.

**GitHub Issues**
- `POST /repos/{owner}/{repo}/issues`, `title` required; `labels`, `assignees` and `milestone` are silently dropped without push access, so the connector's `Check()` verifies push access and says so. A fine-grained token needs "Issues: write" ([create an issue](https://docs.github.com/en/rest/issues/issues#create-an-issue)).
- Webhooks: `X-Hub-Signature-256` = `sha256=` + hex HMAC-SHA256 of the payload with the secret; `X-GitHub-Delivery` identifies a delivery ([validating deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)). The older `X-Hub-Signature` is SHA-1 and is refused. The `issues` event actions include `closed`, `reopened`, `labeled` and `edited`. Whether the sender of our own change is marked as a bot is **not verified**: compare `sender.login` with the app's own login.

**Common rules (go into D69).** Every outbound call goes through one client that refuses private, loopback and link-local addresses after DNS resolution, limits redirects and response size, and sets a timeout. Secrets are read from `secret_material` at the moment of the call and never logged. An inbound webhook is a public endpoint: signature first, then size limit, then parse. A ticket resolution `Won't Do` or `False Positive` creates a risk-acceptance or not-affected **request** (D27). Every connector resource specifies its `direction` (`outbound | inbound | bidirectional`).

## 5. Dependency-Track: verified facts and what is still open

Read from the Java sources of Dependency-Track **4.14.6** (the latest 4.x tag) on 2026-11-13; the full table is in docs/10 section 8. **Dependency-Track 5.x exists (5.2.1)**: the plan targets 4.x, and 5.x compatibility is checked before 3.4 starts.

- **Corrected in docs/10:** `suppressed` and `source` are real parameters of the finding endpoint; `X-Total-Count` is real; the FPF export produces version 1.4; the non-deprecated token endpoint is `GET /api/v1/event/token/{uuid}`; permission names are `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`, `VIEW_POLICY_VIOLATION`, `BOM_UPLOAD`, `VULNERABILITY_ANALYSIS`; `POST /api/v1/vex` exists.
- **Changes the design (decision in D23's direction, not against it):** the webhook publisher **can send one authentication header** (Basic, Bearer, or a custom token header as configured by the administrator). So the secret does not go in the URL path as docs/10 first said; the rule supports `Authorization: Bearer <secret>` or Basic credentials and compares them in constant time. The payload is still an untrusted hint (thin event, fat fetch).
- **There is no "analysis complete" notification** in 4.14.6 (`PROJECT_VULN_ANALYSIS_COMPLETE` does not exist). The processing token needs `BOM_UPLOAD`, which a read-only pull key lacks. Whether `ProjectMetrics.lastOccurrence` moves after each analysis is **not verified**. Until it is tested against a running Dependency-Track, a project is settled when two spaced reads of its findings are identical, with the mass-close guard (D22) as the safety net. This is the first task of 3.4 and needs a real instance in CI or a recorded fixture of the behaviour.
- **Pagination & events:** Official docs do not firmly confirm whether `pageNumber` starts at 1 or 0 across all 4.x/5.x releases. The client loops until returning fewer items than `pageSize` and checks total count against `X-Total-Count`. `BOM_PROCESSED` event payloads follow `org.dependencytrack.notification.v1` with `notification.group = "BOM_PROCESSED"` and `subject.project.uuid`. **Still open:** whether `/api/v1/team/self` lists the key's permissions (the probe may have to try a harmless call per permission instead); whether `properties` and `tags` are filled in the single-project response.

## 6. CI OIDC federation (3.3): verified facts

Sources: GitHub's [OIDC reference](https://docs.github.com/en/actions/reference/security/oidc), GitLab's [ID token authentication](https://docs.gitlab.com/ci/secrets/id_token_authentication/), RFC 8693, RFC 7519.

- **GitHub** tokens carry `iss` = `https://token.actions.githubusercontent.com`, `aud` (the owner's URL by default; a workflow can request a custom audience), `sub`, `repository`, `repository_id`, `repository_owner`, `repository_owner_id`, `jti`, `ref`, `workflow_ref`, `job_workflow_ref`, `run_id`, and `environment` (only if the job uses one). The discovery document is at `…/.well-known/openid-configuration`; the key set URL is taken from its `jwks_uri` (not stated on the page). The `sha` claim is **not verified** (the page lists `workflow_sha` and `job_workflow_sha`). Token lifetime is not documented as a fixed constant on GitHub's reference page; relying code must read `exp` directly from token claims with clock skew checks, and exchange it immediately at D22's exchange endpoint (`POST /ingest/v1/t/{tenant}/token`) for the 15-minute Rampart token. Replay cache entries for `(issuer, jti)` are retained for 10 minutes.
- GitHub documents an immutable `sub` form with owner and repository ids (`repo:OWNER@OWNER-ID/REPO@REPO-ID:…`), made the default for repositories created after **2026-07-15**, not available on GHES; a custom `sub` template replaces the default entirely; at least one condition must be defined on the relying side or untrusted repositories can obtain tokens. **Decision (D22 stands):** trust rules match `repository_id` and `repository_owner_id`, never names; the audience is `rampart:<public-host>:<tenant>`.
- **GitLab** ID tokens carry `iss`, `aud` (the instance domain by default, configurable in `id_tokens`), `project_id`, `namespace_id`, `project_path`, `namespace_path`, `ref`, `ref_protected` (a string, `"true"` or `"false"`), `jti`, `exp` (the job timeout, or 5 minutes). The issuer is the instance's base URL; for gitlab.com and self-managed alike the **key set is read from the issuer's discovery document**, not from a fixed path (a fixed path was not on the pages read: not verified). A trust rule names the issuer, so a self-managed GitLab is a different trust source from gitlab.com.
- Both carry `jti`. RFC 7519 §4.1.7 allows `jti` to prevent replay but makes it optional and unique **per issuer**: **Decision:** the replay cache is keyed on `(issuer, jti)` and entries live until the token's `exp` plus a clock-skew allowance; a token without `jti` is refused.
- RFC 8693 shape for the exchange: `POST` with `application/x-www-form-urlencoded`, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`, `subject_token_type`, optional `audience`; the response is JSON with `access_token`, `issued_token_type`, `token_type` and `expires_in`. **Decision:** the exchange endpoint of D22 (`POST /ingest/v1/t/{tenant}/token`) takes and returns these names, so a standard client works; the issued token lasts 15 minutes and is bound to the source and the derived context.

## 7. Parsers wave 2 (3.5)

Native or mapping, by the format. Already built and **not** in this wave: SARIF, CycloneDX, SPDX, Syft, OpenVEX, Trivy, Grype, Semgrep, Gitleaks, TruffleHog. To build: Checkov, Nuclei, OWASP ZAP, Bandit, Dependency-Check, kube-bench, Prowler (OCSF), Snyk, GitLab report schemas, Generic JSON. Each parser comes with real, sanitised fixtures under `testdata/<tool-version>/`, a golden canonical output and a fingerprint-stability test, as the ways of working in docs/09 require; each handles a record it cannot read the way D51 does.

## 8. Not in Phase 3

gRPC plugins and the Python and TypeScript SDKs (Phase 5), SAML (Phase 4), Dependency-Track SBOM forwarding and write-back (after v1.0, D23), the DefectDojo-compatible shim (after v1.0), cross-tool merging (after v1.0, D24).

## 9. Review of milestones 3.0 and 3.1: findings and the plan to fix them

Written 2026-11-13 after reading `981729b` and the working tree. Each item has what is wrong, what was found when it was researched, the fix, and how the fix is checked. The order is the order of work; items 1 to 5 are text only.

### 9.1 What the research found (and how sure it is)

| Claim in D69 | Found | Sure? | What to write |
|---|---|---|---|
| GitHub OIDC token "expires strictly in 5 minutes" | GitHub's own page describes `exp` as "the expiry time of the JWT" and states no duration. Secondary sources (Claude platform docs, Gato-X, a Spacelift article) all say about 5 minutes; the request URL stays valid for the whole job, so a fresh token can be requested | Secondary only | "About 5 minutes (not stated by GitHub). The code reads `exp` and never assumes a lifetime; a token past `exp` plus the skew allowance is refused" |
| Dependency-Track `pageNumber` is 1-based | Mirrored OpenAPI documents of running instances say "(1-based)", default 1, and `pageSize` default 100; `X-Total-Count` carries the total. The official v5 breaking-changes page says that **in v4 some paging parameters were ignored on certain endpoints** (it names component and finding endpoints) | Mirrors only; the official OpenAPI of 4.x was not read | "1-based per mirrored specs; the client does not trust paging on the finding endpoint and reads the total from `X-Total-Count`; tested against a running 4.x in 3.4". Newer builds add `X-Total-Count-Type` (`EXACT` or `AT_LEAST`): a count of type `AT_LEAST` is a lower bound |
| Jira `description` must be ADF | In v3 a plain string is rejected ("must be an Atlassian Document"); `description`, `environment` and textarea custom fields are ADF, single-line custom fields take a string (Atlassian community and the JRACLOUD tickets; the v3 intro page confirms ADF is supported) | Secondary; the official create-issue reference was not read in full | "ADF for `description`. The create-issue schema, including whether `priority` and `labels` are accepted, **depends on the project and issue type**: the tracker calls the create-issue metadata endpoint at `Check()` and refuses a configuration whose project does not accept the fields it sends" |
| Teams connectors retired in May 2026 | Microsoft: rollout 18 to 22 May 2026, after which Office 365 connectors "will no longer function"; creation blocked since 15 August 2024; the deadline moved several times (the last update read: 14 April 2026) | Official page ([retirement notice](https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/)) | Keep the claim; add the page and the dates |
| DT webhook "sends `Authorization: Bearer`" | The publisher supports Basic, Bearer or a token header, chosen and filled by the administrator who writes the rule | Source read (4.14.6) | "can send; the rule is set to send `Authorization: Bearer <secret>`" |

### 9.2 Text fixes (docs only)

1. D69 "Verified and recorded": rewrite the five claims as in the table above, each with its source and whether the source is official or secondary.
2. D69 has the heading `### Spike 6 measurement results and limitations` **twice**: remove one.
3. docs/20 section 4: align Teams with the dates above and the Jira item with the create-issue-metadata decision; section 6: GitHub lifetime wording.
4. D69: add the `direction` decision (section 9.3, item 4) and name which connector types are inbound.
5. docs/04 (`Connector`): make the example match the CRD that exists (Slack with a bot token, Teams with a Workflows URL secret, the webhook with a signature secret).

### 9.3 Code fixes, in order

| # | Fix | Check |
|---|---|---|
| 1 | **Types without an implementation.** `gitlab`, `azureBoards`, `serviceNow` and `sonarqube` are in the CRD enum with no config section and no code. Remove them from the enum until built, or answer `Ready=False`, reason `NotSupported`. Prefer removal: a CRD that admits what the server refuses is a trap | envtest: applying one is refused by the API server |
| 2 | **`webhook.headers` is a free map.** Refuse `Host`, `Authorization`, `Cookie`, `Content-Length`, `Transfer-Encoding`, `X-Hub-Signature*` and anything with a CR or LF; refuse values that look like secrets; secrets come only from `secretRef` | unit test with the forbidden list and a header-injection attempt |
| 3 | **Address checks at reconcile time.** Every `url` (Jira, webhook, Dependency-Track, GitHub Enterprise host) must be `https`, resolve to public addresses, and be re-checked after DNS resolution at call time (a name can change between the two). `ssrf.go` exists; the reconciler must call it and set `Ready=False`, reason `UnsafeAddress`, with the address in the message | unit tests for loopback, link-local (169.254.x), private ranges, IPv6 forms, an IP written in decimal or octal, a redirect to a private address, and DNS rebinding with a fake resolver |
| 4 | **`direction`.** Add `spec.direction` (`outbound` or `inbound`), defaulted from the type (Jira, GitHub, Slack, Teams, email, webhook outbound; Dependency-Track and SonarQube inbound) and refused if it contradicts the type. Show it in the API and the UI so the screen groups "sends to" and "pulls from" | domain test; envtest for the default |
| 5 | **Connector finalizer (D49).** Deleting a connector must remove what it registered elsewhere (the Jira webhook) and the secret material, and keep its history | envtest as for the other kinds |
| 6 | **`Check()` and status.** A periodic check writes the `Connected` condition and the time of the last success; Jira's REST-registered webhook is refreshed before 30 days and says in status when it could not be | unit test with a fake clock; a failing refresh turns the condition false |
| 7 | **Tenant isolation test for `connector`.** The table has row-level security but no test that tenant B cannot read or write tenant A's rows through each role | PostgreSQL test like the one for the other tenant tables |
| 8 | **Who writes.** `rampart_app` can only read `connector`; the operator writes as `rampart_system`. Decide whether the UI or API may create connectors (it must then go through the same validation as the operator) or stays resource-only, and write it down | decision in D69 |
| 9 | **Spike test in CI.** `spike_test.go` asserts nothing on time but prints a measurement and runs 1.3 s on every CI run. Move it behind `-short`/a build tag or make it a benchmark; keep the numbers in D69 | CI time unchanged |
| 10 | **The rest of 3.1.** The notifiers exist; what remains is connecting the in-app notifications of D45 to the router, the `Notifier` registration in the registry, and an end-to-end test against a local fake of Slack, Teams and a webhook receiver, including a 429 with `Retry-After`, a response larger than the limit and a redirect | tests with `httptest` servers |

### 9.4 Needs a running Dependency-Track (first task of 3.4)

Run a Dependency-Track 4.x in Docker in CI (or record real responses as fixtures, with the version in the file name) and settle: paging on `/api/v1/project` and on the finding endpoint, `X-Total-Count` and `X-Total-Count-Type`, the field names of `BOM_PROCESSED`, whether `properties` and `tags` are filled by the single-project call, whether `/api/v1/team/self` lists permissions, and whether project metrics `lastOccurrence` moves after analysis. The same run decides whether 5.x needs a separate client.

### 9.5 How the two sessions share the files

One session owns `internal/connectors`, `internal/domain/connector*.go`, `internal/store/connector*.go`, migration `00026`, and the CRD; the other owns `docs/` (D69, docs/20, docs/10, docs/04). A change to a decision goes through the docs session so the two stay in agreement. `internal/auth/handlers.go` has an uncommitted change that belongs to neither and is left alone.

### 9.6 Post-commit e1864fa review: remaining issues and prioritized hardening plan

Written 2026-11-13 after review of commit `e1864fa`. Items are strictly ordered by priority: P1 (functional & architectural blockers) must land before proceeding to 3.2/3.4, P2 (security & error resilience), followed by P3 (workflow scalability & test coverage).

| # | Priority | Issue | Files Affected | Fix & Acceptance Criteria | Status |
|---|---|---|---|---|---|
| 1 | **P1 (Blocker)** | **Relative URLs break Slack & Teams messages** (`invalid_blocks`) | `internal/connectors/router.go`, `notifiers.go` | Route must accept `server.publicUrl` (or base URL) and build absolute links `https://<publicUrl>/t/<tenant>/findings/<id>`. Digest must point to an existing UI view instead of `/applications/<name>/runs`. Unit test asserting all generated button URLs are absolute HTTPS. | **Done** |
| 2 | **P1 (Arch)** | **In-cluster / On-premise services blocked by strict public-only SSRF** | `internal/domain/ssrf.go`, `internal/connectors/client.go`, `docs/16` (D69) | Add platform-level allowlist (operator/server config, not per-tenant): allowed CIDRs (e.g., in-cluster pod/service network) and allowed HTTP schemes for internal services (Dependency-Track on `http://...svc:8080`, on-prem Jira DC/GitLab). Document in D69 before milestone 3.4. | **Done** |
| 3 | **P2 (Security)** | **Opportunistic STARTTLS fallback to plaintext** | `internal/connectors/notifiers.go`, `internal/domain/connector.go` | Add explicit `tlsMode` (`starttls` mandatory by default, `implicit_tls`/`smtps` for port 465, or explicit `none`/`insecure`). Fail if server does not advertise STARTTLS under `starttls` mode. Add transaction deadline context to the entire SMTP session to prevent hanging goroutines. | **Done** |
| 4 | **P2 (Resilience)** | **Fragile URL sanitization & empty secret `%w(<nil>)` error** | `internal/connectors/client.go`, `router.go` | Unwrap errors with `errors.As(err, &urlErr)` and sanitize `urlErr.URL` rather than substring search. When secret key exists in map but value is empty string, return explicit `fmt.Errorf("secret key %q is empty", key)` instead of wrapping `nil`. | **Done** |
| 5 | **P2 (Resilience)** | **Unbounded email body size** | `internal/connectors/notifiers.go` | Enforce maximum body size / rune-truncate finding descriptions in SMTP email bodies (e.g. 64 KiB cap) to prevent memory spikes or SMTP rejection. | **Done** |
| 6 | **P3 (Workflow)** | **Missing routing rules (noise reduction)** | `internal/connectors/router.go`, `domain/connector.go` | Add routing filter criteria (min severity, events, application selectors) so connectors only receive relevant notifications rather than all 20 findings per run. | **Done** |
| 7 | **P3 (Scalability)** | **Inline delivery blocks ingest (needs River job)** | `internal/connectors/router.go`, `internal/ingest/` | Outbound notifications should enqueue into River with persistent retries and backoff so 429 rate-limiting (>60s) or slow destinations don't delay the ingest pipeline. | Tracked for 3.2 |
| 8 | **P3 (Docs)** | **Reconcile-time DNS resolution policy** | `docs/16` (D69), `domain/ssrf.go` | Explicitly document that allowing unresolved DNS during reconcile is safe and intended, because strict SSRF dial checks happen at runtime. | **Done** |
| 9 | **P3 (Testing)** | **Missing test coverage suite** | `internal/connectors/connectors_test.go` | Add unit tests for: (1) Slack relative URL rejection, (2) mandatory STARTTLS refusal, (3) SMTP full session deadline, (4) empty secret values, (5) routing filters, (6) unexpected `url.Error` wrapping. | **Done** |

### 9.7 Post-commit b6d7b40 review: platform SSRF allowlist wiring, dial consistency, and e2e fixes

Written 2026-11-13 after code review of commit `b6d7b40` and `29076ca`:

1. **Platform SSRF allowlist configuration wiring**:
   - Added `ConnectorsConfig` with `SSRFAllowlistConfig` to `internal/config/config.go`, exposing env vars `RAMPART_CONNECTORS_SSRF_ALLOWLIST_CIDRS`, `RAMPART_CONNECTORS_SSRF_ALLOWLIST_HOSTS`, and `RAMPART_CONNECTORS_SSRF_ALLOWLIST_ALLOW_INTERNAL_HTTP`.
   - Wired allowlist through `internal/targets/runner.go` into `internal/operator/manager.go` and `ConnectorReconciler`.
   - Rejects insecure wildcard `*` host definitions during configuration validation.

2. **Reconcile and Dial-Time SSRF consistency**:
   - Fixed inconsistency where host-based allowlists passed during reconcile DNS check but were blocked by IP-only checks in `SafeClient.Control`.
   - `SafeClient.DialContext` resolves DNS and executes `IsBlockedIPWithAllowlistAndHost(ip, host, allowlist)` on all resolved IPs before connecting; dialer `Control` validates the connected socket IP.
   - Host matching permits private cluster IPs for explicitly allowed host patterns (e.g. `*.svc.cluster.local`, `*.internal`).

3. **Non-bypassable sensitive IP and metadata protection**:
   - `IsAlwaysBlockedIP` unconditionally blocks Cloud metadata (`169.254.169.254`, `100.100.100.200`), link-local (`169.254.0.0/16`, `fe80::/10`), loopback (`127.0.0.0/8`, `::1`), multicast, and `0.0.0.0/8`, even if an administrator allowlist or wildcard matches.

4. **Secret storage key harmonization**:
   - Standardized secret storage keys using `domain.ConnectorSecretStorageKey(connectorName, key)` (canonical format `connector:<name>:<key>`, defaulting empty key to `"token"`).
   - Reconciler and router now access the exact same secret key across Slack, Teams, Webhook, and SMTP (with separate `username`/`password` support).

5. **Honest status reporting & deferred webhook URLs**:
   - Connector reconciler records `Connected=Unknown` (reason: `PendingVerification`, message: `Connector registered, connection not yet tested`) and `Ready=True` (`Reconciled`) upon creation, eliminating misleading premature `Connected=True` claims.
   - `WebhookURL` is left empty until milestone 3.2 implements inbound authenticated webhook endpoints per D23.

6. **Absolute deep links and clean fallbacks**:
   - When `publicURL` is omitted, action buttons in Slack and Teams are omitted cleanly rather than generating broken relative links.
   - Digest routes point to real UI routes (`/applications/<appID>`) and findings use `/t/<tenant>/findings/<findingID>`.
   - Routing rules match against event name (`msg.Fields["event"]`) and application name or slug, safely rejecting misspelled or invalid severities.

7. **E2E Kind script assertion update**:
   - Updated `hack/e2e/kind.sh` to assert `count(*) from secret_material = 2` (for both ScanSource and Connector synced secrets).
   - Changed plaintext position assertion to `count(*) where position(...) > 0 == 0`, ensuring multi-row results never break e2e validation.

8. **Connector finalizer secret cleanup by prefix**:
   - Replaced single-key deletion and `SaveSecretMaterial(..., nil)` with `DeleteSecretMaterialPrefix` (`LIKE 'connector:<name>:%' ESCAPE '\'`).
   - Ensures multi-key secrets (e.g. Email `username` and `password`) and altered secret keys leave zero leftover garbage rows in `secret_material`.
   - Propagates deletion errors so the finalizer retries rather than completing with orphaned secret material.
   - Tested under PostgreSQL RLS in `internal/store/postgres_test.go` and in `internal/operator/operator_test.go`.

Sources read for this section: [Microsoft, retirement of Office 365 connectors](https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/); [GitHub, OIDC reference](https://docs.github.com/en/actions/reference/security/oidc) (no lifetime stated); the Dependency-Track [v5 breaking changes](https://dependencytrack.github.io/docs/next/reference/api/v5-breaking-changes/) page and mirrored `openapi.json` documents of running 4.x servers; Atlassian's [REST v3 introduction](https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/) and the community and JRACLOUD tickets on ADF descriptions.

### 9.8 Review of the 3.2 code (trackers, inbound webhooks, ticket automation): fixed, and recorded as needing redesign

Written 2026-11-13. The findings, the fixes and the tests are in docs/16 **D70**; this section is the pointer and the order of work.

- **Fixed before any commit** (they let an unauthenticated caller have a risk accepted): the inbound webhook failed open when no secret was configured; delivery ids were remembered before the signature was checked; the API token was used as the webhook secret; a label typed on someone else's ticket was trusted; a "false positive" created a 90-day acceptance; the acceptance ignored the tenant's maximum; the tracker was called inside the merge transaction and a failed call was never tried again; GitHub issue text from scanners was written as raw markdown.
- **Recorded as needing redesign (D70 part B, twelve items):** the ledger is not a ticket model (one ticket per finding, no groups, no second tracker), an ambiguous failure can still open two tickets, every critical finding opens a ticket on the first tracker with no opt-in or cap, 4xx answers are retried, false positives only notify, `accountId` is typed by hand, the public endpoint has no rate limit, the delivery cache is per process, Jira Data Center is not supported, `priority` and `labels` are not checked against the project, the sweeper needs the system role, and the migration's blanket `skipped`.
- **Order:** items 1 and 3 (a `ticket` table and an explicit ticketing policy) before 3.6; 2 and 4 before this is switched on for a real tenant; the rest as the milestone continues.

