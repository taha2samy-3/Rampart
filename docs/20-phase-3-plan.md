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
- **Verified:** `POST /rest/api/3/issue` requires `description` formatted strictly in **Atlassian Document Format (ADF)** JSON (`type: doc, version: 1, content: [...]`). `priority` is passed as an object (`{name: "High"}`), `labels` as an array of strings (`["label1", "label2"]`), and `customfield_XXXXX` as string, select object, or ADF depending on custom field type. (Alternatively, API v2 `POST /rest/api/2/issue` accepts raw text strings). **Decision:** The tracker formats `description` as standard ADF document nodes (`paragraph` and `text` with marks for links) for Jira API v3, with a helper for clean ADF encoding.

**Slack**
- Incoming webhooks are bound to one channel, cannot override channel or icon, cannot delete what they posted and do not return the message `ts`. **Decision:** use `chat.postMessage` (a channel per call, returns `ts`, lets a digest be updated). Limits: 50 blocks per message, 3,000 characters in a section's text, about one message per second per channel ([blocks](https://docs.slack.dev/reference/block-kit/blocks/), [postMessage](https://docs.slack.dev/reference/methods/chat.postMessage)).
- Inbound requests (interactive buttons, if used) are verified with `v0=` + HMAC-SHA256 of `v0:{timestamp}:{raw body}`, compared in constant time, and refused if the timestamp is more than 5 minutes off ([verifying requests](https://docs.slack.dev/authentication/verifying-requests-from-slack)).

**Microsoft Teams**
- Microsoft 365 connectors (legacy incoming webhooks) were permanently retired and blocked by Microsoft in **May 2026**; the replacement is a Workflows / Power Automate flow with the trigger "When a Teams webhook request is received" ([Microsoft](https://learn.microsoft.com/en-us/microsoftteams/m365-custom-connectors)). **Decision:** the Teams notifier targets the Workflows webhook only and posts the documented payload (`type: message`, an `attachments` entry of type `application/vnd.microsoft.card.adaptive`). No inbound limit is documented; Microsoft's message-post action is limited to about 28 KB, so a digest is truncated with a link.

**GitHub Issues**
- `POST /repos/{owner}/{repo}/issues`, `title` required; `labels`, `assignees` and `milestone` are silently dropped without push access, so the connector's `Check()` verifies push access and says so. A fine-grained token needs "Issues: write" ([create an issue](https://docs.github.com/en/rest/issues/issues#create-an-issue)).
- Webhooks: `X-Hub-Signature-256` = `sha256=` + hex HMAC-SHA256 of the payload with the secret; `X-GitHub-Delivery` identifies a delivery ([validating deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)). The older `X-Hub-Signature` is SHA-1 and is refused. The `issues` event actions include `closed`, `reopened`, `labeled` and `edited`. Whether the sender of our own change is marked as a bot is **not verified**: compare `sender.login` with the app's own login.

**Common rules (go into D69).** Every outbound call goes through one client that refuses private, loopback and link-local addresses after DNS resolution, limits redirects and response size, and sets a timeout. Secrets are read from `secret_material` at the moment of the call and never logged. An inbound webhook is a public endpoint: signature first, then size limit, then parse. A ticket resolution `Won't Do` or `False Positive` creates a risk-acceptance or not-affected **request** (D27).

## 5. Dependency-Track: verified facts and what is still open

Read from the Java sources of Dependency-Track **4.14.6** (the latest 4.x tag) on 2026-11-13; the full table is in docs/10 section 8. **Dependency-Track 5.x exists (5.2.1)**: the plan targets 4.x, and 5.x compatibility is checked before 3.4 starts.

- **Corrected in docs/10:** `suppressed` and `source` are real parameters of the finding endpoint; `X-Total-Count` is real; the FPF export produces version 1.4; the non-deprecated token endpoint is `GET /api/v1/event/token/{uuid}`; permission names are `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`, `VIEW_POLICY_VIOLATION`, `BOM_UPLOAD`, `VULNERABILITY_ANALYSIS`; `POST /api/v1/vex` exists.
- **Changes the design (decision in D23's direction, not against it):** the webhook publisher **cannot send arbitrary headers and does not sign the body**, but can send one authentication header (Basic, Bearer or a token header). So the secret does not go in the URL path as docs/10 first said; the rule sends `Authorization: Bearer <secret>` and the handler compares it in constant time. The payload is still an untrusted hint (thin event, fat fetch).
- **There is no "analysis complete" notification** in 4.14.6 (`PROJECT_VULN_ANALYSIS_COMPLETE` does not exist). The processing token needs `BOM_UPLOAD`, which a read-only pull key lacks. Whether `ProjectMetrics.lastOccurrence` moves after each analysis is **not verified**. Until it is tested against a running Dependency-Track, a project is settled when two spaced reads of its findings are identical, with the mass-close guard (D22) as the safety net. This is the first task of 3.4 and needs a real instance in CI or a recorded fixture of the behaviour.
- **Verified:** `pageNumber` (1-based index, default 1) and `pageSize` (default 100) are the pagination parameters on `GET /api/v1/project`; the total item count is returned in the `X-Total-Count` response header (supports `totalCount=EXACT` and `totalCount=BOUNDED`). `BOM_PROCESSED` event payloads follow `org.dependencytrack.notification.v1` with `notification.group = "BOM_PROCESSED"` and `subject.project.uuid`. **Still open:** whether `/api/v1/team/self` lists the key's permissions (the probe may have to try a harmless call per permission instead); whether `properties` and `tags` are filled in the single-project response.

## 6. CI OIDC federation (3.3): verified facts

Sources: GitHub's [OIDC reference](https://docs.github.com/en/actions/reference/security/oidc), GitLab's [ID token authentication](https://docs.gitlab.com/ci/secrets/id_token_authentication/), RFC 8693, RFC 7519.

- **GitHub** tokens carry `iss` = `https://token.actions.githubusercontent.com`, `aud` (the owner's URL by default; a workflow can request a custom audience), `sub`, `repository`, `repository_id`, `repository_owner`, `repository_owner_id`, `jti`, `ref`, `workflow_ref`, `job_workflow_ref`, `run_id`, and `environment` (only if the job uses one). The discovery document is at `…/.well-known/openid-configuration`; the key set URL is taken from its `jwks_uri` (not stated on the page). The `sha` claim is **not verified** (the page lists `workflow_sha` and `job_workflow_sha`). The token lifetime (`exp - iat`) is **verified**: strictly short-lived and capped at **5 minutes** (300 seconds), non-configurable in workflow YAML. **Decision:** The exchange endpoint of D22 (`POST /ingest/v1/t/{tenant}/token`) is called immediately upon minting; the issued Rampart token lasts 15 minutes. Replay cache entries for `(issuer, jti)` only need to be retained for 10 minutes (5m lifetime + 5m clock skew).
- GitHub documents an immutable `sub` form with owner and repository ids (`repo:OWNER@OWNER-ID/REPO@REPO-ID:…`), made the default for repositories created after **2026-07-15**, not available on GHES; a custom `sub` template replaces the default entirely; at least one condition must be defined on the relying side or untrusted repositories can obtain tokens. **Decision (D22 stands):** trust rules match `repository_id` and `repository_owner_id`, never names; the audience is `rampart:<public-host>:<tenant>`.
- **GitLab** ID tokens carry `iss`, `aud` (the instance domain by default, configurable in `id_tokens`), `project_id`, `namespace_id`, `project_path`, `namespace_path`, `ref`, `ref_protected` (a string, `"true"` or `"false"`), `jti`, `exp` (the job timeout, or 5 minutes). The issuer is the instance's base URL; for gitlab.com and self-managed alike the **key set is read from the issuer's discovery document**, not from a fixed path (a fixed path was not on the pages read: not verified). A trust rule names the issuer, so a self-managed GitLab is a different trust source from gitlab.com.
- Both carry `jti`. RFC 7519 §4.1.7 allows `jti` to prevent replay but makes it optional and unique **per issuer**: **Decision:** the replay cache is keyed on `(issuer, jti)` and entries live until the token's `exp` plus a clock-skew allowance; a token without `jti` is refused.
- RFC 8693 shape for the exchange: `POST` with `application/x-www-form-urlencoded`, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`, `subject_token_type`, optional `audience`; the response is JSON with `access_token`, `issued_token_type`, `token_type` and `expires_in`. **Decision:** the exchange endpoint of D22 (`POST /ingest/v1/t/{tenant}/token`) takes and returns these names, so a standard client works; the issued token lasts 15 minutes and is bound to the source and the derived context.

## 7. Parsers wave 2 (3.5)

Native or mapping, by the format. Already built and **not** in this wave: SARIF, CycloneDX, SPDX, Syft, OpenVEX, Trivy, Grype, Semgrep, Gitleaks, TruffleHog. To build: Checkov, Nuclei, OWASP ZAP, Bandit, Dependency-Check, kube-bench, Prowler (OCSF), Snyk, GitLab report schemas, Generic JSON. Each parser comes with real, sanitised fixtures under `testdata/<tool-version>/`, a golden canonical output and a fingerprint-stability test, as the ways of working in docs/09 require; each handles a record it cannot read the way D51 does.

## 8. Not in Phase 3

gRPC plugins and the Python and TypeScript SDKs (Phase 5), SAML (Phase 4), Dependency-Track SBOM forwarding and write-back (after v1.0, D23), the DefectDojo-compatible shim (after v1.0), cross-tool merging (after v1.0, D24).
