# 11 — API design

OpenAPI 3.1, generated from Go types (huma). Three route families, served by different targets so the write path and read path stay separate.

| Prefix | Target | Audience | Auth |
|---|---|---|---|
| `/ingest/v1` | `ingest-gateway` | CI, scanners, CLI | ingest token, CI OIDC federation, k8s ServiceAccount |
| `/hooks` | `ingest-gateway` | Jira, GitHub, Dependency-Track | per-hook secret or signature |
| `/compat/defectdojo/api/v2` (shim, after v1.0) | `ingest-gateway` | legacy pipelines, DT's DefectDojo integration | `Authorization: Token` |
| `/auth` | `query-api` | browsers, CLI device login | session cookie, PKCE |
| `/api/v1` | `query-api` | UI, CLI, MCP, automation | OIDC session or API token |
| `/scim/v2` | `query-api` | IdP | SCIM bearer token |
| `/healthz`, `/readyz`, `/metrics` | every target | platform | none / network policy |

## Conventions

- Ingest paths carry the tenant: `/ingest/v1/t/{tenant}/…` (shown below without the prefix for brevity). For `/api/v1` the tenant is the session's or token's active tenant; platform admins may pass `X-Rampart-Tenant`.
- Session endpoints: `GET /auth/login`, `GET /auth/oidc/{idp}/callback`, `GET /auth/session`, `POST /auth/logout`, `POST /auth/tenant` (switch), `POST /auth/device/code`, `POST /auth/device/token`.
- IDs are UUIDv7 strings. Times are RFC 3339 UTC.
- Lists use cursor pagination: `?limit=100&cursor=<opaque>`; response `{items, nextCursor, total?}`. `total` only when `?count=true` because counting 5M rows is not free.
- Filtering uses one grammar everywhere (EBNF and field list in [16-implementation-decisions.md](16-implementation-decisions.md) D16): `?q=` with a small expression language (`severity:critical,high state:open app:payments-api cve:CVE-2024-* kev:true sla:breached age:>30d`). The same grammar backs saved views and CLI.
- Sorting: `?sort=-risk_score,first_seen`.
- Mutations accept `If-Match: <version>` for optimistic locking and `Idempotency-Key` on POST.
- Errors follow RFC 9457 problem details: `{type, title, status, detail, instance, errors[]}`.
- Rate limit headers: `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`; `429` with `Retry-After`.
- Bulk endpoints accept either explicit `ids[]` or a `q` filter, return a `bulkOperationId`, and run as a job when more than 1 000 rows match.
- Long exports return `202` with an operation resource; the result is a signed object-storage URL.

## Ingestion (`/ingest/v1`)

| Method and path | Purpose |
|---|---|
| `POST /uploads` | Create an upload. Body: `{source, format?, filename?, sizeBytes?, context{repository, branch, commit, imageDigest, environment, buildId, pipelineUrl, tags[]}, options{closeOldFindings?, doNotReactivate?, minimumSeverity?}}`. Returns `{uploadId, putUrl, putHeaders, expiresAt}` |
| `POST /uploads/{id}/complete` | Body `{sha256}`. Enqueues parsing. Returns `{ingestRunId, statusUrl}` |
| `POST /reports` | One-shot multipart upload for files up to 32 MB. Same fields as above plus `file` |
| `GET /runs/{id}` | Status and stats of an ingest run |
| `GET /runs`, `GET /runs/{id}` (on `/api/v1`, query API) | For the UI: runs newest first with a signed cursor (`limit`, `cursor`; answers `{items, next_cursor}`), and one run. Each is the run plus `scanners` (the tools in its report) and `ephemeral` (from an untracked ref, D10) |
| `POST /sbom` | Convenience alias of `/reports` that forces SBOM handling and DT forwarding rules |
| `POST /vex` | Upload OpenVEX, CycloneDX VEX or CSAF VEX |

## Hooks (`/hooks`)

| Path | Verification | Effect |
|---|---|---|
| `POST /hooks/dependency-track/{sourceId}/{secret}` | URL secret, optional CIDR allow-list | Debounced project sync. Payload is not trusted |
| `POST /hooks/jira/{connectorId}` | shared secret or JWT | Ticket status sync |
| `POST /hooks/github/{connectorId}` | `X-Hub-Signature-256` | Issue sync, code scanning alert events |
| `POST /hooks/gitlab/{connectorId}` | `X-Gitlab-Token` | Issue sync |
| `POST /hooks/generic/{sourceId}` | HMAC `X-Rampart-Signature` | Generic JSON findings push |

## Read and triage (`/api/v1`)

**Findings**

| Method and path | Purpose |
|---|---|
| `GET /findings` | Explorer. Filters via `q`; `fields=` to trim columns; `groupBy=rule\|cve\|component\|application\|owner` returns aggregates |
| `GET /findings/{id}` | Detail with risk factor breakdown, taxa, SLA, tickets, and `also_reported_by`: the other findings of the same correlation group (`[{id, scanner, rule_id, state}]`, at most 50; D24: display only, never merged) |
| `GET /findings/{id}/occurrences` | Per-tool evidence, newest first |
| `GET /findings/{id}/events` | Timeline |
| `PATCH /findings/{id}` | Change `state` (+ `justification`, `impactStatement`), `severity` (+ reason), `verified`, `owner`, `tags` |
| `POST /findings/{id}/notes` | Add note; supports mentions and attachments |
| `POST /findings/bulk` | `{ids[] \| q, patch{...}}` |
| `POST /findings/{id}/merge` / `/split` | Manual duplicate handling |
| `GET /findings/export` | `format=csv\|json\|sarif\|ocsf` |

**Inventory**

| Method and path | Purpose |
|---|---|
| `GET/POST /applications`, `GET/PATCH/DELETE /applications/{id}` | Applications. Those created from CRDs are read-only here and show `managedBy: crd` |
| `GET /applications/{id}/summary` | Counts, risk, SLA adherence, coverage |
| `GET /applications/{id}/sbom?format=cyclonedx\|spdx` | Merged SBOM |
| `GET /applications/{id}/vex?format=openvex\|cyclonedx\|csaf` | Current triage as VEX |
| `GET /hierarchy`, `GET /hierarchy/{id}/rollup` | Business-unit tree and roll-ups |
| `GET /assets`, `GET /assets/{id}`, `GET /assets/{id}/graph` | Assets and code-to-cloud edges |
| `GET /components?purl=` | "Where is this package used" across the tenant |
| `GET /coverage` | Assets without recent scans per category |

**Vulnerability intelligence**

| Method and path | Purpose |
|---|---|
| `GET /vulnerabilities/{id}` | Canonical record with aliases, CVSS, EPSS, KEV, SSVC, references |
| `GET /vulnerabilities/{id}/impact` | Applications and assets affected in this tenant |
| `GET /taxonomies`, `GET /taxonomies/{id}/status` | Frameworks and per-control open findings |

**Workflow**

| Method and path | Purpose |
|---|---|
| `GET/POST /risk-acceptances`, `POST /risk-acceptances/{id}/approve\|reject\|revoke` | Exception workflow |
| `GET/POST /groups`, `POST /groups/{id}/ticket` | Finding groups and one ticket per group |
| `POST /findings/{id}/tickets` | Create or link a ticket through a connector |
| `GET /sla/summary`, `GET /sla/breaches` | Adherence and breach lists |
| `GET /policies`, `GET /policies/{id}/simulations` | Automation rules and simulate-mode results |
| `GET /ingests`, `GET /ingests/{id}` | Ingest history |
| `GET /integrations`, `GET /integrations/{id}` | Catalogue of installed integrations: kind, runtime, version, support level, config schema, required secrets and egress, conformance result |
| `POST /integrations/{id}/enable`, `/disable` | Tenant admin enables an installed integration for the tenant |
| `POST /integrations/validate` | Dry-run a mapping or declarative definition against an uploaded sample; returns the canonical output and record errors |
| `GET /sources`, `GET /connectors` | Status of sources and connectors, including DT sync state and unmapped projects |
| `POST /sources/{id}/sync` | Trigger a pull now |
| `GET /sources/{id}/unmapped`, `POST /sources/{id}/map` | Dependency-Track projects without an application; assign one |

**Reporting**

| Method and path | Purpose |
|---|---|
| `GET /dashboards/overview` | Posture score, open by band, trend, MTTR, SLA |
| `GET /metrics/trend?metric=open\|new\|closed\|mttr&interval=day` | Time series from read models |
| `POST /report-jobs`, `GET /report-jobs/{id}` | Generate PDF/CSV/JSON report or evidence bundle |
| `POST /gate` | Body `{source, context{commit\|imageDigest}, expect[], wait?, timeoutSeconds?, failOn?}`. Returns `{pass, reasons[], summary{new, fixed, existing}, blocking[], runs[]}`; fails closed; `failOn` defaults to `critical` (D37). "New" is relative to the baseline track. Not built: `byBand`, `url`, `sarif` |
| `GET /stream` | Server-Sent Events, filtered by the caller's scope and coalesced |
| `GET /operations/{id}` | Progress of bulk actions and exports |
| `GET /ui-config` | Public UI configuration |
| `GET /saved-views`, `POST /saved-views` | Saved explorer filters |

**Administration**

| Method and path | Purpose |
|---|---|
| `GET /me`, `GET /me/permissions` | Current principal and effective scopes |
| `GET/POST/DELETE /tokens` | API tokens. Secret shown once |
| `GET/POST /teams`, `GET/POST /bindings` | Teams and role bindings not managed by CRDs |
| `GET /audit` | Audit events with cursor |
| `GET /settings`, `PATCH /settings` | Tenant settings |
| `GET /openapi.json` | Contract |

## Events (outbound webhooks and NATS)

Envelope follows CloudEvents 1.0: `{specversion, id, source, type, time, subject, tenant, data}`. Signed with `X-Rampart-Signature: sha256=<hmac>`.

Types: `rampart.finding.created`, `.updated`, `.state_changed`, `.reactivated`, `.closed`, `.sla_breaching`, `.sla_breached`, `rampart.risk_acceptance.requested`, `.approved`, `.expiring`, `.expired`, `rampart.ingest.completed`, `.failed`, `rampart.gate.evaluated`, `rampart.connector.degraded`, `rampart.source.sync_completed`.

## CLI (`rampart`)

```
rampart login --server https://rampart.example.com
rampart upload report.sarif --source github-actions --context branch=main,commit=$SHA
rampart sbom upload bom.json --source github-actions            # forwards to Dependency-Track when configured
rampart gate --source github-actions --commit $SHA --wait --timeout 300
rampart findings list -q 'severity:critical state:open app:payments-api' -o table|json
rampart findings set-state <id> not_affected --justification vulnerable_code_not_in_execute_path
rampart vex export --app payments-api --format openvex > payments.vex.json
rampart sources sync dtrack-portfolio
rampart integration init --kind parser --runtime mapping     # scaffold with fixture and golden file
rampart integration test ./pip-audit                        # conformance kit
rampart integration pack ./pip-audit && rampart integration push ghcr.io/acme/rampart-pip-audit:1.0.0
rampart feeds snapshot | import        # air-gapped
rampart migrate | version
```

Exit codes for CI: `0` pass, `1` gate failed, `2` usage error, `3` server or timeout error.

## Versioning

- `/api/v1` is stable from 1.0. Additive changes only within v1. Breaking changes ship as `/api/v2` with one minor release of overlap.
- Fields and endpoints are deprecated with `Deprecation` and `Sunset` headers.
- The DefectDojo shim under `/compat/defectdojo/` is a compatibility surface, documented as best-effort and not part of the versioning promise.
