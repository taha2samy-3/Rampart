# 49. Containerized Ticketing Architecture & Standalone `/ticketing` Workspace

Date: 2026-11-26  
Status: Planned / Implementation In Progress  
Related Decisions: [D27](16-implementation-decisions.md#d27), [D66](16-implementation-decisions.md#d66), [D69](16-implementation-decisions.md#d69), [D70](16-implementation-decisions.md#d70), [D87](16-implementation-decisions.md#d87), [D143](16-implementation-decisions.md#d143)

---

## 1. Overview & Motivation

Rampart originally coupled external issue trackers (`JiraTracker`, `GitHubTracker`) directly inside its core binary (`internal/connectors/trackers.go`, `check_trackers.go`, `inbound.go`) and mixed them into the `Connector` CRD and the **Integrations → Connectors & Trackers** UI tab.

This architecture follows Rampart's **Zero-Builtin & Container Microservice** model (matching `ClusterExternalAnalyzer` / `ExternalAnalyzer` in [docs/38](38-analyzers.md)):

1. **Decoupled Container Execution over gRPC (`pkg/api/tracker/v1`)**: Any external ticketing provider (Jira Cloud/DC, GitHub Issues, GitLab Issues, ServiceNow, Linear, custom enterprise systems) runs in an independent Kubernetes container behind a `ClusterExternalTracker` or `ExternalTracker` resource and speaks a single canonical protobuf contract (`TrackerService`).
2. **Core Owns All State, Retries, Rate Limits, and Trust**: Rampart core keeps the Outbox reservations (`ticket_outbox`), exponential backoff (`MaxTicketAttempts`), per-hour rate limits (`MaxPerHour`), idempotency label matching (`FindIssueByLabel`), group/attestation ticketing (`GroupIssue`, `AttestationIssue`), inbound delivery deduplication (`webhook_delivery`), and approval workflow (`WorkflowService`). Tracker containers remain stateless translators with zero database access.
3. **Standalone Sidebar Navigation Tab (`/ticketing`)**: Ticketing is extracted out of `Connectors` and elevated to a dedicated top-level sidebar tab (`/ticketing`) alongside `Workflow`, `Parsers`, and `Integrations`. Meanwhile `/integrations` focuses strictly on **Notifications, Data Sources (`Dependency-Track`), Installed Packages, and API Tokens**.

---

## 2. Canonical Interface (`pkg/api/tracker/v1/tracker.proto`)

`TrackerService` mirrors `domain.Tracker` (`internal/domain/connector.go`), `DetailedChecker` (`internal/connectors/check_trackers.go`), and two-way webhook sync (`internal/connectors/inbound.go`):

| RPC | Purpose | Existing Core Equivalent |
| :--- | :--- | :--- |
| `HealthCheck` | Liveness and serving status of the tracker container | `AnalyzerService.HealthCheck` |
| `GetMetadata` | Provider slug, version, capabilities, `config_schema` JSON, declared secrets | `AnalyzerService.GetMetadata` |
| `Check` | Verifies tenant config & credentials; returns `account_id` (D70 B6) & `accepted_fields` (D87) | `DetailedChecker.CheckDetailed` |
| `CreateIssue` | Opens an issue using pre-resolved `project`, `finding_url`, `idempotency_label`, and typed `custom_fields` | `domain.Tracker.CreateIssue` |
| `FindIssueByLabel` | Idempotent lookup during retries after transient failures (D70 B2) | `domain.Tracker.FindIssueByLabel` |
| `Comment` | Posts updates on an existing ticket | `domain.Tracker.Comment` |
| `Close` | Closes a ticket when finding resolves / attestation renews | `domain.Tracker.Close` |
| `ParseWebhook` | Verifies vendor HMAC signature and translates vendor payload into canonical decision event | `InboundWebhookHandler` |
| `PollStates` | Optional status sync for trackers without webhook support | `syncInterval` polling |

### Core-Side Guardrails Preserved Across the Boundary
* **Error Classification & Sanitization**: Containers return structured `TrackerCallError` (`http_status`, `fatal`, `sanitized_message`) so core continues to apply `domain.IsFatalTrackerError` (4xx flips binding `Connected=False`; 5xx retries) and `SanitizeTrackerError` without exposing secrets or raw vulnerability bodies.
* **Synthetic Issues & Templates Evaluated in Core**: `GroupIssue` and `AttestationIssue` URL routing (`/t/<slug>/compliance` vs `/t/<slug>/findings/<id>`), `FindingLabel(id)`, and `customFields` placeholder evaluation (`{{ finding.risk_score }}` typed as numeric/string) are resolved in Go core before dispatching gRPC requests.
* **Two-Way Sync Anti-Loop & Approval Safety**: Core still enforces `MaxInboundBody` (1 MiB), `ratelimit.Limiter`, `webhook_delivery` deduplication after `verified == true`, `TicketVerifier.FindingHasTicket`, `actor_id != accountId` anti-loop, and `WorkflowService.Request` (`inboundExpiry`).

---

## 3. Kubernetes CRDs & Migration Strategy

1. **`ClusterExternalTracker` (Cluster-scoped)** & **`ExternalTracker` (Namespace-scoped)**:
   * Mirrors `ClusterExternalAnalyzer` / `ExternalAnalyzer` (`protocol`, `service: {name, namespace, port}`, `endpoint` restricted to cluster-scope for SSRF protection, `timeoutSeconds`, `tls: {insecure, caSecretRef}`, `auth: {secretRef}`).
2. **`TicketTracker` (Namespace-scoped Tenant Binding & Policy)**:
   * References `trackerRef: {scope: cluster|namespaced, name}`, `credentialsSecretRef`, `webhookSecretRef`, provider `config` (validated against `GetMetadata.config_schema`), `ticketing` policy (`onCritical`, `minBand`, `project`, `projects`, `maxPerHour`), and `twoWaySync` settings.
3. **Database Schema (`00057_external_trackers.sql`)**:
   * `external_tracker` and `external_tracker_event` (mirroring `external_analyzer` / `analyzer_event` tables for health & test history).
   * `ticket_tracker` (RLS-enforced tenant bindings with status conditions, `account_id`, `accepted_fields`, `webhook_url`).
4. **Expand/Contract Transition from `Connector`**:
   * Step 1: Introduce `TrackerService` gRPC client, `GrpcTracker` adapter, CRDs, `/api/v1/trackers/*`, and standalone `/ticketing` sidebar page while keeping existing `Connector.spec.jira`/`github` functional during migration.
   * Step 2: Ship standalone containerized implementations (`examples/external-tracker/`, Jira & GitHub microservice containers + Helm charts) verified against full parity tests.
   * Step 3: Remove hardcoded `JiraTracker` and `GitHubTracker` HTTP implementations from Rampart core and clean `Connector` to Notifications & Data Sources only.

---

## 4. UI Architecture: Standalone `/ticketing` Tab

* **Sidebar (`web/src/app/nav.ts`)**: Add top-level `{ id: 'ticketing', path: '/ticketing', ... }`.
* **Page (`web/src/routes/ticketing/TicketingRoute.tsx`)**:
  1. **Tracker Containers**: Lists `ClusterExternalTracker` / `ExternalTracker` pods, capabilities, explicit status (`Ready` / `Refused` / `Off`), and right inspector with `Test container` + event history.
  2. **Bindings & Policy**: Lists tenant `TicketTracker` configs, `onCritical`, `minBand`, `maxPerHour`, `twoWaySync` webhook URL, `Connected` health, `Verify credentials`, and schema-driven YAML catalogue dialog.
  3. **Tickets & Outbox**: Real-time SSE-backed view (`live_event`) of `ticket`, `ticket_outbox`, and `attestation_ticket` rows with `Retry` actions.
* **Cleaned `/integrations`**: Renamed first tab from `Connectors & Trackers` to `Notifications & Sources` (Slack, Teams, Email, Webhook, Declarative Notifiers, Dependency-Track), alongside `Installed packages` and `API Tokens`.

---

## 5. Implementation Slices

1. **Slice 1 (Contract & gRPC Client)**: `pkg/api/tracker/v1/tracker.proto`, generated `.pb.go`, `internal/tracker/client` + `bufconn` unit tests.
2. **Slice 2 (Core Adapter)**: `GrpcTracker` implementing `domain.Tracker`, template pre-evaluation, fatal error mapping, `DefaultTrackerResolver` & `DefaultChecker` integration.
3. **Slice 3 (CRDs, Migration & Operator)**: `ClusterExternalTracker`, `ExternalTracker`, `TicketTracker` CRDs, SQL `00057_external_trackers.sql`, operator reconcilers & health probes.
4. **Slice 4 (APIs & Webhooks)**: `/api/v1/trackers/*` & `/api/v1/tickets/*`, `InboundWebhookHandler` delegation to `ParseWebhook`, binding status updates on fatal 4xx errors.
5. **Slice 5 (Standalone `/ticketing` UI & Clean `/integrations`)**: Sidebar route `/ticketing`, 3 internal tabs, cleaned `/integrations`, i18n, mock server, and unit tests.
6. **Slice 6 (Container Implementations & Builtin Removal)**: `examples/external-tracker/`, containerized Jira & GitHub services + Helm charts, parity tests, final removal of builtin tracker code from core.
