# 50. Retiring `/integrations` and Separating Remaining Capabilities

**Status:** Proposed follow-up  
**Related:** `docs/49-containerized-ticketing-architecture.md`

---

## 1. Context

Originally, `/integrations` (`web/src/routes/integrations/IntegrationsRoute.tsx`) acted as a catch-all page for all external system configuration. Over recent slices, dedicated domains were extracted into first-class top-level sidebar sections (`web/src/app/nav.ts`):

1. **Feeds** (`/feeds`) — Threat intelligence & advisory feeds (`KEV`, `EPSS`, `NVD`, `OSV`, `Vulnrichment`, `ExploitDB`).
2. **Parsers & Analyzers** (`/parsers`) — Built-in report parsers, SBOM parsers, and `ExternalAnalyzer` / `SBOMAnalyzer` containers.
3. **Ingestion** (`/ingestion`) — `ScanSource`s, ingest runs, and uploads.
4. **Ticketing** (`/ticketing`) — Containerized gRPC issue trackers (`ClusterExternalTracker` / `ExternalTracker`), tracker bindings, and the `Tickets & Outbox` queue.
5. **Dependency-Track (`dependencyTrack`)** — Excluded from active connector catalogue/UI.

---

## 2. Exact Inventory of What Remains in `/integrations`

Only **three** small items remain in `IntegrationsRoute.tsx`:

| Remaining Item | Details | Current Source |
|---|---|---|
| **1. Notification Connectors** | `slack`, `teams`, `email`, `webhook`, `plugin` (e.g. `google-chat`) | `GET /api/v1/connectors` + `ConnectorCatalogueDialog.tsx` |
| **2. Installed Packages (`IntegrationPackage`)** | Declarative `notifier` packages and mapping `parser` packages | `GET /api/v1/integration-packages` |
| **3. `API Tokens` Tab** | Static informational guidance on CI federation and `rampart login` | `IntegrationsRoute.tsx` (`tokens` tab) |

---

## 3. Target Placement Plan

To retire `/integrations` completely without leaving orphaned UI or dead references:

| Remaining Item | Target Destination | Rationale |
|---|---|---|
| **Notification Connectors + `notifier` `IntegrationPackage`s** | New dedicated **`Notifications`** route (`/notifications`, `NotificationsRoute.tsx`) | Gives outbound alerting its own unambiguous top-level nav item alongside `Policies`, `Feeds`, and `Ticketing`, reusing `ConnectorCatalogueDialog` with `kindFilter="notifier"`. |
| **`parser` `IntegrationPackage`s (`kind: "parser"`)** | **`Parsers`** route (`/parsers`, `ParsersRoute.tsx`) | Custom mapping parser packages belong alongside report & SBOM parsers rather than in a notifications/integrations page. |
| **`API Tokens` Tab** | **`Administration`** route (`/administration`, `AdministrationRoute.tsx`) | Token issuance and auth/CLI guidance belong with RBAC, users, teams, and audit logs. |

---

## 4. Implementation Checklist

1. Create `web/src/routes/notifications/NotificationsRoute.tsx` (connectors filtered to `slack | teams | email | webhook | plugin`, `notifier` packages table, and `ConnectorCatalogueDialog` with `kindFilter="notifier"`).
2. Surface `kind === "parser"` `IntegrationPackage` rows inside `web/src/routes/parsers/ParsersRoute.tsx`.
3. Move the `API Tokens` informational section into `web/src/routes/administration/AdministrationRoute.tsx`.
4. Update `web/src/app/nav.ts` and `web/src/app/router.tsx`:
   - Replace `{ id: 'integrations', path: '/integrations', ... }` with `{ id: 'notifications', path: '/notifications', ... }`.
   - Add a client redirect from `/integrations` -> `/notifications` for bookmark compatibility.
5. Remove `web/src/routes/integrations/IntegrationsRoute.tsx` and `integrations.test.tsx` (replaced by `notifications.test.tsx`), and update the legacy check in `web/src/routes/feeds/feeds.test.tsx` that asserts `/integrations` has no Feeds tab.

---

## 5. Resulting Navigation Structure

```text
Configure / Operate:
- Policies        (/policies)
- Feeds           (/feeds)
- Ticketing       (/ticketing)      <- Tracker Containers + Bindings + Tickets & Outbox
- Notifications   (/notifications)  <- Slack / Teams / Email / Webhook + Notifier Packages
- Administration  (/administration) <- Users, Teams, Access, Audit Log + API Tokens
```
