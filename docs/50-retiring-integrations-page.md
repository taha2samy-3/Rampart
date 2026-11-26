# 50. Retiring `/integrations`: where its three remaining parts go

**Status:** plan, reviewed 2026-11-26 against the code (nothing applied). It is step 3.7 of [docs/51](51-fix-plan-after-review-2026-11-26.md) and is worked after the security steps there.
**Related:** [docs/49](49-containerized-ticketing-architecture.md) (ticketing moved to `/ticketing`), D82 (connectors are created only as resources), D94 (installed packages).

## 1. Context, as the code is today

`/integrations` (`web/src/routes/integrations/IntegrationsRoute.tsx`, 211 lines) used to hold every external setting. Since then:

| Moved to | What | Note |
|---|---|---|
| `/feeds` | KEV, EPSS, NVD, OSV and the other sources, advisory sources | |
| `/parsers` | report parsers (`ClusterParser`, `Parser`), SBOM readers (`ClusterSBOMParser`), analyzers | None of them is built in (D141, D146) |
| `/ticketing` | tracker connectors (`jira`, `github`, `externalTracker`) and the tracker containers | `TrackerBindingsView.tsx` lists them; its catalogue uses `kindFilter="tracker"` |
| application page, Sources tab | `ScanSource`s bound to an application | Not on `/ingestion`, which has the ingest runs and the upload |
| removed | Dependency-Track | D129. Some strings remain: `api/types.ts:788, 956-973`, `en.ts:545` (`scanNowTooltip`) |

## 2. What is left on `/integrations`

| Item | What it shows | Source |
|---|---|---|
| 1. Notifier connectors | `slack`, `teams`, `email`, `webhook`, `plugin`. Filtered by a **deny-list** of tracker types (`IntegrationsRoute.tsx:41-43`) | `GET /api/v1/connectors`, `ConnectorCatalogueDialog` with `kindFilter="non-tracker"` |
| 2. Installed packages | `IntegrationPackage` of kind `notifier` and `parser`, with runtime, version, error and "used by" | `GET /api/v1/integration-packages` |
| 3. API Tokens tab | Static text: "API tokens are not listed or issued from this page yet", how CI federation and `rampart login` work | `IntegrationsRoute.tsx:195` |

## 3. Where each goes

| Item | Goes to | Why |
|---|---|---|
| Notifier connectors and `notifier` packages | A new route **`/notifiers`**, labelled **Notifiers** | Outbound messages get their own place beside Ticketing. Not `/notifications`: that name is already the person's in-app inbox (the bell, `GET /api/v1/notifications`, D45). Two different "Notifications" in one product would be read as one. `notifier` is also the kind the catalogue and `IntegrationPackage` already use. |
| `parser` packages | `/parsers`, **as detail on rows that already exist** | `GET /api/v1/parsers` already lists each parser package as `mapping:<name>` (`internal/query/parsers.go:37-44`). A second table would show each one twice. What the parsers page lacks is the package's runtime, version, compile error and "used by"; those go into the parser inspector. |
| API Tokens text | `/administration`, as an "API access" section | It is guidance on how access is given (federation, `rampart login`), next to users, access and audit. It is **not** token issuance: there is no token API (D82). The section says so, as the tab does today. |

## 4. Steps

1. **Server: say each connector's kind.** Add `kind` (`tracker`, `notifier`, `source`) to each item of `GET /api/v1/connectors`, taken from the catalogue (`internal/domain/connector_catalogue.go`). Today two pages each keep a hard-coded list of types: a deny-list in `IntegrationsRoute.tsx:41` and an allow-list in `TrackerBindingsView.tsx:9`. A new type, such as the deferred `gitlab`, `azureBoards` and `serviceNow` (`domain/connector.go:113-115`), would land on the wrong page or on neither. Then both pages filter by `kind`. Add `kind` to `ConnectorSummary`, `openapi.json` and the mock server. A Go test checks that every `ConnectorType` has a catalogue kind.
2. **`/notifiers`.** `web/src/routes/notifiers/NotifiersRoute.tsx`: connectors with `kind === 'notifier'`, the `notifier` packages table (moved as it is, with its error and empty states), `ConnectorCatalogueDialog` with `kindFilter="notifier"`. Change the dialog's prop type from `'tracker' | 'non-tracker'` to the catalogue kinds.
3. **`/parsers`.** In the parser inspector, for a `mapping:` parser, show the package's runtime, version, error and "used by" from `GET /api/v1/integration-packages`. A package whose compile failed must show its error there; the parsers list alone does not carry it today.
4. **`/administration`.** Move the tokens text into an "API access" section. Its wording follows the federation fix of docs/51 step 1.3. It does not describe `tokenSecretRef` tokens (docs/48 Mode A) as working: nothing reads them for authentication today.
5. **Navigation.** `nav.ts`: replace the `integrations` item with `{ id: 'notifiers', path: '/notifiers', ... }`, with its `what` text. Pick an icon that is not `IconBell`, which the top bar uses for the inbox. `router.tsx`: the route, the `BUILT` set, and a redirect `/integrations` -> `/notifiers` (`beforeLoad` with `redirect`, `replace: true`) kept for two releases. `en.ts`: `nav.notifiers` and the page's strings as keys (the current page has hard-coded English); remove the `integrations.*` keys.
6. **Remove** `routes/integrations/IntegrationsRoute.tsx` and `integrations.test.tsx`. Keep `ConnectorCatalogueDialog.tsx`, which `/ticketing` uses: move it to `components/` or `features/connectors/`. In `feeds.test.tsx:47`, replace the `/integrations` check with a test that `/integrations` redirects.
7. **Words left from Dependency-Track** (section 1): remove the types no screen reads, and correct `scanNowTooltip` (matching is the analyzers' work, D143).
8. **Tests.**
   - `notifiers.test.tsx`: only notifiers listed (a tracker connector in the fixture is not), packages with an error, empty and error states, axe.
   - `ticketing.test.tsx`: trackers filtered by `kind`.
   - The redirect.
   - The parser inspector showing a package error.
   - Playwright: no current spec opens `/integrations`; add none unless a spec already covers the nav.
9. **Docs.** docs/13's navigation section; a D-entry in docs/16 (the route name and why not `/notifications`, the `kind` field, where the tokens text went); docs/09's status line.
10. The AGENTS.md section 5 battery, run by the owner.

## 5. Navigation after

```text
Look:      Overview, Findings, Applications, Inventory, Vulnerabilities
Act:       Workflow, Compliance, Ingestion, Parsers
Configure: Policies, Feeds, Ticketing, Notifiers, Administration
```

| Item | Holds |
|---|---|
| Ticketing | Tracker containers, bindings (Jira, GitHub, external), Tickets & outbox |
| Notifiers | Slack, Teams, Email, Webhook, plugin connectors, notifier packages |
| Administration | Users, teams, access, audit log, API access |

## 6. What the first version of this plan missed

- The route name `/notifications` collides with the in-app inbox.
- Parser packages are already rows on `/parsers`; a new table would duplicate them.
- Connectors are split between two pages by two hard-coded type lists, which a third list would make worse; the server should say the kind.
- The tokens tab issues nothing; calling it "token issuance" overstates it.
- Context errors: `/ingestion` does not hold ScanSources, and the parsers are not "built-in" (D146).
- `ConnectorCatalogueDialog` is used by `/ticketing` too, so it cannot leave with the folder.
- i18n keys, the icon, the `BUILT` set, the mock server, the D-entry and docs/13 were not in the steps.
