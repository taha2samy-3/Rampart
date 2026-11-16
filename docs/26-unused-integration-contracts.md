# 26. Unused integration contracts: removed

Status: **removed** (docs/16 D96). The code below is gone; `KindSource`, `KindTracker` and `KindNotifier` were unused and went with it. This file records what was removed and why.

## Why

docs/19 designed one contract per integration kind: parser, source, tracker, notifier. In Phase 3 the real connectors came first (D69, D70), each with its own interface. The contracts were then written beside them in D75, with placeholder adapters and tests for those placeholders. The real connectors were never moved onto the contracts, although D75 says they were (docs/23 K1, K2). D82 deleted the placeholders, so the tracker, notifier and source contracts now have no implementation and no caller.

The interfaces the code runs on are:

| Kind | Interface in use |
|---|---|
| Tracker | `domain.Tracker` (`internal/domain/connector.go`), used by the ticket sweeper |
| Notifier | `connectors.Notifier` (`internal/connectors/notifiers.go`), used by the router; installed packages (D94) plug in here |
| Source | none generic; Dependency-Track is `internal/upstream/dependencytrack/{client,sync,webhook,service}` (D92) |
| Parser | `integrations.ParserContract` and the `Registry` parser functions. **Keep these**: the ingest gateway, the processor and the query API use them |

Dependency-Track never ran through `SourceContract`. Only a placeholder adapter did, and D82 removed it.

The rule for later: write a contract when a second real implementation needs it, shaped to the code that exists. If code plugins (gRPC, WebAssembly) come in a later phase (docs/19 §7, docs/23 §6.6), their contract is written then.

## What was removed

### `internal/integrations/registry.go`

Types:
- `SourceContract`, `UpstreamProject`
- `TrackerContract`, `IssueDraft`, `IssueRef`, `IssueState`
- `NotifierContract`, `Message`

`Registry` fields: `sources`, `trackers`, `notifiers`, and their initialisation in `NewRegistry`.

Functions:
- `RegisterSource`, `GetSource`, `ListSources`
- `RegisterTracker`, `GetTracker`, `ListTrackers`
- `RegisterNotifier`, `GetNotifier`, `ListNotifiers`
- `ListAll`: only its test calls it. Remove it, or reduce it to the parsers.

Constants `KindSource`, `KindTracker` and `KindNotifier`: check first. `Descriptor.Kind` and the catalogue may still use them as labels; keep any that are referenced.

Keep: `ParserContract`, `Descriptor`, `SupportLevel`, `RegisterParser`, `GetParser`, `ListParsers`, `DetectParser`, `default.go`, the `conformance` package.

### `internal/domain/canonical.go`

Nothing outside the file uses these:
- `IssueDraft`, `IssueDraftFinding`
- `CanonicalMessage`, `MessageItem`
- `UpstreamProject`

Nothing else was in the file, so it was deleted.

### Tests

`internal/integrations/contracts_test.go`, `TestRegistry_AllBuiltinContracts`: drop the part that counts trackers, notifiers and sources, and the `ListAll` check. The parser checks stay.

## Docs updated with the removal

| Document | Change |
|---|---|
| docs/16 | A new decision: the contracts are removed, with the reason above. Mark D75's tracker, notifier and source contract bullets as superseded by it. |
| docs/23 | §6 and K2: the target design no longer names `TrackerContract`, `NotifierContract` or `SourceContract`. Say the existing interfaces stay until a second implementation needs a shared one. |
| docs/21 | The line that lists the four contracts as built. |
| docs/19 | §3: say the tracker, notifier and source contracts are a design for code plugins, not built. |
| docs/09 | Phase 3.5, if it lists the contracts as done. |

## Check

```sh
go build ./... && go vet ./...
grep -rn "TrackerContract\|NotifierContract\|SourceContract\|CanonicalMessage" --include=*.go .   # expect nothing
```
