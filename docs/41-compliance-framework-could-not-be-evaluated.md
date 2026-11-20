# 41. "The framework could not be evaluated": why the Compliance page says it

Written for the owner to read and fix. Nothing here is applied. The cause was reproduced on the dev cluster with read-only requests (2026-11-20).
Also item 26 of [docs/34](34-review-and-fix-plan.md).

## 1. What was seen

Compliance page, framework **"PCI DSS 4.0.1: configuration, cryptography, scanning and testing (complements the built-in requirement 6 view)"**, application
**flare-reminders**: a red box "The framework could not be evaluated. Check the address, or go back to the findings.", a request id
(`744ab341-998d-9664-bcc4-c8f977a605d3`), and a Try again button. Trying again does not help.

## 2. The cause: it is not an error, it is a refusal that the page words as one

The request is `GET /api/v1/taxonomies/pci-dss-4.0.1-extended/status?application=<flare-reminders>`. Three requests, as the administrator, on the dev server:

| Request | Answer |
|---|---|
| that framework, **flare-reminders** | **404** `"This framework does not apply to that application: it does not list the complianceScope pci-dss"` |
| that framework, the whole tenant (no `application`) | 200 |
| `pci-dss-4.0.1-req6` (the built-in one), flare-reminders | 200 |

The framework `pci-dss-4.0.1-extended` carries `scope: pci-dss` (it comes from the platform, origin `cluster`). A framework with a scope reads **only the applications that
list that scope** in their `complianceScope` (D102): `handleTaxonomyStatus`, `internal/query/compliance.go:507-517`. `flare-reminders` was created by an upload and
lists none, so the framework does not apply to it. The application page already says so ("Not read here, because they cover only applications with their scope: ...",
`GET /api/v1/applications/{id}/compliance` returns the same frameworks under `not_in_scope`). The server's answer is correct; **the page makes it look like a failure.**

## 3. Why the page hides the real reason (the defect)

1. **The server puts the reason in `title`, and sends no `detail`.** `problem(w, status, typ, title)` (`internal/query/api.go:870`) writes `{type, title, status}` only. The refusal text above is
   the `title`. There are **324** calls of `problem(` in `internal/query`, and the third argument of most of them is a sentence for a person, not a short title.
2. **The page replaces the title.** `ComplianceRoute.tsx:99` renders `<ProblemMessage problem={...} title={t('compliance.loadFailed')} />`, and `ProblemMessage` shows
   `title ?? problem.title` and then **only `problem.detail`** (`web/src/components/Problem.tsx:32-39`). With an own title and no detail, the server's sentence is thrown away: the person reads
   "could not be evaluated" and a generic "Check the address" (the text for any 404).
3. **The same pattern is everywhere.** 41 uses of `<ProblemMessage ... title={...}>` in the web code set their own title, so every one of them hides a server sentence that arrived as a title.
4. **The picker offers what cannot be read.** The framework list and the application list are chosen independently, so any pair can be asked for, including a framework that does not
   apply to the application.
5. **The server does not log it.** A `404` from `problem()` is not logged, so the request id quoted on the page finds nothing in the log (searched the last three hours of the dev pod's log).
   For a refusal that is fine; for a 500 it would leave support with nothing to look up.

## 4. What the owner can do now (no code)

- Read the framework for the **whole tenant** (leave the application out), or pick `PCI DSS, requirement 6 and 8.6.2` (built in, no scope), which works for this application.
- To read the extended PCI framework for `flare-reminders`, put `pci-dss` in the application's `complianceScope` (an `Application` resource: `spec.complianceScope: [pci-dss]`).
  **Not checked:** whether an application made by an upload can be given a scope from the web page (no screen for it was found in the code; the Settings tab edits criticality, internet-facing,
  data, controls, lifecycle and environment).

## 5. What to change, in order

### 5.1 Say the reason (the real fix)

Pick one, or both:

- **Server:** make `problem()` send the sentence as `detail` as well, with a short `title`. The smallest change that fixes every page: add a `detail` field (the same text) and keep `title` as is, so
  nothing that reads `title` breaks:
  `json.NewEncoder(w).Encode(map[string]any{"type": ..., "title": title, "detail": title, "status": status})`. A cleaner change gives `problem` a `detail` argument and moves the 324 sentences there over time.
- **Page:** in `ProblemMessage`, when an own `title` is given and `problem.detail` is empty, show `problem.title` under it (so the server's sentence is never dropped):
  `{(problem.detail || (title && title !== problem.title ? problem.title : '')) && <p ...>{problem.detail || problem.title}</p>}`.

### 5.2 Do not call a refusal a failure

For `404` and `409` with a sentence from the server, the box should read as information, not a red failure: the Compliance page can check `status.error.status === 404` and show
"This framework does not apply to **flare-reminders**: it reads only applications that list `pci-dss` in their complianceScope" with a link to the application's Compliance section
(and no Try again button, which cannot help).

### 5.3 Do not offer what cannot be read

When an application is chosen, list only the frameworks of `GET /api/v1/applications/{id}/compliance` (its `frameworks`), and show the others in a short "not in this application's scope"
note (the same `not_in_scope` the application page prints). When no application is chosen, list every framework.

### 5.4 Log a 5xx with its request id

A request id on the page must find something: log every 5xx with the id (and, for a 4xx, nothing is needed).

## 6. Tests to add

| Where | What |
|---|---|
| `internal/query` | `GET /taxonomies/{id}/status?application=` for a scoped framework and an application without the scope answers 404 with the sentence in `detail`; with the scope present answers 200; whole tenant answers 200. |
| `internal/query` | `problem()` sends `detail` (every problem has a sentence a person can read). |
| `web/src/components` | `ProblemMessage` with an own title and a problem that has only `title` shows both; with `detail` shows the detail. |
| `web/src/routes/compliance` | Choosing a framework outside the application's scope shows the scope sentence and no Try again button; the picker lists only the application's frameworks when one is chosen. `compliance.test.tsx:126` already pins the generic text: it has to change with 5.2. |

## 7. What was and was not checked

Checked: the three requests above against the dev server (read only, as the administrator), the server code at the lines named, the web code at the lines named, the counts (324 and 41, by `grep`).
**Not checked:** whether the page's request really used `pci-dss-4.0.1-extended` and the application's id (inferred from the framework name in the screenshot and the 404 text, and reproduced with
those two; the request id in the screenshot was not found in the pod's log); how the application's scope can be set from the web page.
