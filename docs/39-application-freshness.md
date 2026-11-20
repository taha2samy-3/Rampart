# 39. How fresh is an application: sync status, re-check, and many people at once

A plan, with what was checked. Nothing in section 5 is built. The question (owner, 2026-11-20): should an application page say when it was last
synced with the vulnerability databases (the feeds) and with the analyzers, with a button to check again? Is that what happens today, do people
have to go and check, and what happens if 300 people ask at the same moment?

**Verified here** means read in this repository's code or run. **Dependency-Track** statements come from its published design documents and are
marked with the page; **the old system** is read from git (`3c367c3^`). What was not found is said.

## 1. What happens today (verified in the code)

| Question | Answer | Where |
|---|---|---|
| Does anyone have to go and check an application against new data? | **No.** Two background mechanisms do it, on their own. | below |
| **The feeds** (KEV, EPSS, NVD, OSV, ...): when do they sync? | On a schedule, every `feeds.interval` (6 h by default); a feed that failed is due again at the next check; a feed that is fresh is left alone. An administrator can also press Sync on the Feeds page. | `enrich.RunScheduler`, `FeedConfig.OnlyDue` |
| What happens to an application after a feed synced? | Every finding that has a vulnerability id is **re-scored** (score, band, KEV, EPSS bucket, due date), for every tenant, after the aliases are re-keyed. It is **not** matched again: a new advisory does not create a finding by itself. | `runner.go` `fc.OnSynced` -> `ingest.RekeyAll`, `scoring.RescoreAll`; `Scorer.Rescore` |
| **The analyzers**: when does an application get matched against the advisories? | When an SBOM is uploaded, when a person asks (`POST /api/v1/analyzers/analyze`, `POST /api/v1/assets/{id}/analyze`), and on a sweep that runs every 60 s and asks again about an SBOM whose last analysis is older than `analysis.maxAge` (24 h), or when the SBOMAnalyzer's cron fired. Only the newest SBOM of each application and track. | `internal/analysis`, docs/38 |
| So how fresh is an application normally? | Its **scores** follow the feeds within one feed interval plus the re-score. Its **matches** (which components have which advisory) follow the analyzers within 24 h, or at the next upload. | |
| Does the application page say any of it? | **No.** It shows `last_scan` (the last report), the SBOM and the findings. Nothing says when the feeds or the analyzers last worked for this application. The feeds' state is global (`feed_state`), and the analysis record per SBOM and analyzer (`sbom_analysis`) is shown nowhere but the analyzer's history. | `scan_coverage.go`, `ApplicationSBOMSection.tsx` |
| Is there a button? | There is one, and **it does nothing.** "Refresh" in the SBOM section calls `POST /api/v1/applications/{id}/refresh-vulnerabilities`, which checks the role and the application and then answers `202 "Native vulnerability scan triggered for application"` without queuing anything. | `internal/query/app_refresh.go`, `ApplicationSBOMSection.tsx:144`; docs/34 item 1 already says to remove the Dependency-Track refresh |

**Conclusion: the normal state is that nobody checks.** The system re-checks by itself, and that is what Dependency-Track does too. What is missing is
*seeing* it, and one button that is a lie and has to be made true or removed.

## 2. What Dependency-Track does

From its design documents ([vulnerability analysis](https://dependencytrack.github.io/docs/next/concepts/architecture/design/vulnerability-analysis/),
[auditing basics](https://docs.dependencytrack.org/triage/auditing-basics/)); the search results are summarised, the pages were not read in full:

- Analysis is **per project**, started by a BOM upload, a manual trigger or a schedule.
- **One analysis run per project at a time**, whatever started it. Scheduled and manual triggers are de-duplicated per project (a request for a project
  that is already being analysed does not start a second run). A BOM upload is the exception: each upload gets its own run.
- Priority: manual (75) over upload (50) over scheduled (0); it decides who is admitted next, it does not interrupt a run.
- The scheduler wakes every 60 s, takes projects last analysed more than 24 h ago, oldest first, and stops at 50 in flight. Every trigger resets that clock.
- The **Reanalyze** button is on the project's *Audit Vulnerabilities* tab (added in v4.7.0). A known report: [issue #4518](https://github.com/DependencyTrack/dependency-track/issues/4518)
  says Reanalyze did not remove findings that a changed setting made stale, while re-uploading the same SBOM did.
- **Not found:** where, or whether, the UI shows the *time* of the last analysis. Do not copy a "last analysed" line on the strength of Dependency-Track.

Rampart already follows the first four points (docs/38, `ClaimSBOMAnalysis`). Reanalyze with a fake behind it is the one thing it does worse.

## 2a. The old system and the new one, side by side

"The old system" is the Rampart that depended on Dependency-Track (removed in the commit `3c367c3`). Read from git (`3c367c3^`) and from the Dependency-Track
pages above:

| | **Old: Rampart with Dependency-Track** | **New: Rampart's own analyzers** |
|---|---|---|
| Who matched components to advisories | Dependency-Track, in its own database, per project | Rampart: the built-in matcher over `vulnerability_affected`, and any external analyzer (`internal/analysis`) |
| Did it check periodically? | **Yes, in two layers.** (1) Dependency-Track mirrored its sources on its own schedule (OSV: daily, or at restart; NVD and GitHub advisories: each has its own cron, defaults not confirmed) and **re-analysed its portfolio on a schedule**, so a newly published advisory surfaced without a new upload. (2) Rampart then **pulled** Dependency-Track's findings: an incremental portfolio sync every **30 minutes** by default (`DefaultDTrackSchedule`, never below 5), and a project sync when a webhook or an upload said it changed (`dtrack_sync`, one row per project; `RecordPortfolioSync` kept the time). | **Yes, in two parts.** The feeds sync every 6 h and the findings are re-scored after each (section 1); the analyzers analyse an SBOM on upload, on request, and again when its last analysis is older than 24 h (or its cron fired). |
| So how stale could an application be? | Up to Dependency-Track's own cycle (it decided when a new advisory was matched) **plus** up to 30 minutes for Rampart to pull it. Two clocks, neither Rampart's. | One clock, Rampart's: at most `analysis.maxAge` (24 h) for a new match, one feed interval (6 h) for a new score. |
| Was there a "when was it last synced" line? | Rampart kept `LastPortfolioSync` on each source and the project's `lastVulnerabilityAnalysis` was read to wait until a BOM was analysed (`CheckSettled`, D-series DT1). **Not found:** a line on the application page. | None yet (section 1). |
| What did the Refresh button do? | `POST .../refresh-vulnerabilities` **queued a sync of each Dependency-Track project mapped to the application**. Its own comment says it pulled what Dependency-Track had already analysed and **did not ask Dependency-Track to re-analyse**. With no project mapped it answered 409. | Nothing: after the removal the endpoint kept its name and its `202` and lost the work (`app_refresh.go`). Slice A of section 5 makes it real. |
| One at a time? | Dependency-Track: one analysis run per project (its concurrency key); Rampart: one sync job per project (`dtrack_sync` state). | One analysis per SBOM and analyzer, claimed in the database (`ClaimSBOMAnalysis`). |
| What was lost, and what was gained | Lost: the speed of "Dependency-Track already has it" and its commercial sources (OSS Index, Snyk) unless an analyzer brings them (D142). | Gained: one clock, one place that says why something is stale, and attribution per analyzer. The price: the matcher is only as good as the OSV data loaded (docs/38 section 9), and a wider matcher is Rampart's work now. |

**What this means for the plan.** The old system re-checked by itself and so does the new one; nobody had to go and check in either. What the old one did that
the new one does not yet is **tell the application's reader when that last happened** and **let them ask now** (the Refresh button, which worked by pulling).
So the plan below restores both, on the new system, and does one thing the old one could not: it can really ask the matcher again, because the matcher is
Rampart's.

## 3. Is the idea right?

**Yes, for the *seeing*, with two conditions; for the *button*, yes only if it is real and limited.**

- A section that says, for this application: when each feed last synced and how it went, and for each analyzer when it last analysed the newest SBOM, how it
  ended and what it found, answers the question every auditor asks ("is this still true today?") without anyone running anything. It is cheap: the data
  is already stored (`feed_state`, `sbom_analysis`, `analyzer_event`).
- Condition 1: **say what each date means.** A feed's last sync is *when the data was fetched*; it is global, shared by every application, and a fresh feed
  does not mean this application was matched against it. Only the analyzer's last analysis speaks for this application's matches. Showing both side by side
  invites the mistake of reading the feed date as the application's.
- Condition 2: the button must be **one request that the server can refuse politely**, because the work behind it calls external services that cost money or
  have quotas (Sonatype OSS Index) and hold a worker each.

## 4. Many people at the same moment (300)

What the code does now, and where it would not hold:

| Case | Today | Verdict |
|---|---|---|
| 300 people press "Sync" on the Feeds page | Administrators only. A PostgreSQL advisory lock allows one round; the others get `409 already running` (`ErrSyncBusy`). | Holds. The message is an error banner after a click: it should be a state everyone sees before clicking. |
| 300 people have the Feeds page open during a sync | Each browser polls `GET /api/v1/feeds` every 2 s while a feed is syncing or queued (`FeedsRoute.tsx` `refetchInterval`): about **150 requests a second** for the duration of a sync, each reading the feed table. | **Does not scale well.** |
| 300 people press "Analyze" for the same application | `ClaimSBOMAnalysis` lets one analysis be pending or running per SBOM and analyzer, so the 299 others queue nothing (the API answers `queued: 0`). | Holds on the server. The answer reads as "nothing happened"; it should say "already running, started HH:MM". |
| 300 people press it for 300 different applications | Each is one analysis per analyzer per SBOM; the queue is capped by `analysis.maxInFlight` (50) only for the *sweep*; manual requests are not capped. 300 manual requests would be 300 jobs, 10 workers, each calling the analyzer with a whole SBOM. | **Not limited.** An external analyzer with a quota would be hit 300 times. |
| The live stream | The browser has one `EventSource` per tab; the server polls the `live_event` table **once per replica**, whatever the number of streams, and fans out (docs/16 D91). Topics: `ingests`, `findings`, `operations`; a message carries no data and the page refetches. | The right mechanism, and it does not carry feed or analysis changes yet. |

## 5. The plan

Four slices, each with its own tests; none is started.

**A. Make the button true, or take it out (first, because it is wrong today).**
`POST /api/v1/applications/{id}/refresh-vulnerabilities` asks every analyzer that is on to analyse the newest SBOM of each asset of the application
(`ListApplicationAssets`, then `Service.DispatchAsset`), triager role on the application, and answers what it did: `202 {queued, already_running,
analyzers}`. Rename it in the UI to **Check again** and make it say what happened ("queued 2", "already running since 14:02", "nothing to check: no SBOM",
"analysis is switched off"). Tests: the real call queues; a second call while the first is pending queues nothing and says so; a viewer is refused.

**B. The freshness section on the application page (read only).**
One `GET /api/v1/applications/{id}/freshness` (viewer), one small payload:
`feeds: [{name, last_sync, status, error}]` (global; labelled as such), `analyzers: [{name, kind, state, last_analysed_at, findings, created, closed, error,
in_progress_since}]` for the newest SBOM of the application (from `sbom_analysis`), `sbom: {at, components}`, and `rescored_at`. Each date says what it is
(section 3, condition 1). No new table: the rows exist. Tests: with no SBOM, with a failed analyzer (error shown, findings kept), with an analysis in
flight, and tenant isolation on PostgreSQL.

**C. No polling by hundreds of viewers: use the live stream.**
Add a live topic (`operations` already exists; `analysis` is clearer) written when an analysis starts or ends and when a feed round starts or ends, with the
application id for the analysis (nil, tenant-wide, for a feed). The page refetches once on the event, as the other pages do. Remove the 2 s polling of the
Feeds page, keep a 30 s fallback poll only when the stream is down (`useLiveEvents` already has one, `POLL_MS`). Cost: one row per transition, read once
per replica. Tests: the topic is accepted by the stream, an analysis end writes one event for its application, and the page refetches on it.

**D. Limits, so that a crowd cannot flood the analyzers.**
1. **Single flight, already there**, but make it visible (`in_progress_since`, who started it) so the second person sees "running" instead of pressing.
2. **A cooldown after a manual check of the same application** (default 5 minutes from the last *completed* manual analysis; the answer says when it ends),
   configurable as `analysis.manualCooldown`. A person who needs it sooner uploads again (an upload is not limited by it), as in Dependency-Track.
3. **A cap on manual work in flight** next to the sweep's: manual requests count against `analysis.maxInFlight` too, but are admitted first (priority 1);
   above the cap the answer is `429` with `Retry-After`, using the token-bucket limiter the API already has (D-series quotas), not a new mechanism.
4. **Feeds:** the Sync button disabled for everyone while a round runs (the state is shared through C), a message naming who started it and when.

## 6. Open questions for the owner

1. Should "Check again" be allowed for a **triager** on the application (as the old button was) or an administrator only (as the analyzers' own button is)?
   Recommendation: triager, because it is one application, with the cooldown of D.2.
2. Should the freshness section show the **feeds** at all on an application page, given section 3, condition 1? Recommendation: yes, collapsed under the
   analyzers, with the sentence "shared by every application".
3. Cooldown of 5 minutes: is that the right order for an analyzer with a daily quota?
4. Slice A first and alone? Recommendation: yes; it removes a button that lies and needs no new screen.

## 7. What was and was not checked

Checked: the code paths in section 1 (read, with file names), the live stream's design, the existing claim, the Dependency-Track statements in section 2 as the
search summarised them. **Not checked:** how many requests the feeds endpoint costs under real load (the 150 a second is arithmetic, not a measurement); the
Dependency-Track pages in full, and its UI for the last analysis time; how the quota of a real analyzer behaves (Sonatype's limits were not seen, docs/16 D142).
