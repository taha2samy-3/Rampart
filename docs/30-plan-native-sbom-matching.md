# 30. Plan: take Dependency-Track out; an SBOM upload becomes findings inside Rampart

Status: plan, nothing built. Written 2026-11-18 from a read of the code and public documentation. Items marked UNVERIFIED were not checked.

## 1. The idea

Today a Rampart user who wants component vulnerabilities runs Dependency-Track (DT); Rampart pulls DT's findings (D92). The owner's idea: the user uploads an SBOM to Rampart; a dedicated SBOM parser (a resource, like docs/29, because an SBOM is a component graph and not a list of CVEs) reads it; Rampart itself matches the components to vulnerabilities, keeps the inventory, and re-matches when the vulnerability data changes. DT is no longer needed.

This **reverses a standing decision**: docs/16 line 617 (D23, with docs/10 and ADR 0006) says "Vulnerability analysis stays in Dependency-Track ... Rampart does not write its own matcher." The owner has chosen to revisit it, so this plan lists what changes (section 9).

## 2. What DT does for Rampart today

Verified by reading the code. DT's footprint is **smaller than docs/10 describes**.

The client (`internal/upstream/dependencytrack/client/client.go`) calls only: the permission probe `/team/self`, `/project` (list, one, properties), `/finding/project/{uuid}` and `/metrics/project/{uuid}/current`. It does not call `/component`, `/bom`, `/violation`, `/license`, and it never uploads a BOM. So licence data, outdated-version data, policy violations and BOM upload, which docs/10 lists as DT's role, are **not built** and need no replacement.

What Rampart does use from DT:

1. **Vulnerability matching**: the findings (component, vulnerability id and aliases, severity, CVSS, CWE, recommendation, analysis state with suppression).
2. **Re-analysis**: DT re-matches when its data changes, and Rampart syncs (a schedule every 30 minutes, a webhook).
3. **Project to application mapping**: seven rules, the implicit `isLatest` version, a manual map (D92).
4. **Analysis decisions** as VEX-like states, kept as `dtrack_decision` and the `upstream_decision` timeline entry (D92 DT5). Nothing is written back to DT.

For comparison, DT's own analyzers (public documentation): the internal analyzer matches against a database DT mirrors from NVD, GitHub Advisories and OSV, by CPE for NVD (following the NIST CPE name matching specification) and by purl for GitHub Advisories and OSV; a component with neither CPE nor purl is not evaluated. OSS Index, Snyk and Trivy are optional external analyzers.

## 3. What Rampart already has

| Piece | State |
|---|---|
| SBOM readers | CycloneDX, SPDX, Syft: `ParseSBOM` returns the SBOM, its components and the dependency graph (`internal/sbom/readers/{cyclonedx,spdx,syft}`) |
| SBOM storage | tables `sbom` and `sbom_component` (ref, purl, `purl_base`, name, version, licences, scope, direct, hashes), index on `(tenant_id, purl_base)`; per track since migration 00045 |
| Upload | `POST /ingest/v1/sbom` then `processor.saveSBOM` (whole document in memory, up to 256 MiB; ephemeral runs skip it) |
| Inventory | components of the latest SBOM per asset, searchable; the "SBOM packages" tab |
| Vulnerability tables | `vulnerability` (aliases, CWEs, CVSS, EPSS, KEV, SSVC, exploit maturity, `affected` JSONB, `fixed_versions`), `vulnerability_alias`, `vulnerability_exploitation`, local variants |
| Feeds | KEV, EPSS, NVD, OSV (per ecosystem, opt in; full mode defaults to Go, npm, PyPI, Maven), exploitation feeds, mirrors, custom feeds; a hook after every sync (`OnSynced`) |
| VEX | OpenVEX and CycloneDX VEX import, OpenVEX export, `not_affected` triage, carry-over between tracks (D57) |
| Purl | `normalize.CanonicalPURL` |
| Re-key precedent | `internal/ingest/rekey.go` (D50) |

**Nothing matches components to vulnerabilities today** (found by absence: no reader of `vulnerability.affected` in `query`, `store`, `scoring`, `risk`). The "scan a package" call only re-scores.

## 4. The gaps

1. **A queryable affected-range store.** OSV's `affected[]` is stored raw in one JSONB column with no index by package. It needs a normalised table.
2. **Coverage of ecosystems.** Full mode syncs four OSV ecosystems. A matcher needs the ones SBOMs contain (OSV publishes a list at `gs://osv-vulnerabilities/ecosystems.txt`).
3. **Version comparison per ecosystem**: semver, Maven, PEP 440, npm, Go, NuGet, RubyGems, crates, deb, rpm, apk. None exists.
4. **Purl and name normalisation per ecosystem** (PyPI names, Maven group and artifact, npm scopes, Go module paths, distro and source package for OS packages).
5. **CPE matching** for components that have no ecosystem advisory (NVD): no CPE data is ingested today.
6. **A re-match job** when the vulnerability data changes.
7. **False-positive control** beyond VEX: withdrawn advisories, same name in two ecosystems, distro backports.
8. **Scale**: the SBOM is read whole; no measurement exists of the matcher join at tenant scale.
9. **Finding identity**: see section 6.

## 5. How the industry does it (what to copy)

- **OSV schema** (public): a range has `type` SEMVER, ECOSYSTEM or GIT and ordered events `introduced`, `fixed`, `last_affected`; `introduced: "0"` means from the start; the vulnerable interval includes the introduced version and stops before the fixed one; a version is affected if it is in any range or in the explicit `versions` list. GIT ranges need the repository's commit graph, so a component matcher uses SEMVER and ECOSYSTEM ranges and the versions list.
- **Grype** (Anchore's architecture notes): a provider finds candidate vulnerabilities for a package, then the matcher compares versions against the constraints, then checks the "unaffected" records; there are matchers per package type, distro-aware matching, and a CPE fallback that its own documentation says can produce false positives. It separates exact matches from CPE matches in the output. This is the shape to copy: candidates by index, then version comparison, then exclusions, and CPE as a labelled lower-confidence path.
- **Dependency-Track**: purl for ecosystem advisories, CPE for NVD, results cached per identifier.

Licences: OSV.dev's data page lists a licence per upstream source (GitHub Advisory Database CC-BY 4.0; RustSec and the Global Security Database CC0 1.0). Using the data means keeping the attribution the licences require; this belongs in the feed documentation and the product's notices. Whether OSV's combined archives carry their own terms was not confirmed.

## 6. Architecture

### 6.1 SBOM parsers get their own resource: `SBOMParser`

The owner's decision (2026-11-18): the SBOM side has a resource of its own, not a `Parser` with a special output. The reason is the contract. A `Parser` turns a report into findings that go to the merge; an `SBOMParser` turns a document into a component graph that goes to storage (`saveSBOM`) and then to the matcher. Different output, different consumer, different validation.

- **Kinds**: `SBOMParser` (namespaced) and `ClusterSBOMParser` (shipped by the chart), like `Parser` and `ClusterParser` in docs/29. Detection (filename and content probes) and the load order (tenant over cluster over embedded) are the same.
- **Output contract**: SBOM metadata (format, spec version, serial, tool, timestamp, the described component), components (ref, purl, name, version, group, licences, scope, hashes, direct), edges (ref to ref), and optionally findings for the formats that carry them (CycloneDX VDR and VEX, which already become findings today). All of it validated by the host.
- **Runtime**: `lua`, with the host reading the document: JSON as a stream, XML as events (CycloneDX XML), tag-value as lines (SPDX). Host API: `components(path)`, `edges(path)`, `emit_component`, `emit_edge`, `set_metadata`, `emit_finding`. The Lua gate of docs/29 applies; until it passes, CycloneDX, SPDX and Syft are wrapped as `runtime: native` so nothing changes.
- `saveSBOM` stops choosing a reader by a substring of the parser id and uses the resource the upload matched. The SBOM stays separate from `RawFinding`, as it already is.
- **Open**: whether the matcher needs its own resource too (which ecosystems, whether CPE is on, the confidence labels shown): suggested `SBOMMatchPolicy`, cluster-scoped with a tenant override, decided in Phase 1 when the matcher exists.

### 6.2 The vulnerability knowledge base

A normalised table, filled by the OSV feed, for example `vuln_affected(vulnerability_id, ecosystem, package_name_normalised, purl_base, range_type, introduced, fixed, last_affected, versions[], withdrawn)` with an index on `(ecosystem, package_name_normalised)` and on `purl_base`. The raw record stays in `vulnerability.affected`. Phase 2 adds `vuln_cpe` from NVD `configurations` for components without an ecosystem advisory.

### 6.3 The matcher

A package `internal/match`, with no database access of its own (it takes a lookup interface, so it is testable with in-memory data):

1. Normalise the component: purl to ecosystem and name.
2. Candidates by index.
3. Compare the version per ecosystem.
4. Remove the unaffected and the withdrawn.
5. Emit a match with a confidence: `exact` (ecosystem advisory) or `cpe` (labelled "possible").

Version comparators: use maintained libraries instead of writing them. Candidates, from memory and **UNVERIFIED (licence and API must be checked before adoption)**: Go `golang.org/x/mod/semver` (confirmed to exist; semver only), the version libraries Trivy publishes for deb, rpm, apk, npm, PEP 440, Maven and RubyGems, and Google's OSV tooling (`osv-scanner`, `osv-scalibr`, Apache-2.0). The search did not confirm which comparator each of those uses.

### 6.4 The pipeline

A River job `sbom_match` per (asset, track):

1. Enqueued by `saveSBOM` when an SBOM is stored, and by a re-match trigger (below).
2. Reads `sbom_component` for the latest SBOM of that asset and track.
3. Runs the matcher.
4. Emits `RawFinding`s (category SCA, a new scanner family such as `rampart-sca`, `Package.DependencyPath` from `sbom.dependencies`) through the existing `ingest.Engine`, so merge, idempotency, the mass-close guard and closing when a component is removed or upgraded all come for free.

**Re-matching** when the data changes: the `OnSynced` hook after a feed sync gives the changed vulnerability ids, which give `purl_base` values, which give the distinct `(asset, track)` that contain them (the `(tenant_id, purl_base)` index exists), and one `sbom_match` is enqueued for each. A periodic sweep covers anything missed.

**Ephemeral runs and the CI gate**: ephemeral runs do not store an SBOM today. For a pull request the gate matches from the uploaded document in memory and returns the result without saving.

### 6.5 Finding identity

The key includes the scanner family, so native findings have new keys and sit beside DT, Trivy and Grype findings of the same issue. D24 correlation shows them as "also reported by" and never merges them. During the migration there is a double-count window. Options: (a) accept it and close DT's findings when DT is switched off (the rekey job, D50, is the precedent for a family migration); (b) give native findings the family of the tool that reported the same issue (not recommended: it hides where a finding came from).

## 7. Validation: how to know it is as good as DT

The risk is not the code; it is the data and the edge cases DT has had years to tune.

1. **A corpus**: 15 to 20 real SBOMs (the owner's demo repository, plus open-source projects in several ecosystems), kept in the repository as test data.
2. **A differential test**: for each, the native matcher against DT, Grype, Trivy and osv-scanner on the same SBOM. Record, per tool, the set of (component, vulnerability) pairs; list the differences; triage each as a bug in the matcher, a data gap, or a false positive in the other tool.
3. **A threshold, agreed before starting** (suggested: the native matcher finds at least 98% of the vulnerabilities that at least two of the other tools agree on, in the ecosystems it claims to support, and every difference is explained).
4. **Shadow mode**: for two releases the native matcher runs beside DT and produces a comparison report but no findings.

## 8. Phases

| Phase | What | Exit |
|---|---|---|
| 0 | Corpus and differential harness; the normalised `vuln_affected` table filled from OSV for the target ecosystems; matcher for semver-like ecosystems first | harness reports numbers |
| 1 | All target ecosystems and their comparators; the `sbom_match` job; re-match after feed sync; shadow mode | threshold met in shadow |
| 2 | Findings on by default for new SBOM uploads (family `rampart-sca`); DT stays; dependency path on findings; CPE matching as a labelled lower-confidence path, off by default | one release without a regression |
| 3 | Deprecate DT: stop offering it in the UI, keep the webhook route for one release, document the removal of the ScanSource fields; export `dtrack_decision` and the `upstream_decision` entries first (they are the only record of DT triage) | |
| 4 | Remove DT: client, sync, webhook, `dtrack_*` tables, the CRD fields and connector type, the UI view; the DT file format reader (FPF) stays as a file importer | |

## 9. What changes outside the code

Decision and docs to revise: docs/16 D23 (line 617), D74, D92, D70 part B, the scope notes at lines 617 and 2107; docs/10 (the DT document), 01, 02, 04 (ScanSource and Connector kinds), 05, 06, 09, 11, 12, 15, 19, 20 to 23, 25, 26, 28; `adr/0006-dependency-track-first-class.md` and `adr/0002`; the README and `docs/images/dependency-track-*.svg`. Docs 19 to 23 were only searched, not read.

Compatibility: customers' DT instances call `/hooks/dependency-track/{id}`: keep it for one release. Removing the `dependencyTrack`, `connector` and `schedule` fields of `ScanSource` and the DT `Connector` type is a breaking CRD change: give it a deprecation window. Findings created from DT keep their keys and are no longer refreshed.

## 10. What Rampart would lose and gain

Loses: DT's years of tuning of CPE matching; the optional commercial sources (OSS Index, Snyk, VulnDB) unless a feed brings them; DT's UI (not used by Rampart). Gains: one system and one data path; no JVM service to run, secure and upgrade; matching on data Rampart already holds (KEV, EPSS, exploitation feeds) so scoring and matching agree; results when the SBOM arrives, not after a sync; the SBOM per track and the inventory in one model; a matcher that works air-gapped from a mirror (the feed mirror and `egress: deny` already exist).

## 11. Decisions needed from the owner

1. Confirm that D23 is reversed, and whether DT stays as an optional connector after Phase 4 or goes entirely (the plan assumes it goes, with FPF import kept).
2. Which ecosystems to support first (suggested: npm, PyPI, Maven, Go, then NuGet, RubyGems, crates; OS packages by distro in a later step).
3. Whether CPE matching is in scope at all (it is where false positives come from).
4. The acceptance threshold of section 7.
   (Decided 2026-11-18: SBOM readers are `SBOMParser` resources and run in Lua once the Lua gate of docs/29 passes.)
5. The family name of native findings, and whether the double-count window is accepted.
6. Attribution for the OSV and GitHub Advisory data.

## 12. To verify before building

- Which comparator libraries to adopt, their licences and their handling of each ecosystem's version rules.
- Whether OSV records carry purls for each ecosystem (the schema allows it; real data varies), and what happens to name normalisation when they do not.
- Which distro advisories OSV covers and how its Debian, Alpine and Ubuntu records name the source package.
- The size of `sbom_component` and the matcher join at realistic tenant scale (nothing is measured).
- How many SBOMs exceed the 256 MiB limit or its memory cost; whether `saveSBOM` needs to stream.

## 13. Implementation Record: SBOMParser CRDs & Hybrid Pluggable Analyzer Engine (2026-11-18)

In accordance with architectural decisions:

1. **Dedicated CRD Definitions:**
   - `ClusterSBOMParser` & `SBOMParser` (`deploy/crds/{clustersbomparser,sbomparser}.yaml` and Helm mirrors): Decouples SBOM component and dependency graph ingestion from vulnerability findings.
   - `ClusterExternalAnalyzer` & `ExternalAnalyzer` (`deploy/crds/{clusterexternalanalyzer,externalanalyzer}.yaml` and Helm mirrors): Configures external analyzer microservices with `service.name`, `service.namespace`, `service.port`, or `endpoint`.
   - Updated operator RBAC permissions and verified `diff -r deploy/crds deploy/helm/rampart/crds` and `helm lint`.

2. **WASM Streaming SBOM Parser (`parsers/wasm/sbom-cyclonedx`):**
   - Implemented streaming CycloneDX 1.2–1.6 parser emitting JSONL events to `stdout`:
     - `metadata`: format, version, timestamp, root application ref.
     - `component`: package purl, canonical purl_base, licenses, hashes.
     - `edge`: parent-to-child relationships with direct vs. transitive classification.
     - `vulnerability`: optional embedded VDR/VEX findings toggled via `EXTRACT_VULNERABILITIES`.
   - Tested in Wazero sandbox with real-world enterprise SBOMs (OWASP Juice Shop 726KB with 841 components, Dropwizard 380KB with 168 components and 170 edges).

3. **Hybrid Vulnerability Analyzer Architecture:**
   - **In-Process Matcher (`internal/analyzer/matcher`):** Fast, local Go engine matching components against OSV and vulnerability definitions in PostgreSQL using canonical PURL base and ecosystem version comparison.
   - **External Analyzer gRPC Protocol (`pkg/api/analyzer/v1/analyzer.proto`):** High-performance Protobuf contract supporting `Analyze`, `GetMetadata`, and `HealthCheck`.
   - **Rampart gRPC Client (`internal/analyzer/client`):** Connects to external analyzer containers with connection pooling, timeouts, and automatic finding mapping to `domain.RawFinding`.
   - **Reference External Analyzer Container (`examples/external-analyzer/`):** Complete runnable gRPC server, multi-stage `Dockerfile`, and Kubernetes deployment manifest.
