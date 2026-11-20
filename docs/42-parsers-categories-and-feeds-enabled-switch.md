# 42. Parsers Categories & Feeds Enabled Option Enhancements

**Documentation of Architectural Enhancements in Releases v0.3.10 & v0.3.11**  
*Date: 2026-11-20*  
*Related Documents: [docs/04 (CRDs)](04-crds.md), [docs/13 (Frontend)](13-frontend.md), [docs/16 (Decisions D86, D88, D94)](16-implementation-decisions.md), [docs/29 (Parsers as CRDs)](29-plan-parsers-as-crds.md), [docs/33 (Vulnerability Feeds)](33-vulnerability-feeds-and-kev-architecture.md).*

---

## 1. Executive Summary

This document records two major operational and architectural enhancements implemented in Rampart:
1. **Parsers Category Sub-Tabs & Filtering (`v0.3.10`)**: Categorizing report parsers into dedicated sub-tabs (SAST, SCA, Secrets, IaC & Cloud, DAST, Compliance, VEX) with live counts, search filtering, and brand alignment.
2. **Feeds Declarative `enabled` Switch Support (`v0.3.11`)**: Enabling explicit declarative control (`enabled: true / false`) for every feed in the `ClusterFeed` CRD without requiring dummy mirror URLs, syncing frontend manifest generation, and surfacing clear `Enabled` / `Disabled` status indicators in the UI inspector.

---

## 2. Report Parsers: Category Sub-Tabs & UI Organization (v0.3.10)

### 2.1 Context & Problem
In earlier iterations, parsers were nested under the Ingestion route. When Parsers was promoted to a dedicated primary navigation item (`/parsers`), Report Parsers, SBOM Parsers, and Analyzers were split into top-level tabs. However, the report parser catalog (covering Semgrep, Trivy, Gitleaks, Checkov, ZAP, etc.) was rendered as a flat list, making it difficult for security teams to quickly locate and filter parsers by their security domain.

### 2.2 Category Architecture & Sub-Tabs
In `web/src/routes/parsers/ParserList.tsx`, dynamic sub-tabs were introduced to partition report parsers by their functional category:

| Category Key | Category Label | Matching Domains / Engines |
|---|---|---|
| `all` | **All** | Entire active catalog with total parser count badge |
| `sast` | **Static Analysis (SAST)** | Source code analysis (e.g. Semgrep, SonarQube, Bandit, Brakeman) |
| `sca` | **Software Composition (SCA)** | Open-source dependency analysis (e.g. Trivy, Snyk, Grype, Dependency-Track) |
| `secrets` | **Secret Detection** | High-entropy secrets and credentials (e.g. Gitleaks, TruffleHog) |
| `iac` | **IaC & Cloud** | Infrastructure as Code & misconfigurations (e.g. Checkov, tfsec, KICS) |
| `dast` | **Dynamic Analysis (DAST)** | Web application dynamic scans (e.g. OWASP ZAP, Burp Suite) |
| `compliance` | **Compliance & Benchmarks** | Hardening & audit frameworks (e.g. OpenSCAP, Kube-bench) |
| `vex` | **Vulnerability Exploitability (VEX)** | Machine-readable VEX statements (e.g. OpenVEX, CSAF) |

### 2.3 Interactive Search & Count Badges
- **Live Counts**: Each sub-tab dynamically displays the number of active parsers in that category: `<span className="badge">{count}</span>`.
- **Compound Filtering**: Search queries (by parser name, description, or family) filter strictly within the selected category sub-tab.
- **Empty States**: If a category or search yields no matches, contextual empty states guide the user to clear filters.

### 2.4 Brand Wordmark Alignment
- Updated `web/src/components/Logo.tsx` and English localization (`web/src/lib/i18n/en.ts`) to ensure uniform capitalization for the Rampart brand wordmark: **`Rampart`** (capitalized 'R').

---

## 3. Vulnerability Intelligence & Feeds: Declarative `enabled` Switch (v0.3.11)

### 3.1 Advisory Sources & CVE Writeup Clarification
During threat intelligence reviews, the source of detailed package CVE advisory writeups (such as `multer` CVE-2022-24434 / GHSA-g5hq-p3nh-g8gq containing `Impact`, `Patches`, `Workarounds`, `References`, CVSS, and EPSS) was audited:
- **Markdown Writeups**: Delivered by OSV (Open Source Vulnerabilities) and GitHub Security Advisories (`GHSA`), imported via `ClusterFeed` into `vulnerability.description` and `vulnerability.source_payloads`.
- **Exploitation Intelligence**: Sourced from CISA KEV and VulnCheck KEV (`vulnerability.kev`, `kev_date_added`, `kev_due_date`, `kev_ransomware`).
- **Exploit Prediction Probabilities**: Computed from FIRST EPSS (`vulnerability.epss_score`, `epss_percentile`).
- **Standardized Severity & Weaknesses**: Sourced from NIST NVD and CISA Vulnrichment (`cvss_v31`, `cvss_v40`, CWE taxonomies).

### 3.2 The Need for Declarative `enabled` Control
Previously, `epss` and `kev` in `ClusterFeed` CRD schemas had `required: [url]`. If an administrator wanted to disable KEV or EPSS in their cluster via GitOps, writing:
```yaml
spec:
  kev:
    enabled: false
```
would fail Kubernetes OpenAPI schema validation with `missing required field: url`, and Go's `ParseFeedMirrorSpec` would reject it with `kev.url must be an http(s) URL, got ""`. Furthermore, the frontend manifest generator (`buildManifest`) omitted the `enabled` field entirely, printing empty `{}` blocks or omitting disabled state in YAML exports.

### 3.3 Changes Implemented

#### 1. CRD & Schema Synchronization
- In `deploy/crds/clusterfeed.yaml` and `deploy/helm/rampart/crds/clusterfeed.yaml`:
  - Removed `required: [url]` from `epss` and `kev`.
  - Added full schema validation support for `enabled: boolean` across all feed blocks (`nvd`, `osv`, `epss`, `kev`, `vulnrichment`, `exploitdb`, `metasploit`, `euvd`, `vulncheckKev`, `custom[].enabled`).
- Re-bundled and validated CRD bundle:
  ```bash
  python3 hack/crds-bundle.py
  python3 hack/crds-bundle.py --check
  ```

#### 2. Go Backend Domain Parser
- In `internal/domain/feed_mirror.go` (`ParseFeedMirrorSpec`):
  - Updated validation logic to accept `src.URL == ""` whenever `src.Enabled != nil`:
    ```go
    for name, src := range map[string]*FeedMirrorSource{"epss": s.EPSS, "kev": s.KEV} {
        if src == nil {
            continue
        }
        if src.Schedule != "" {
            return nil, fmt.Errorf("clusterfeedmirror: %s.schedule is not built; every feed runs every feeds.interval", name)
        }
        if src.URL == "" && src.Enabled == nil {
            return nil, fmt.Errorf("clusterfeedmirror: %s.url must be an http(s) URL, got %q", name, src.URL)
        }
        if src.URL != "" && !httpURL(src.URL) {
            return nil, fmt.Errorf("clusterfeedmirror: %s.url must be an http(s) URL, got %q", name, src.URL)
        }
    }
    ```
- In `internal/domain/feed_mirror_test.go`:
  - Added unit test cases confirming specs with `{"kev": {"enabled": false}}` and `{"epss": {"enabled": false}}` without mirror URLs parse successfully.

#### 3. Frontend Types & Manifest Generator
- In `web/src/api/types.ts`:
  - Added `enabled?: boolean` across all sources in `FeedMirrorSpec`.
- In `web/src/routes/feeds/manifest.ts`:
  - Updated `buildManifest(mirror)`:
    ```typescript
    for (const key of SOURCES) {
      const v = m[key] as Sourced | undefined;
      if (!v) continue;
      lines.push(`  ${key}:`);
      if (v.enabled !== undefined) lines.push(`    enabled: ${v.enabled}`);
      if (v.url) lines.push(`    url: "${v.url}"`);
      if (v.tokenFile) lines.push(`    tokenFile: "${v.tokenFile}"`);
      if (!v.url && !v.tokenFile && v.enabled === undefined) lines.push('    {}');
    }
    ```
  - Added custom feeds `enabled: ${c.enabled}` output formatting.
- In `web/src/routes/feeds/manifest.test.ts`:
  - Added unit tests verifying `enabled: false` and `enabled: true` in the output YAML.

#### 4. UI Inspector & Visual Indicators
- In `web/src/routes/feeds/FeedInspector.tsx`:
  - Surfaced an explicit status pill in the inspector header:
    - **`Enabled`** (green pill: `bg-success/15 text-success`)
    - **`Disabled`** (gray pill: `bg-surface-3 text-ink-2`)
- In `web/src/lib/i18n/en.ts`:
  - Registered translation tokens `feeds.enabled` and `feeds.disabled`.

#### 5. Presets & Default Manifests
- Updated `deploy/presets/clusterfeed-default.yaml` and `deploy/compose/resources/default-resources.yaml` to declare `enabled: true` explicitly across all feeds as reference documentation.

---

## 4. Verification Battery & Evidence

All changes were strictly verified against Rampart's verification cycle:

| Verification Suite | Target | Status | Notes |
|---|---|---|---|
| **CRD Bundle Check** | `python3 hack/crds-bundle.py --check` | **PASS** | 24 CRDs verified and bundled |
| **Backend Race Tests** | `go test -race ./internal/domain/... ./internal/query/...` | **PASS** | All domain and query tests passed cleanly |
| **Helm Lint** | `helm lint deploy/helm/rampart` | **PASS** | 0 chart failures on `0.3.11` |
| **Frontend TypeScript** | `npm run typecheck` (`tsc --noEmit`) | **PASS** | 0 type errors across whole codebase |
| **Frontend Linter** | `npm run lint` (`eslint`) | **PASS** | 0 warnings, 0 errors |
| **Frontend Unit Tests** | `npm test` (`vitest run`) | **PASS** | 42 test files, 301/301 tests passing |
| **Production Build** | `npm run build` (`vite build`) | **PASS** | Production bundles generated without issues |

---

## 5. Git Commit & Release History

- **v0.3.10**: Commit `959d9bf` — Report Parsers dynamic category sub-tabs (`sast`, `sca`, `secrets`, `iac`, `dast`, `compliance`, `vex`), unit tests, and brand capitalization.
- **v0.3.11**: Commit `8a7e23f` — Declarative `enabled` option support across `ClusterFeed` CRD schema, Go backend, manifest generator, and UI inspector status badges.
