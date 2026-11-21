# 46. Unified Scanner Evidence Pipeline & Dynamic Key-Value UI

This document describes the design and implementation of Rampart's unified, lossless scanner evidence ingestion pipeline and declarative, auto-adaptive UI presentation system (Decision D147).

---

## 1. Problem Statement

Security scanners produce diverse, domain-specific evidence that traditional vulnerability management platforms discard:
- **Secret Scanners (Gitleaks, TruffleHog)**: Commit hash, author name, author email, commit timestamp, Shannon entropy, secret fingerprints.
- **SAST Analyzers (Semgrep, SARIF)**: Execution paths, code snippets, suggested fixes, confidence levels, rule documentation URLs.
- **DAST Tools (Nuclei, ZAP)**: HTTP methods, attack vectors, curl reproducer commands, extraction matchers.
- **Cloud & IaC (Checkov, Kube-bench, Prowler)**: Remediation scripts, benchmark tests, resource ARNs, audit commands.
- **SCA / Container (Trivy, Grype, Snyk)**: Container layer IDs, multi-vendor CVSS ratings, advisory references.

Hardcoding these tool-specific fields in Go structs or TypeScript interfaces breaks the extensible Kubernetes CRD architecture of Rampart, requiring new code releases whenever a scanner is added.

---

## 2. Architecture: Lossless Ingestion & Zero-Hardcoding

### A. Domain Entities Synchronization
`RawFinding` was augmented with generic attributes and raw payload fields across both the core platform (`defectdojo`) and the standalone parsers repository (`parsers`):

```go
type RawFinding struct {
    // Canonical core fields
    RuleID       string          `json:"rule_id"`
    Title        string          `json:"title"`
    Severity     Severity        `json:"severity"`
    Location     Location        `json:"location"`
    // Generic dynamic data
    Attributes   map[string]any  `json:"attributes,omitempty"`
    RawPayload   json.RawMessage `json:"raw_payload,omitempty"`
}
```

### B. Lossless Occurrence Storage
In `internal/ingest/merge.go`:
- `occurrence.raw` stores the complete raw scanner payload as JSONB.
- `occurrence.normalized` stores extracted key-value pairs as JSONB. Sensitive secrets (`secret`, `secret_value`) are automatically redacted before storage.

---

## 3. Declarative CRD Control (`spec.display`)

`ClusterParser` and `Parser` CRDs support an optional `spec.display` block:
```yaml
spec:
  display:
    title: "Gitleaks Secret Scanner"
    icon: "key"
    summary: "Git repository secret and credential detection"
    highlightedAttributes:
      - "commit"
      - "author"
      - "entropy"
    attributeLabels:
      commit: "Commit Hash"
      author: "Commit Author"
```

---

## 4. Smart Auto-Adaptive UI (`ScannerEvidenceSection.tsx`)

Mounted directly in `web/src/features/finding-inspector/Inspector.tsx`:
1. **Multi-Scanner Occurrence Switcher**: If multiple tools detect the same vulnerability, analysts can seamlessly toggle between tools.
2. **Smart Type Inference**:
   - **URLs**: Clickable external links with icon (`↗`).
   - **Emails**: `mailto:` links.
   - **Hashes / Commits / PURLs / ARNs**: Monospace typography with one-click copy button.
   - **Markdown / Multiline Scripts**: Rendered via `MarkdownView`.
   - **Booleans & Statuses**: Distinct status badges.
3. **Interactive Raw Record Inspector**:
   - Collapsible panel displaying the formatted JSON payload with a one-click "Copy Raw JSON" button.
