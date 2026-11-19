# 31. Supported Parsers and Format Versions Specification

This document defines the supported schemas, vendor tool versions, CLI generation flags, and format detection signatures for all 21 Rampart parsers.

Following the **"All Come In Front Door"** architectural principle (docs/29, D127), every parser is deployed as a `ClusterParser` or `Parser` Custom Resource without hardcoded version constraints or family duplication.

---

## 1. Quick Reference Matrix

| # | Parser | Runtime | Category | Supported Standard / Tool Versions | Detection Signature (Filenames & Probes) |
|---|---|---|---|---|---|
| 1 | **`sarif`** | `wasm` | SAST | OASIS SARIF 2.1.0 Standard | `*.sarif`, `*sarif*.json` \| `runs`, `version` |
| 2 | **`cyclonedx`** | `wasm` | SCA / VEX | CycloneDX 1.4, 1.5, 1.6 (JSON & XML) | `*cyclonedx*`, `*.cdx.json`, `*.cdx.xml` \| `bomFormat` |
| 3 | **`spdx`** | `wasm` | SCA | SPDX 2.2, 2.3 (JSON & Tag-Value) | `*.spdx`, `*.spdx.json` \| `spdxVersion` |
| 4 | **`syft`** | `wasm` | SCA | Syft JSON Schema v1.0.0 through v16.x | `*syft*.json` \| `descriptor`, `artifacts` |
| 5 | **`openvex`** | `wasm` | SCA / VEX | OpenVEX Spec 0.2.0 | `*vex*.json` \| `@context: openvex.dev` |
| 6 | **`trivy`** | `wasm` | Container / SCA | Trivy JSON Schema v2 (Trivy 0.20+) | `*trivy*.json` \| `SchemaVersion: 2`, `Results` |
| 7 | **`grype`** | `wasm` | SCA | Anchore Grype JSON (Grype 0.50+) | `*grype*.json` \| `matches`, `source` |
| 8 | **`semgrep`** | `wasm` | SAST | Semgrep JSON (Semgrep 0.40+) | `*semgrep*.json` \| `results`, `check_id` |
| 9 | **`gitleaks`** | `wasm` | Secret | Gitleaks JSON (Gitleaks 8.0+) | `*gitleaks*.json` \| `RuleID`, `StartLine`, `File` |
| 10 | **`trufflehog`**| `wasm` | Secret | TruffleHog v3 JSON / JSONL | `*trufflehog*.json*` \| `SourceMetadata`, `Raw` |
| 11 | **`dependencytrack`** | `wasm` | SCA | DTrack Findings JSON / FPF 1.x | `*.fpf`, `*findings*.json` \| `component`, `vulnerability` |
| 12 | **`checkov`** | `wasm` | IaC | Bridgecrew Checkov JSON (v2.x, v3.x) | `*checkov*.json` \| `check_type`, `results` |
| 13 | **`snyk`** | `wasm` | SCA | Snyk CLI Test JSON (Snyk 1.x+) | `*snyk*.json` \| `vulnerabilities`, `packageManager` |
| 14 | **`kubebench`** | `wasm` | Compliance | kube-bench CIS JSON (CIS 1.5 - 1.8+) | `*kube-bench*.json` \| `Controls`, `tests` |
| 15 | **`prowler`** | `wasm` | CSPM | Prowler v3 / v4 JSON & OCSF | `*prowler*.json` \| `CheckID`, `ServiceName` |
| 16 | **`gitlab`** | `wasm` | SAST / DAST | GitLab Security Report Schemas 14.x, 15.x | `gl-*-report*.json` \| `scan`, `vulnerabilities` |
| 17 | **`dependencycheck`** | `wasm` | SCA | OWASP Dependency-Check JSON Schema 1.1 | `*dependency-check*.json` \| `reportSchema: 1.1` |
| 18 | **`bandit`** | `lua` | SAST | PyCQA Bandit JSON (Bandit 1.6+) | `*bandit*.json` \| `results`, `metrics` |
| 19 | **`zap`** | `lua` | DAST | OWASP ZAP 2.x JSON Report | `*zap*.json` \| `site`, `@programName: ZAP` |
| 20 | **`nuclei`** | `lua` | DAST | ProjectDiscovery Nuclei JSONL (v2, v3) | `*nuclei*.json*` \| `template-id`, `info` |
| 21 | **`genericjson`**| `lua` | Generic | Rampart Generic v1 / DefectDojo Generic | `*generic*.json` \| `findings`, `rampart-generic` |

---

## 2. Detailed Specifications per Parser

### 1. SARIF (`parsers/wasm/sarif`)
- **Documentation**: [OASIS SARIF v2.1.0 Standard](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- **Supported Formats**: OASIS Static Analysis Results Interchange Format (SARIF) 2.1.0 JSON.
- **Generation Command**:
  - Semgrep: `semgrep scan --sarif -o results.sarif`
  - Trivy: `trivy image --format sarif -o results.sarif <image>`
  - Checkov: `checkov -d . -o sarif > results.sarif`
  - GitHub CodeQL: `codeql database analyze ... --format=sarif-latest --output=results.sarif`
- **Extracted Fields**:
  - `rule_id`: `result.ruleId` (resolved against `tool.driver.rules`)
  - `title`: `rule.shortDescription` or `result.message.text`
  - `location`: `result.locations[0].physicalLocation.artifactLocation.uri`, `region.startLine`
  - `severity`: mapped from `rule.defaultConfiguration.level` or `result.level` (`error` -> high/critical, `warning` -> medium, `note` -> low/info).
  - `cwes`: extracted from `rule.relationships` (CWE taxonomy references)

### 2. CycloneDX (`parsers/wasm/cyclonedx`)
- **Documentation**: [OWASP CycloneDX Specifications](https://cyclonedx.org/specification/overview/)
- **Supported Versions**: CycloneDX v1.4, v1.5, v1.6 in JSON and XML.
- **Document Types**: Software Bill of Materials (SBOM), Vulnerability Disclosure Report (VDR), and VEX.
- **Generation Command**:
  - Syft: `syft <target> -o cyclonedx-json=bom.cdx.json`
  - Trivy: `trivy image --format cyclonedx -o bom.cdx.json <image>`
  - cdxgen: `cdxgen -o bom.cdx.json`
- **Extracted Fields**:
  - `vuln_ids`: `vulnerability.id` (CVE, GHSA, OSV)
  - `location.package`: `component.purl`, `component.name`, `component.version`
  - `vex`: statements with `state` (`not_affected`, `affected`, `fixed`, `under_investigation`), `justification`, `impact`.

### 3. SPDX (`parsers/wasm/spdx`)
- **Documentation**: [Linux Foundation SPDX Specification](https://spdx.dev/specifications/)
- **Supported Versions**: SPDX 2.2 and SPDX 2.3 in JSON and Tag-Value format.
- **Generation Command**:
  - Syft: `syft <target> -o spdx-json=bom.spdx.json`
  - Trivy: `trivy image --format spdx-json -o bom.spdx.json <image>`
- **Extracted Fields**:
  - `location.package`: `package.externalRefs` (purl), `package.name`, `package.versionInfo`
  - `licenses`: `package.licenseConcluded` or `package.licenseDeclared`

### 4. Anchore Syft (`parsers/wasm/syft`)
- **Documentation**: [Anchore Syft JSON Schema](https://github.com/anchore/syft/blob/main/schema/json/)
- **Supported Versions**: Syft JSON schema v1.0.0 through v16.x.
- **Generation Command**: `syft <target> -o json=report.syft.json`
- **Extracted Fields**:
  - `artifacts`: `name`, `version`, `type`, `purl`, `licenses`, `cpes`, `locations`
  - `artifactRelationships`: component graph dependencies (`depends-on`)

### 5. OpenVEX (`parsers/wasm/openvex`)
- **Documentation**: [OpenVEX Specification](https://openvex.dev/ns/v0.2.0)
- **Supported Versions**: OpenVEX specification v0.2.0 (`@context: https://openvex.dev/ns/v0.2.0`).
- **Generation Command**: `vexctl create --vuln <CVE> --status not_affected --justification inline_mitigations_already_exist ...`
- **Extracted Fields**:
  - `statement_id`, `vuln_id`, `status`, `justification`, `impact`, `products` (subcomponents and purls)

### 6. Aqua Security Trivy (`parsers/wasm/trivy`)
- **Documentation**: [Trivy Reporting Reference](https://aquasecurity.github.io/trivy/latest/docs/references/configuration/reporting/)
- **Supported Versions**: Trivy JSON SchemaVersion 2 (Trivy v0.20.0 through latest v0.60+).
- **Generation Command**: `trivy image -f json -o trivy.json <image>` or `trivy fs -f json -o trivy.json .`
- **Extracted Sections**:
  - `Vulnerabilities`: CVE/GHSA, PURL, installed version, fixed version, CVSS, CWE
  - `Misconfigurations`: Rule ID, title, resolution, cause metadata
  - `Secrets`: Rule ID, file path, start line (secret is hashed and redacted)
  - `Licenses`: Classification and compliance status

### 7. Anchore Grype (`parsers/wasm/grype`)
- **Documentation**: [Anchore Grype JSON Documentation](https://github.com/anchore/grype)
- **Supported Versions**: Grype JSON output schema 0.x / 5.x (Grype v0.50.0 through latest v0.80+).
- **Generation Command**: `grype <target> -o json > grype.json`
- **Extracted Fields**:
  - `matches[].vulnerability.id`, `severity`, `cvss`, `fix.versions`, `artifact.purl`, `artifact.name`, `artifact.version`

### 8. Semgrep (`parsers/wasm/semgrep`)
- **Documentation**: [Semgrep CLI JSON Reference](https://semgrep.dev/docs/cli-reference/#json-output)
- **Supported Versions**: Semgrep JSON CLI format (Semgrep 0.40 through latest 1.x).
- **Generation Command**: `semgrep scan --json -o semgrep.json`
- **Extracted Fields**:
  - `results[].check_id`: canonical rule id
  - `path`, `start.line`, `start.col`, `end.line`
  - `extra.message`, `extra.severity` (`ERROR` -> high, `WARNING` -> medium, `INFO` -> low)
  - `extra.metadata.cwe`, `extra.metadata.owasp`

### 9. Gitleaks (`parsers/wasm/gitleaks`)
- **Documentation**: [Gitleaks Repository](https://github.com/gitleaks/gitleaks)
- **Supported Versions**: Gitleaks 8.0.0 through latest 8.24+.
- **Generation Command**: `gitleaks detect --report-format json --report-path gitleaks.json`
- **Extracted Fields & D42 Protections**:
  - `RuleID`: leak classification rule
  - `File`, `StartLine`, `EndLine`, `StartColumn`, `EndColumn`
  - `SecretValue`: extracted into memory solely for computing `secret_hash` (never stored in database or logs)
  - `RawPayload`: strictly redacted (`[redacted]`) to prevent credential leakage

### 10. TruffleHog (`parsers/wasm/trufflehog`)
- **Documentation**: [TruffleHog v3 Documentation](https://github.com/trufflesecurity/trufflehog)
- **Supported Versions**: TruffleHog v3.x JSON/JSONL output.
- **Generation Command**: `trufflehog git file://. --json > trufflehog.jsonl`
- **Extracted Fields**:
  - `DetectorName`, `Verified` (`secret_verified = true` when live verified), `SourceMetadata.Data.Git.file`, `line`
  - Secret value hashed and redacted per D42.

### 11. OWASP Dependency-Track (`parsers/wasm/dependencytrack`)
- **Documentation**: [Dependency-Track API & Finding Packaging Format](https://docs.dependencytrack.org/)
- **Supported Versions**: Dependency-Track v4.x Findings JSON & FPF 1.x.
- **Generation Command**: Exported from Dependency-Track API `/api/v1/finding/project/{uuid}`.
- **Extracted Fields**:
  - `vulnerability.vulnId`, `severity`, `component.name`, `component.version`, `component.purl`, `analysis.state`

### 12. Bridgecrew Checkov (`parsers/wasm/checkov`)
- **Documentation**: [Checkov Documentation](https://www.checkov.io/)
- **Supported Versions**: Checkov v2.x and v3.x JSON output.
- **Generation Command**: `checkov -d . -o json > checkov.json`
- **Extracted Fields**:
  - `check_id`, `check_name`, `file_path`, `file_line_range`, `resource` (address in Terraform/K8s/CloudFormation), `severity`, `guideline`

### 13. Snyk (`parsers/wasm/snyk`)
- **Documentation**: [Snyk CLI Test Commands](https://docs.snyk.io/snyk-cli/cli-commands/snyk-test)
- **Supported Versions**: Snyk CLI test JSON (v1.x).
- **Generation Command**: `snyk test --json > snyk.json`
- **Extracted Fields**:
  - `vulnerabilities[].id`, `title`, `severity`, `packageName`, `version`, `fixedIn`, `from` (dependency path), `identifiers.CVE`, `identifiers.CWE`

### 14. Aqua Security kube-bench (`parsers/wasm/kubebench`)
- **Documentation**: [kube-bench GitHub](https://github.com/aquasecurity/kube-bench)
- **Supported Versions**: CIS Kubernetes Benchmarks 1.5, 1.6, 1.7, 1.8.
- **Generation Command**: `kube-bench --json > kube-bench.json`
- **Extracted Fields**:
  - `Controls[].tests[].results[]`: filters `status == "FAIL"`
  - `test_number` -> `rule_id`, `test_desc` -> `title`, `remediation` -> `description`

### 15. Prowler (`parsers/wasm/prowler`)
- **Documentation**: [Prowler Cloud Security](https://github.com/prowler-cloud/prowler)
- **Supported Versions**: Prowler v3.x and v4.x JSON / OCSF formats.
- **Generation Command**: `prowler aws --json -M prowler.json`
- **Extracted Fields**:
  - `CheckID`, `CheckTitle`, `Status == "FAIL"`, `Severity`, `ServiceName`, `Region`, `ResourceId`, `ResourceArn`, `Remediation`

### 16. GitLab Security Reports (`parsers/wasm/gitlab`)
- **Documentation**: [GitLab Security Report Schemas](https://gitlab.com/gitlab-org/security-products/security-report-schemas)
- **Supported Versions**: Schema versions 14.x and 15.x for SAST, DAST, Secret Detection, Container Scanning.
- **Generation Command**: Native artifacts produced by GitLab CI security analyzers (`gl-sast-report.json`, `gl-secret-detection-report.json`, etc.).
- **Extracted Fields**:
  - `vulnerabilities[].id`, `cve`, `name`, `severity`, `location.file`, `location.start_line`, `identifiers`

### 17. OWASP Dependency-Check (`parsers/wasm/dependencycheck`)
- **Documentation**: [OWASP Dependency-Check Documentation](https://jeremylong.github.io/DependencyCheck/)
- **Supported Versions**: JSON Schema 1.1 (Engine versions 6.x through 10.x+).
- **Generation Command**: `dependency-check.sh --project "app" --scan . --format JSON --out dependency-check.json`
- **Extracted Fields**:
  - `dependencies[].fileName`, `filePath`, `packages[].id` (purl), `vulnerabilities[].name`, `severity`, `cvssv3`, `cwes`

### 18. Bandit (`parsers/lua/bandit`)
- **Documentation**: [PyCQA Bandit Documentation](https://bandit.readthedocs.io/)
- **Supported Versions**: Bandit 1.6.x through latest 1.8.x.
- **Generation Command**: `bandit -r . -f json -o bandit.json`
- **Extracted Fields**:
  - `results[].test_id` -> `rule_id`, `issue_text` -> `title`, `filename`, `line_number`, `issue_severity`, `issue_cwe.id`

### 19. OWASP ZAP (`parsers/lua/zap`)
- **Documentation**: [ZAP Report Generation](https://www.zaproxy.org/docs/desktop/addons/report-generation/)
- **Supported Versions**: OWASP ZAP 2.11.x through latest 2.16.x JSON reports.
- **Generation Command**: `zap-cli report -f json -o zap.json` or ZAP Automation Framework JSON report.
- **Extracted Fields**:
  - `site[].alerts[]`: `pluginId`, `alert` (title), `riskdesc`, `cweid`, `instances[].uri`, `instances[].param`, `instances[].method`

### 20. ProjectDiscovery Nuclei (`parsers/lua/nuclei`)
- **Documentation**: [Nuclei Documentation](https://docs.projectdiscovery.io/tools/nuclei/)
- **Supported Versions**: Nuclei v2.x and v3.x JSONL output.
- **Generation Command**: `nuclei -u https://example.com -jsonl -o nuclei.jsonl`
- **Extracted Fields**:
  - `template-id`, `info.name`, `info.severity`, `info.classification.cwe-id`, `matched-at` -> `location.web.normalized_url`

### 21. Rampart / DefectDojo Generic (`parsers/lua/genericjson`)
- **Documentation**: [Rampart Generic Findings Import (docs/25 §4) & DefectDojo Generic Format](docs/25-integration-contracts.md)
- **Supported Formats**: `rampart-generic/v1` and DefectDojo Generic Findings JSON.
- **Extracted Fields**:
  - `title`, `severity`, `category` (or auto-inferred), `rule_id`, `file`, `line`, `url`, `method`, `param`, `purl`, `component`, `resource`, `secret`
