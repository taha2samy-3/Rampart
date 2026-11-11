# Research: Open standards and data formats

Research date: 2026-11-10.

---

## 1. SARIF 2.1.0 (OASIS)

SARIF 2.1.0 is the current OASIS Standard (March 2020); 2.2 is stalled. Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html · Schema: https://json.schemastore.org/sarif-2.1.0.json

**Structure.**
- `sarifLog`: `version`, `$schema`, `runs[]`.
- `run`: `tool`, `results[]`, `invocations[]`, `artifacts[]`, `logicalLocations[]`, `taxonomies[]`, `originalUriBaseIds`, `automationDetails` (id/guid for grouping runs), `versionControlProvenance[]`, `properties`.
- `tool.driver`: `name`, `version`, `semanticVersion`, `informationUri`, `rules[]`, `taxa[]`; `tool.extensions[]`.
- `reportingDescriptor` (rule): `id`, `name`, `shortDescription`, `fullDescription`, `help`/`helpUri`, `defaultConfiguration{level, rank, enabled}`, `relationships[]` (links to CWE taxa), `properties` (GitHub: `tags`, `security-severity`, `precision`).
- `result`: `ruleId`, `ruleIndex`, `level` (`none|note|warning|error`), `kind` (`notApplicable|pass|open|informational|review|fail`), `message`, `locations[]`, `relatedLocations[]`, `codeFlows[]`, `stacks[]`, `fixes[]`, `partialFingerprints` (e.g. `primaryLocationLineHash`), `fingerprints`, `baselineState` (`new|unchanged|updated|absent`), `rank`, `suppressions[]`, `taxa[]`, `guid`, `correlationGuid`, `properties`.
- `location`: `physicalLocation{artifactLocation{uri, uriBaseId}, region{startLine, startColumn, endLine, endColumn, snippet}}`, `logicalLocations[]{name, fullyQualifiedName, kind}`.
- `suppression`: `kind` (`inSource|external`), `status` (`accepted|underReview|rejected`), `justification`.

**ASPM notes.** `partialFingerprints` + `ruleId` + normalized URI is the practical dedup key. `baselineState` is rarely populated; compute your own baseline. `level` is not severity; use `properties.security-severity` (CVSS float) when present.

**Native SARIF producers**: CodeQL, Semgrep, Trivy, Grype, Gitleaks, Checkov, Bandit, Nuclei, Snyk CLI, ZAP (add-on), kube-linter, tflint, ESLint, Brakeman, KICS, Dependency-Check, Hadolint, OSV-Scanner, Scorecard. Not native: Prowler (OCSF), SonarQube (imports only), kube-bench.

**Go libraries**: `github.com/owenrumney/go-sarif/v3` (typed model + builder, used by Trivy/tfsec) — recommended; `github.com/haveyoudebuggedit/gosarif` (struct-only).

## 2. CycloneDX 1.6 / 1.7

1.6 = ECMA-424 1st ed. (June 2024); 1.7 released Oct 2025, ECMA-424 2nd ed. Dec 2025. Spec: https://cyclonedx.org/specification/overview/ · Schemas: https://github.com/CycloneDX/specification

**BOM types in one schema**: SBOM, SaaSBOM (`services[]`), HBOM, OBOM, MBOM, VDR (BOM + `vulnerabilities[]`), VEX (`vulnerabilities[]` with `analysis`), CBOM (`cryptographic-asset`), ML-BOM, attestations (`declarations`).

**Top-level**: `bomFormat`, `specVersion`, `serialNumber` (urn:uuid), `version`, `metadata{timestamp, tools, authors, component, supplier, lifecycles}`, `components[]`, `services[]`, `dependencies[]`, `compositions[]`, `vulnerabilities[]`, `annotations[]`, `formulation[]`, `declarations`, `signature`.

**`bom-ref`**: document-unique opaque string; everything cross-references by it. Index purl/cpe separately.

**`component`**: `type` (`application|framework|library|container|platform|operating-system|device|firmware|file|machine-learning-model|data|cryptographic-asset`), `name`, `version`, `group`, `purl`, `cpe`, `swid`, `hashes[]`, `licenses[]`, `supplier`, `scope`, `evidence`, nested `components[]`, `properties[]`.

**`dependencies[]`**: `{ref, dependsOn[], provides[]}`.

**`vulnerabilities[]`**: `bom-ref`, `id`, `source{name,url}`, `references[]`, `ratings[]{source, score, severity (critical|high|medium|low|info|none|unknown), method (CVSSv2|CVSSv3|CVSSv31|CVSSv4|OWASP|SSVC|other), vector}`, `cwes[]` (ints), `description`, `detail`, `recommendation`, `workaround`, `proofOfConcept`, `advisories[]`, `created/published/updated/rejected`, `analysis{state: resolved|resolved_with_pedigree|exploitable|in_triage|false_positive|not_affected; justification: code_not_present|code_not_reachable|requires_configuration|requires_dependency|requires_environment|protected_by_compiler|protected_at_runtime|protected_at_perimeter|protected_by_mitigating_control; response[]: can_not_fix|will_not_fix|update|rollback|workaround_available; detail}`, `affects[]{ref, versions[]{version|range (vers), status}}`.

**Go**: `github.com/CycloneDX/cyclonedx-go` (spec 1.0–1.7, JSON+XML, version downgrade).

## 3. SPDX 2.3 and 3.0

**SPDX 2.3** (ISO/IEC 5962): `SPDXID`, `creationInfo`, `packages[]` (`name`, `versionInfo`, `supplier`, `downloadLocation`, `checksums[]`, `licenseConcluded/Declared`, `externalRefs[]{referenceCategory: SECURITY|PACKAGE-MANAGER|PERSISTENT-ID, referenceType: cpe23Type|purl|advisory|fix}`, `primaryPackagePurpose`), `files[]`, `snippets[]`, `relationships[]` (~45 types: DESCRIBES, CONTAINS, DEPENDS_ON, BUILD_TOOL_OF, ...). Serializations: tag-value, JSON, YAML, RDF. Security only via externalRefs. https://spdx.github.io/spdx-spec/v2.3/

**SPDX 3.0.1** (Sept 2024): graph of `Element`s with profiles (Core, Software, Security, Licensing, Build, Dataset, AI, Lite). JSON-LD. Security profile: `Vulnerability` + `VulnAssessmentRelationship` subclasses (`CvssV2/V3/V4...`, `Epss...`, `ExploitCatalog...` (KEV), `Ssvc...`, `VexAffected...`, `VexNotAffected...`, `VexFixed...`, `VexUnderInvestigation...`). https://spdx.github.io/spdx-spec/v3.0.1/model/Security/

**Go**: `github.com/spdx/tools-golang` supports 2.1–2.3; no complete 3.0 support yet. Syft and Trivy emit SPDX 2.3 JSON.

## 4. CSAF 2.0, VEX profile, OpenVEX

**CSAF 2.0** (OASIS Nov 2022, ISO/IEC 20153:2025); 2.1 still draft. `document{category (csaf_vex|csaf_security_advisory), publisher, tracking{id, status, version, revision_history}, title, distribution/tlp}`, `product_tree{branches, full_product_names[]{product_id, product_identification_helper{cpe, purl, hashes, sbom_urls}}}`, `vulnerabilities[]{cve, cwe, ids, notes, product_status{fixed, known_affected, known_not_affected, under_investigation, ...}, flags[], threats[], remediations[]{category: vendor_fix|mitigation|workaround|no_fix_planned|none_available}, scores[]}`. VEX profile requires `product_status`; `known_not_affected` needs `flags` or impact `threats`. https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html

**OpenVEX** v0.2.0: document `@context, @id, author, role, timestamp, version, tooling, statements[]`; statement `vulnerability{@id, name, aliases[]}`, `products[]{@id (purl), identifiers{purl, cpe23}, hashes, subcomponents[]}`, `status`, `status_notes`, `justification`, `impact_statement`, `action_statement`. Go: `github.com/openvex/go-vex`. https://github.com/openvex/spec

**Four VEX statuses** (CSAF, OpenVEX, SPDX 3, CISA): `not_affected`, `affected`, `fixed`, `under_investigation`. **Five not_affected justifications**: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`.

**Mapping CycloneDX analysis.state → OpenVEX**: `not_affected`→`not_affected`, `exploitable`→`affected`, `resolved`→`fixed`, `in_triage`→`under_investigation`, `false_positive`→`not_affected`. VEX ties to SBOM via purl/cpe; `subcomponents` express "product X not affected via subcomponent Y".

## 5. Identifiers and scoring

- **CVE JSON 5.1.x**: `cveMetadata{cveId, state, datePublished, dateUpdated}`, `containers{cna{title, descriptions[], affected[]{vendor, product, packageName, cpes[], versions[]{version, status, lessThan, versionType}}, problemTypes[] (CWE), metrics[] (cvssV2_0/V3_0/V3_1/V4_0, other e.g. SSVC), references[]}, adp[]}`. CISA ADP adds SSVC and KEV. Bulk: https://github.com/CVEProject/cvelistV5
- **CWE**: https://cwe.mitre.org/ (XML/CSV/JSON; views 1003/1000). CWE Top 25 2025: #1 CWE-79, #2 CWE-89, #3 CWE-352, #4 CWE-862, #5 CWE-787. Store CWE as int; keep local copy for names/parents.
- **CPE 2.3**: `cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other`. Go: `github.com/knqyf263/go-cpe`.
- **purl**: `pkg:type/namespace/name@version?qualifiers#subpath`. Go: `github.com/package-url/packageurl-go`. Version ranges: `vers` spec.
- **GHSA**: `GHSA-xxxx-xxxx-xxxx`; also published as OSV JSON at https://github.com/github/advisory-database.
- **OSV schema** 1.9.x: `id`, `modified`, `published`, `withdrawn`, `aliases[]`, `related[]`, `summary`, `details`, `severity[]{type: CVSS_V2|CVSS_V3|CVSS_V4, score}`, `affected[]{package{ecosystem, name, purl}, ranges[]{type: SEMVER|ECOSYSTEM|GIT, events[]}, versions[]}`, `references[]`. API: `POST https://api.osv.dev/v1/query`, `/v1/querybatch`, `/v1/vulns/{id}`; bulk GCS dumps. https://ossf.github.io/osv-schema/
- **NVD API 2.0**: `https://services.nvd.nist.gov/rest/json/cves/2.0` (`cveId`, `cpeName`, `lastModStartDate/EndDate`, `startIndex`, `resultsPerPage` ≤2000, `hasKev`); 5 req/30s without key, 50 with. https://nvd.nist.gov/developers/vulnerabilities
- **CISA KEV**: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json — `vulnerabilities[]{cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, cwes[]}`.
- **EPSS** (FIRST, model v4): `https://api.first.org/data/v1/epss?cve=...` (≤100 per call, `date`, `scope=time-series`); daily CSV at https://epss.cyentia.com/. https://www.first.org/epss/api
- **CVSS**: v2, v3.0/3.1, v4.0 (Base + Threat + Environmental + Supplemental; CVSS-B/BT/BE/BTE). Go: `github.com/pandatix/go-cvss` (v2/v3/v4, recommended); `github.com/goark/go-cvss` (no v4).
- **SSVC** (CISA): Exploitation (none|poc|active), Automatable (no|yes), Technical Impact (partial|total), Mission & Well-being → `Track`, `Track*`, `Attend`, `Act`. Decision trees JSON at https://github.com/CERTCC/SSVC.

## 6. Grouping and compliance taxonomies

- **OWASP Top 10:2021**: A01 Broken Access Control … A10 SSRF; CWE mapping machine-readable at https://github.com/OWASP/Top10.
- **OWASP Top 10:2025**: A01 Broken Access Control (absorbs SSRF), A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Logging & Alerting Failures, A10 Mishandling of Exceptional Conditions.
- **OWASP ASVS 5.0** (May 2025): 17 chapters, ~350 requirements, levels 1–3; CWE mapping via OpenCRE (https://www.opencre.org).
- **OWASP SAMM 2.x**, **OWASP API Top 10 (2023)**.
- **NIST SSDF SP 800-218 v1.1**: PO/PS/PW/RV groups, 19 practices; v1.2 draft Dec 2025.
- **SLSA v1.0–1.2**: Build track L0–L3; v1.2 adds Source track.
- **OpenSSF Scorecard**: ~20 checks, 0–10; API `https://api.scorecard.dev/projects/github.com/{org}/{repo}`; emits SARIF.
- **PCI DSS v4.0.1**: 6.2 (secure dev), 6.3.1 (risk ranking), 6.3.2 (inventory of bespoke and third-party components = SBOM), 6.3.3 (patch critical in 1 month), 6.4 (web app protection), 11.3 (scanning).
- **SOC 2** (TSC): CC6, CC7.1 vuln detection, CC8.1 change management.
- **ISO/IEC 27001:2022 Annex A**: 8.8 technical vulnerabilities, 8.9 config mgmt, 8.25–8.32 secure development / testing / environments / change.
- **CIS Benchmarks** per platform; CIS Controls v8.1 (7 vuln mgmt, 16 app security).

**Mapping pipeline**: scanner rule → CWE (SARIF taxa, Semgrep metadata, Trivy CweIDs, CycloneDX cwes) → framework category via crosswalks (CWE→Top 10 via OWASP lists; CWE→ASVS/NIST via OpenCRE; CIS/PCI/ISO via scanner-provided control IDs). Model taxonomies as versioned tables, not hard-coded.

## 7. Scanner native output formats

| Scanner | Native | SARIF | CycloneDX/SPDX | Notes |
|---|---|---|---|---|
| Trivy | JSON (`Results[].Vulnerabilities[]{VulnerabilityID, PkgName, PkgIdentifier.PURL, InstalledVersion, FixedVersion, Severity, CVSS{nvd,redhat,ghsa}, CweIDs, Status}`, `Misconfigurations[]`, `Secrets[]`, `Licenses[]`) | yes | CDX 1.6, SPDX 2.3 | |
| Grype | JSON (`matches[]{vulnerability{id, severity, cvss[], fix, epss, kev}, artifact{name, version, purl, locations}}`) | yes | CDX | |
| Syft | JSON (`artifacts[]{name, version, purl, cpes[]}`, `artifactRelationships[]`) | n/a | CDX 1.6, SPDX 2.3 | Go lib usable directly |
| Semgrep | JSON (`results[]{check_id, path, start, end, extra{message, severity, metadata{cwe[], owasp[], confidence}, fingerprint, dataflow_trace}}`) | yes | no | |
| Gitleaks | JSON array (`RuleID, File, StartLine, Secret, Commit, Fingerprint, Entropy`) | yes | no | |
| Checkov | JSON (`results{failed_checks[]{check_id, resource, file_path, file_line_range, severity}}`) | yes | CDX | |
| tfsec | merged into Trivy config | yes | no | |
| ZAP | JSON/XML (`site[]{alerts[]{pluginid, alert, riskcode, confidence, instances[]{uri, method, param, evidence}, cweid, wascid}}`) | add-on | no | |
| Nuclei | JSONL (`template-id, info{name, severity, tags, classification{cve-id, cwe-id, cvss-score, epss-score}}, host, matched-at`) | yes | no | |
| Snyk CLI | JSON (`vulnerabilities[]{id, title, severity, cvssScore, identifiers{CVE, CWE}, packageName, version, from[], fixedIn}`) | yes | no | |
| SonarQube | Web API `api/issues/search`, `api/hotspots/search` | imports only | no | API-pull |
| Dependency-Check | XML/JSON (`dependencies[]{fileName, identifiers{purl, cpe}, vulnerabilities[]}`) | yes | no | |
| Bandit | JSON (`results[]{test_id, issue_severity, issue_confidence, issue_cwe, filename, line_number}`) | yes | no | |
| kube-bench | JSON (`Controls[]{id, tests[]{results[]{test_number, status, remediation}}}`) CIS IDs | no | no | |
| Prowler | OCSF JSON (Detection Finding 2004), CSV | no | no | |
| Dependency-Track | REST (`/api/v1/bom`, `/api/v1/finding/project/{uuid}`, `/api/v1/vex`) | n/a | CDX VDR/VEX | |

Takeaway: SARIF-first covers Semgrep, Gitleaks, Checkov, Trivy, Grype, Nuclei, Snyk, ZAP, Bandit, Dependency-Check, CodeQL, Scorecard, GitHub/Azure/GitLab uploads. CycloneDX-first covers Syft, Trivy, Grype, cdxgen, Dependency-Track, VEX producers. Native parsers still needed for kube-bench, Prowler OCSF, SonarQube API, and for enrichment data SARIF loses (Trivy per-source CVSS, Grype EPSS/KEV, Semgrep dataflow). Pattern: "SARIF for triage, native JSON for enrichment".

## 8. OCSF as an internal canonical model

OCSF Findings category (2): Vulnerability Finding (2002), Compliance Finding (2003), Detection Finding (2004), **Application Security Posture Finding (2007, added 1.4)**. ASPF required: `activity_id`, `finding_info{uid, title, desc, first_seen_time, last_seen_time}`, `metadata`, `severity_id`, `time`; recommended: `application`, `compliance{standards, control, status}`, `remediation`, `vulnerabilities[]{cve{uid, cvss[], epss}, cwe{uid}, affected_code[]{file, start_line, end_line}, affected_packages[]{name, version, purl}, fix_available, is_exploit_available}`, `resources[]`, `status_id`.

**Assessment**: good *export/interop* target (Security Lake, Splunk, Prowler). Poor *internal* model: event-oriented, loose enums, no dedup fingerprint or VEX status, frequent versions. Own a compact internal `Finding` model and provide mappers to SARIF, CycloneDX VDR and OCSF 2007.

## 9. Supply-chain attestations

- **in-toto Attestation**: DSSE envelope wrapping Statement (`subject[]{name, digest}`, `predicateType`, `predicate`). Predicates: SLSA Provenance v1, VSA, SPDX, CycloneDX, Vulns, Test Result. Go: `github.com/in-toto/attestation/go/v1`, `github.com/secure-systems-lab/go-securesystemslib/dsse`.
- **SLSA Provenance v1**: `buildDefinition{buildType, externalParameters, resolvedDependencies[]}`, `runDetails{builder{id}, metadata}`. Verify with `slsa-verifier`.
- **Sigstore cosign**: `cosign attest --type ... --predicate ... image`; `cosign verify-attestation`; Sigstore bundles. Go: `github.com/sigstore/sigstore-go`.
- **ASPM consumption**: discover attestations per deployed digest (OCI referrers, GitHub attestations API, Rekor), verify identity, derive SLSA level, extract SBOM/vuln predicates, enforce policies, surface gaps as posture findings. Store raw DSSE + verification result.

## 10. CI/CD and IDE integration standards

- **GitHub Code Scanning**: `POST /repos/{o}/{r}/code-scanning/sarifs` (gzip+base64, ≤10 MB, 20 runs/file, 25k results/run, 1000 locations/result); `properties.security-severity` drives severity; `partialFingerprints.primaryLocationLineHash` drives dedup; `automationDetails.id` is category.
- **GitLab security report schemas** (15.x): `gl-sast-report.json`, `gl-secret-detection-report.json`, `gl-dependency-scanning-report.json`, `gl-container-scanning-report.json`, `gl-dast-report.json`, ...; shape `version`, `scan{analyzer, scanner, type, status}`, `vulnerabilities[]{id, name, description, severity, solution, identifiers[]{type, name, value}, location{file, start_line, end_line; dependency; image; hostname}, cvss_vectors[]}`, `remediations[]`. https://gitlab.com/gitlab-org/security-products/security-report-schemas
- **Jenkins Warnings NG**: `recordIssues tool: sarif(...)` + ~100 parsers; quality gates; REST export.
- **Azure DevOps Advanced Security**: `AdvancedSecurity-Publish@1` merges SARIF, computes fingerprints; alerts REST `advsec.dev.azure.com/.../alerts`.
- **IDE**: SARIF is the de facto IDE format (VS Code SARIF Viewer, JetBrains); LSP Diagnostic is near-1:1 with SARIF result.

## Summary recommendations

1. SARIF 2.1.0 (go-sarif v3) and CycloneDX 1.6/1.7 (cyclonedx-go) as first-class ingest formats; native parsers for Trivy, Grype, Semgrep, Gitleaks, Checkov, Nuclei, ZAP, Dependency-Check, kube-bench, Prowler OCSF.
2. Normalize identifiers: CVE/GHSA/OSV with aliases, CWE int, purl, CPE 2.3; keep CVSS vectors verbatim, recompute with pandatix/go-cvss; enrich from OSV.dev, NVD 2.0, KEV, EPSS, CISA SSVC.
3. OpenVEX vocabulary as internal triage state; map to CycloneDX analysis, CSAF, SPDX 3 on export.
4. Taxonomies (OWASP 2021/2025, CWE Top 25, ASVS 5 via OpenCRE, PCI 6.x, ISO 27001 8.x, SSDF, CIS, SLSA) as data tables keyed by CWE and control IDs.
5. OCSF 2007 as export target only.
6. Verify in-toto/SLSA attestations with sigstore-go/slsa-verifier; derive posture findings.
