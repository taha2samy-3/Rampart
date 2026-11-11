# Research: DefectDojo (OSS 3.x and Pro)

Research date: 2026-11-10. DefectDojo OSS is on the 3.x line (v3.0 June 2026, 3.2.x current). In v3 the UI relabels Product Type → "Organization" and Product → "Asset" (DB models and API v2 names unchanged).

Docs: https://docs.defectdojo.com/ · Repo: https://github.com/DefectDojo/django-DefectDojo

---

## 1. Data model hierarchy

Core chain: **Product_Type → Product → Engagement → Test → Finding**, with Endpoints ("Locations" in v3) attached to Findings via Endpoint_Status.

**Product_Type**: `name`, `description`, `critical_product`, `key_product`, `authorized_users` M2M.

**Product**: `name`, `description`, `product_manager` / `technical_contact` / `team_manager`, `prod_type` (FK), `sla_configuration` (FK), `authorized_users`, `prod_numeric_grade`, `business_criticality` (very high…none), `platform` / `lifecycle` / `origin`, `user_records`, `revenue`, `external_audience`, `internet_accessible`, `regulations` M2M, `tags`, `enable_product_tag_inheritance`, `enable_simple_risk_acceptance`, `enable_full_risk_acceptance`, `disable_sla_breach_notifications`.

**Engagement**: `name`, `description`, `version`, `target_start` / `target_end`, `lead`, `requester`, `preset`, `status` (Not Started, Blocked, Cancelled, Completed, In Progress, On Hold, Scheduled, Waiting for Resource), `engagement_type` ("Interactive" | "CI/CD"), `build_id`, `commit_hash`, `branch_tag`, `source_code_management_uri`, `deduplication_on_engagement`, `risk_acceptance` M2M, `tags`, `threat_model` / `api_test` / `pen_test` / `check_list` bools, `tracker`, `test_strategy`.

**Test**: `engagement`, `lead`, `test_type`, `scan_type`, `title`, `target_start/end`, `environment`, `version`, `build_id`, `commit_hash`, `branch_tag`, `api_scan_configuration`. **Test_Type**: `name`, `static_tool`, `dynamic_tool`, `active`, `dynamically_generated`. **Test_Import** records import history with per-finding action (created / closed / reactivated / untouched) and `import_settings` JSON.

**Finding** key fields:
- Identity/content: `title`, `date`, `cwe`, `cve` (legacy), `description`, `mitigation`, `impact`, `steps_to_reproduce`, `severity_justification`, `references`, `url`, `severity` (Critical/High/Medium/Low/Info), `numerical_severity` (S0–S4), `scanner_confidence`, `nb_occurences`, `service`.
- Scoring: `cvssv3`, `cvssv3_score`, `cvssv4`, `cvssv4_score`, `epss_score`, `epss_percentile`, `known_exploited`, `ransomware_used`, `kev_date`, `publish_date`.
- Location: `file_path`, `line`, `sast_source_object`, `sast_sink_object`, `sast_source_line`, `sast_source_file_path`, `component_name`, `component_version`, `param`, `payload`, `endpoints` M2M, `static_finding`, `dynamic_finding`.
- Lifecycle: `active`, `verified`, `false_p`, `duplicate`, `duplicate_finding`, `out_of_scope`, `risk_accepted`, `under_review`, `under_defect_review`, `is_mitigated`, `mitigated`, `mitigated_by`, `last_status_update`, `last_reviewed`, `sla_start_date`, `sla_expiration_date`, `planned_remediation_date`, `planned_remediation_version`, `effort_for_fixing`, `fix_available`, `fix_version`.
- People/relations: `reporter`, `reviewers`, `notes`, `files`, `found_by` (M2M Test_Type), `tags`, `inherited_tags`, `sonarqube_issue`.
- Dedupe: `hash_code` (SHA-256 of per-scanner fields), `unique_id_from_tool`, `vuln_id_from_tool`.
- Related: `Vulnerability_Id` (finding, vulnerability_id, type), `Finding_CWE` (multi-CWE, 3.2), `BurpRawRequestResponse`.

**Finding_Group**: `name`, `test`, `findings` M2M. **Finding_Template**: reusable text/severity/CWE. **Stub_Finding** removed in 3.0.

**Endpoint**: `protocol, userinfo, host, port, path, query, fragment, product`. **Endpoint_Status** per (finding, endpoint): `mitigated, false_positive, out_of_scope, risk_accepted`. v3 Locations (URLs, dependencies/purl, code, cloud resources, container images) replace Endpoints.

**Risk_Acceptance**: `name`, `accepted_findings` M2M, `recommendation` & `decision` (Accept / Avoid / Mitigate / Fix / Transfer), `accepted_by`, `path` (proof), `owner`, `expiration_date`, `reactivate_expired`, `restart_sla_expired`, `restore_verified_expired`, `notes`. Plus "simple risk acceptance" one-click mode.

**SLA_Configuration**: `critical=7, high=30, medium=90, low=120` days, `enforce_*` flags, `restart_sla_on_reactivation`.

**JIRA**: `JIRA_Instance` (url, creds, issue type, transition IDs, severity→priority mapping, resolution mapping to Risk Accepted / False Positive), `JIRA_Project` (instance, project_key, product or engagement, custom_fields, push_all_issues, epic mapping, push_notes), `JIRA_Issue` (one-to-one with finding / engagement / finding_group).

**Notifications**: per-user / per-product row with channels (`slack, msteams, mail, webhooks, alert`) per event (product_added, engagement_added, test_added, scan_added, scan_added_empty, jira_update, upcoming_engagement, stale_engagement, sla_breach, sla_breach_combined, risk_acceptance_expiration, user_mentioned, review_requested...). `Notification_Webhooks` with auto-deactivation on errors.

**Others**: Notes, Tags (tagulous, lowercase, inherited from product), DojoMeta (key/value metadata), Tool_Type / Tool_Configuration / Product_API_Scan_Configuration (deprecated 3.2, removal 3.6), Regulation, Benchmarks (ASVS), Questionnaires, Development_Environment, Engagement_Presets, CICDInfrastructure, Languages / App_Analysis, Check_List, System_Settings (~100 toggles).

## 2. Import / reimport semantics

Endpoints: `POST /api/v2/import-scan/` (always creates a new Test) and `POST /api/v2/reimport-scan/` (diffs into an existing Test; with `auto_create_context=true` can create Product Type / Product / Engagement / Test). Maintainers plan to merge the two.

Options: `scan_type` (required), `environment`, `engagement`/`test` or by-name (`product_type_name`, `product_name`, `engagement_name`, `test_title`, `auto_create_context`), `active` / `verified` (null = parser-provided, true = force), `minimum_severity`, `scan_date`, `close_old_findings` (+ `close_old_findings_product_scope`), `do_not_reactivate`, `push_to_jira`, `group_by` (component_name | component_name+version | file_path | finding_title | vuln_id_from_tool), `create_finding_groups_for_all_findings`, `tags`, `apply_tags_to_findings`, `endpoints_to_add`, `service`, `version`, `build_id`, `commit_hash`, `branch_tag`, `deduplication_execution_mode` (async | async_wait | sync). Batch sizes 1000. Max file 100 MB.

Reimport algorithm: parse → min-severity filter → compute hash → deterministic sort → snapshot existing findings in Test with same `service` → match per batch via parser's dedupe algorithm → outcomes **created / untouched / closed / reactivated**. False-positive, out-of-scope and risk-accepted matches are never reopened. Reimport never updates existing finding fields such as severity/description (issues #6774, #12937). Unstable hash inputs (line numbers) cause close+recreate churn (#11227).

**Deduplication** (post-import, Celery): algorithms `legacy` (title, cwe, line, file_path, description + endpoint rules), `hash_code` (per-scanner field list, e.g. Trivy = title, severity, vulnerability_ids, cwe, description; Snyk = vuln_id_from_tool, file_path, component_name, component_version; Bandit = file_path, line, vuln_id_from_tool), `unique_id_from_tool`, `unique_id_from_tool_or_hash_code`. Scope: product (default) or engagement. OSS dedupes only within the same tool; Pro adds cross-tool, Dedupe Pools, global component / vuln-id / location matching. Earliest finding is the original. **False positive history** is mutually exclusive with dedupe.

**Status model**: `active`, `verified`, `is_mitigated` + `mitigated` + `mitigated_by`, `false_p`, `out_of_scope`, `duplicate`, `risk_accepted`, `under_review`, `under_defect_review`. Rendered as a comma list or "Initial".

## 3. Parser ecosystem

~363 parser directories in `dojo/tools/` ("360+ built-in parsers"). Each is a Python class with `get_scan_types()`, `get_findings(file, test)`. Popular: sarif, trivy, trivy_operator, anchore_grype, semgrep, snyk, snyk_code, checkmarx(_one), sonarqube, zap, burp(_api/_enterprise), tenable, qualys(_webapp/_vmdr), dependency_check, dependency_track, cyclonedx, spdx, syft, gitleaks, trufflehog, detect_secrets, bandit, gosec, brakeman, kubebench, kubehunter, kubescape, prowler, awssecurityhub (ASFF), aws_inspector2, nuclei, nmap, nikto, checkov, tfsec, terrascan, kics, veracode, fortify, codeql, github_vulnerability, gitlab_* (sast/dast/dep_scan/container_scan/secret_detection), npm_audit, yarn_audit, pip_audit, osv_scanner, govulncheck, clair, twistlock, wiz, ms_defender, openvas, nexpose, acunetix, hadolint, mobsf, wpscan, sslyze, testssl, generic.

**Generic Findings Import** JSON: top-level `name`, `type`, `version`, `description`, `dynamic_tool`, `static_tool`, `findings[]`. Required per finding: `title`, `severity`, `description`. Optional: `date`, `vulnerability_ids`, `cwe`/`cwes`, `cvssv3(_score)`, `cvssv4(_score)`, `epss_score`, `epss_percentile`, `known_exploited`, `kev_date`, `mitigation`, `impact`, `references`, `param`, `payload`, `service`, `file_path`, `line`, `sast_*`, `component_name`, `component_version`, `purl`, `endpoints`, `files`, `tags`, `unique_id_from_tool`, `vuln_id_from_tool`, status bools, `fix_available`, `fix_version`. **Universal Parser** (Pro): UI field-mapping for arbitrary JSON/CSV/XML with versioned mappings.

## 4. SLA, severity, CVSS, EPSS/KEV, risk acceptance

- Five severities; `numerical_severity` S0–S4. CVSS v3/v4 vectors + scores; vector paste computes score.
- SLA per-product config (7/30/90/120 default); `sla_start_date` defaults to finding `date`; daily Celery task sends breach notifications; reimport does not restart SLA. Pro: risk-based SLAs, KEV due-date cap, FedRAMP timelines.
- EPSS/KEV: fields in OSS but populated only by scanners; Pro enriches daily from FIRST/CISA and feeds a priority score.
- Risk acceptance: full workflow with expiry handler (warn → reactivate / restart SLA / restore verified); Pro adds approval workflow.
- Dedupe vs reimport: reimport = intra-Test matching before persistence; dedupe = cross-Test marking after save.

## 5. Integrations

- **Jira** (OSS): multiple instances, product/engagement project mapping, push single/bulk/group, epic mapping, notes↔comments, webhook for close/reopen and resolution→status mapping, custom fields. Pro: "Downstream Connectors" (Jira, Azure DevOps, GitLab, GitHub, Linear, ServiceNow, PagerDuty, Opsgenie).
- **Notifications**: email, Slack, MS Teams, in-app, outbound webhooks (events: product_added, engagement_added, test_added, scan_added, scan_added_empty, ping; headers `X-DefectDojo-Event`).
- **SSO**: OAuth2/SAML/OIDC removed from OSS in 3.0; Pro-only (plus LDAP, SCIM, MFA).
- **RBAC**: v3 OSS reverted to binary "Authorized Users" lists + superuser/staff. Pro keeps roles (Reader/Writer/Maintainer/Owner/API Importer) + custom roles.
- **API auth**: DRF Token, optional expiry, OpenAPI at `/api/v2/oa3/swagger-ui/`.
- Other: GitHub Action, `defectdojo-cli` (Pro), secureCodeBox hook, Dependency-Track push, MCP server (Pro).

## 6. Metrics / reporting

OSS: fixed dashboard, product-type / simple / engineer metrics views, Report Builder → HTML, CSV/Excel exports. Pro: Command Center, Posture Score (0–1000), custom dashboards, Insights (Executive / Priority / Program / Remediation / Tool), scheduled PDF/JSON reports.

## 7. Pro vs OSS

Pro adds: 140+ Upstream Connectors (scheduled API pulls), asset connectors (GitHub, GitLab, Azure DevOps, ServiceNow CMDB, Backstage), Universal Parser / Importer / CLI, background imports, cross-tool dedupe, EPSS/KEV enrichment, priority score, reachability/exposure, Root Causes, Triage (rules) Engine with simulate mode, AI triage, Scan Cadence, Remediation Campaigns, Downstream Connectors, risk-acceptance approvals, risk-based SLAs, compliance packs (FedRAMP POA&M, OSCAL, CMMC, PCI, EU CRA), PSIRT, SBOM/VEX export, asset hierarchy, Locations, custom fields, SSO/LDAP/SCIM/MFA, RBAC, audit logs, MCP server, air-gapped hosting.

## 8. Architecture pain points (commonly cited)

- Stack: Django monolith on uWSGI + nginx + Celery worker + Celery Beat + PostgreSQL + Redis/Valkey. "Four services to monitor, patch, back up, scale."
- Import/dedupe performance: per-finding Celery tasks; 1000+ finding imports take minutes (PR #13491, #14458, #4641); rehash takes hours on large DBs.
- Query scaling: filters take minutes at 5M findings (#6388), filter pages 12 s (#8680), edit finding 50 s at 100K (#10313), N+1 from tags.
- Memory: uWSGI OOMKilled on Kubernetes (#9562, #9849, #13899).
- API gaps: no bulk create/update (#13900), reimport doesn't update fields (#12937), cross-branch dedupe (#6815), per-rule notifications (#7393), health check (#8327), non-root containers (#11031).
- No multi-tenancy. OSS→Pro feature migration (RBAC, SSO, EPSS) criticized.
- Model debt: Endpoint→Location migration, Tool Configuration deprecation.

## 9. Outside the ASPM core

Questionnaires/surveys, OWASP ASVS Benchmarks, Credential Manager (removed 3.0), engagement scheduling/calendar/presets/checklists, threat-model upload, Regulations catalogue, Languages/technologies, product business metadata, Development Environments, Announcements/banners, CI/CD infrastructure records, Testing Guide, Pro threat modeling / PSIRT / AI governance.
