# Research: ASPM market (Gartner, ArmorCode, competitors)

Research date: 2026-11-10. Gartner reports are paywalled; ArmorCode docs were unreachable (DNS / 403), so the ArmorCode section relies on vendor blogs, press releases and third-party integration docs. OX Security, Snyk, Brinqa, Dependency-Track and Faraday docs were reachable and cited directly.

---

## 1. Gartner's definition and core capabilities

**Lineage.** ASOC (Application Security Orchestration and Correlation, 2019) merged AVC and ASTO. *Innovation Insight for ASPM* (May 2023) retired ASOC and introduced ASPM; a second edition (Jan 2025) refreshed it.

**Definition.** ASPM "analyzes security signals across software development, deployment and operation to improve visibility, better manage vulnerabilities and enforce controls" and provides "a single source of truth to identify, correlate, and prioritize security vulnerabilities across the SDLC". Forecast: by 2027, 80% of regulated organizations using AST will incorporate ASPM (vs ~29% today).

**Core capabilities (2025 edition, per vendor summaries):** comprehensive coverage across dev and ops; data correlation; intelligent prioritization; streamlined remediation; risk indicators; plus orchestration, root-cause identification, owner identification; deployment flexibility; automation.

**Capability checklist that vendor guides converge on:**
- Ingestion/aggregation from SAST, DAST, SCA, IaC, container, secrets, CSPM/CNAPP, pentest, API security, VM into one normalized schema.
- Application/asset inventory and discovery (repos, pipelines, dependencies, owners, cloud accounts) with coverage gaps.
- Deduplication + correlation (same vuln from multiple tools; code → container → running service chains).
- Context enrichment and risk prioritization: reachability, deployed/exposed, sensitive data, ownership, EPSS/KEV.
- Policy engine / governance (SLA rules, ownership, auto-triage, pipeline guardrails).
- Remediation workflow: ticketing with two-way sync, SLAs, campaigns.
- Developer workflow integration (IDE, PR, pipeline gates).
- Reporting and compliance mapping (SOC 2, PCI DSS, NIST SSDF, ISO 27001, CRA); metrics such as MTTR, FP rate, coverage.

**Differences from adjacent categories:**
- *ASOC*: orchestration + correlation; ASPM is the superset adding risk scoring, inventory with criticality, business context, developer workflows.
- *Orchestration-only*: schedule and fan-out scans; ASPM's center of gravity is posture and risk, not scan execution.
- *CNAPP/CSPM*: cloud infrastructure misconfiguration and runtime; ASPM focuses on pre-production artifacts and consumes CNAPP output as context.
- *VM / RBVM / exposure management*: asset-centric (hosts, CVEs); ASPM is application-centric (apps, repos, services, CWE and CVE). Converging into "unified exposure management".

Sources: https://cyberdefenders.org/cybersecurity-glossary/asoc-vs-aspm/ , https://apiiro.com/resource/gartner-innovation-insight-for-aspm/ , https://www.armorcode.com/blog/appsec-aspm-goes-mainstream , https://phoenix.security/gartner-aspm-insight , https://cycode.com/blog/application-security-posture-management-aspm-key-components/

## 2. ArmorCode

- **Integrations**: "375+" claimed (SAST, DAST, SCA, IAST, MAST, container, IaC, CSPM/CNAPP, secrets, API security, pentest, ticketing, chat, CI/CD).
- **Data model**: *Products* and *Sub-Products* with metadata (ID, environment, team ownership, tool integrations). *Environments* are attributes on sub-products. *Findings* are normalized records. *Tool Mapping* binds each connected scanner instance to product / sub-product / environment. *Sub-Findings* / occurrences = per-tool raw records merged into one finding (unverified against official docs).
- **Hierarchies / business units**: N-level, parallel organizational / technological / ownership trees built on tags; globally selectable to filter dashboards, findings, reports, SLA adherence. MSSP tenant segregation claimed.
- **Correlation/dedup**: deterministic fingerprint (normalized CWE, CVE, package coordinates, rule ID, file path/line range) then an AI correlation engine (GA May 2024) linking findings across tools and asset types. "Context Risk Graph" correlates findings, assets, repos, cloud resources, identities, network topology, ownership; attack paths.
- **Adaptive Risk Score**: (a) normalized technical severity (tool base severity, CVSS, tool weighting), (b) exploitability (KEV, EPSS, public exploits, threat intel), (c) exposure and business context from asset tags with risk weightings (internet exposure, PCI/PII, criticality, compensating controls). Recomputes on signal change; rolls up to sub-product / product / hierarchy.
- **SLA**: per combination of criticality, team and asset class (e.g. 7 days critical PCI vs 30 internal); adherence per hierarchy.
- **Remediation tickets**: Jira, ServiceNow (incl. VR app), Azure Boards, GitHub/GitLab Issues; routing rules; duplicate consolidation into one ticket.
- **Runbooks** (automation): trigger on new finding → filter → actions (update severity/category/due date/owner, create ticket, notify, escalate); no-code builder.
- **AI (Anya)**: NL querying, triage, remediation guidance, blast radius, MCP server.
- **Compliance**: SOC 2, ISO 27001, PCI DSS, EU CRA evidence bundles; exceptions with owner, expiry, justification.
- **Enterprise**: SAML, OIDC, SCIM (Okta listing); RBAC; audit log; SaaS primary, air-gapped sales-led. Cons: no own scanners, opaque pricing.

Sources: https://www.armorcode.com/platform , https://www.armorcode.com/blog/armorcode-hierarchies , https://www.armorcode.com/blog/introducing-armorcode-risk-prioritization , https://www.armorcode.com/context-risk-graph , https://appsecsanta.com/armorcode , https://docs.praetorian.com/articles/9365466-armorcode

## 3. Other vendors

**Apiiro**: Deep Code Analysis (semantic AST model, "material changes"); Risk Graph (code, infra, people, business context; NL queries). Likelihood factors: used in code, deployed / internet-exposed, behind gateway/WAF, exploitable (EPSS/KEV), valid secret. Impact factors: active development, PII, toxic combination, shared modules, business impact, OWASP Top 10.

**Cycode**: native SAST/SCA/secrets/IaC/container + third-party ingestion; Risk Intelligence Graph; Change Impact Analysis; pipeline security (CI/CD posture, build hardening, code leakage); tunable Risk Score; no-code policy builder; audit logs; SaaS only.

**OX Security** (docs reachable): "Active ASPM" (block deployments, trigger scans); PBOM (Pipeline Bill of Materials: repo → pipeline → registry → cloud); prioritization = scanner severity ± "Severity Factors" in Reachable / Exploitable / Damage categories; roles + scopes, SAML/OIDC, audit logs + API, API keys, MCP server, SaaS / on-prem / broker. https://docs.ox.security/issue-prioritization.md

**Snyk AppRisk**: app discovery, coverage management, risk-based prioritization; Pro adds third-party ingestion and runtime context (Dynatrace, Sysdig, eBPF sensor), Backstage ownership. Risk Score 0–1000 = Impact (C/I/A, scope, criticality) × Likelihood (exploit maturity, EPSS, attack vector, malicious package, age, transitive depth, reachability). https://docs.snyk.io/manage-risk/snyk-apprisk

**Wiz Code / Wiz ASPM**: code-to-cloud Security Graph (SAST finding → repo/commit/owner → artifact → workload → internet exposure); third-party ingestion (Checkmarx, Snyk, SARIF) treated like native; "Representative" vs "Duplicate"; one ticket per consolidated finding; toxic combinations = one Issue; posture issues with SLAs; project segmentation.

**Phoenix Security**: 4D contextual risk (severity, reachability, threat intel, context); blast radius; static / runtime / container / canary-network reachability; contextual dedup across code, container, cloud.

**Legit Security**: software-factory discovery (repos, pipelines, AI models, shadow assets); CI/CD posture; secrets across SCM, Confluence, Slack; AI prioritization and remediation PRs.

**Dependency-Track (OWASP)**: CycloneDX SBOM/VEX; sources NVD, GHSA, OSV, OSS Index, Snyk, Trivy, VulnDB; EPSS; policy engine (Security, License, Operational); inherited risk score = Critical×10 + High×5 + Medium×3 + Low×1 + Unassigned×5; notifications; OIDC, LDAP, API keys; OpenAPI. https://docs.dependencytrack.org/

**Faraday**: workspaces, 150+ parsers, 26 agent types, bidirectional Jira, roles (admin, pentester, asset owner, client), LDAP/SAML/2FA; pentest-oriented.

**Kondukto (Invicti ASPM)**: orchestration + BYO data, 110+ integrations, open-source Go CLI (KDT), two-way Jira/GitHub/Azure Boards, SLA, SBOM/license risk.

**Plexicus**: native scanners + AI pentest + AI remediation PRs; XBOM (SBOM+CBOM+AIBOM) with VEX; compliance (NIS2, DORA, CRA); SaaS / self-hosted / air-gapped; MCP.

**Rapid7**: no standalone ASPM; Active Risk score 0–1000 blends CVSS 3.1 with AttackerKB, Metasploit, Exploit-DB, KEV.

**Brinqa** (docs reachable): RBVM, 260+ connectors; risk score = base (CVSS v4 → v3 → v2 → severity → 0) + Σ risk factor offsets, 0–10; asset score = max open finding score; configurable level ranges; default SLA 9–10 → 7d, 7–9 → 30d, 4–7 → 90d, 0–4 → 365d. https://docs.brinqa.com/docs/risk-scores , https://docs.brinqa.com/docs/sla

## 4. Common enterprise requirements

- **Multi-tenancy / business units**: tenant → N-level hierarchy (tags) → product → sub-product/service → environment; every finding and SLA report scoped by hierarchy node.
- **RBAC + ABAC**: roles × asset scopes (OX), fixed roles (Faraday), advanced RBAC (DefectDojo Pro).
- **SSO**: SAML and OIDC table stakes; SCIM provisioning (ArmorCode via Okta).
- **Audit logging**: append-only, exportable, API-accessible (OX).
- **Data retention / exports**: compliance evidence bundles, CSV/PDF, SBOM exports, audit-log export; zero-retention / EU residency as differentiators.
- **API-first**: OpenAPI everywhere; MCP endpoint is a 2025–26 expectation.
- **Rate limits**: none documented; plan per-token quotas for bulk ingestion.
- **Deployment**: SaaS, on-prem, broker for private networks, air-gapped; HA implied by Kubernetes.

## 5. Risk-scoring inputs and SLA matrices

**Inputs**: CVSS base (v3.1/v4) and vendor severity with tool weighting; exploit maturity (Metasploit, Exploit-DB, VulnCheck); EPSS; KEV (incl. VulnCheck KEV); reachability (static / runtime / container / network); asset/business criticality; internet exposure / deployed-to-prod; data sensitivity (PII/PCI); compensating controls (WAF/gateway); toxic combinations / attack paths; secondary: vuln age, package popularity, transitive depth, malicious package.

**Formula patterns**: Brinqa additive "base + Σ factor offsets on 0–10 with configurable level ranges" (fully documented); Snyk "impact × likelihood on 0–1000"; Dependency-Track severity-count-weighted portfolio score; OX "scanner severity ± severity factors".

**SLA matrices**:
| Source | Critical | High | Medium | Low |
|---|---|---|---|---|
| Brinqa default | 7d | 30d | 90d | 365d |
| DefectDojo default | 7d | 30d | 90d | 120d |
| Palo Alto Cortex | 7d | 14d | 30d | 90d |
| FedRAMP Rev 5 | 30d | 30d | 90d | 180d |
| FedRAMP VDR (Dec 2026) | 4d if exploitable + internet-reachable, 14d exploitable, 30d reachable | | | |
| CISA BOD 19-02 | 15d | 30d | | |
| PCI DSS | high-risk within 30d | | | |

Design implication: SLA = f(risk level, asset tier, exploitability flags, exposure) with hard caps from regulatory feeds (KEV due dates), escalation thresholds, time-boxed exceptions.

## 6. Out of scope of core ASPM but present in DefectDojo

Engagement management (pentest scheduling, leads, test strategy), questionnaires/surveys, credential manager, ASVS benchmarks, test-type / tool configuration and scan scheduling, notes threads, finding templates, "Sensei" tutoring. Keep these out of the core domain; optional modules at most.

## 7. Design takeaways

1. Core domain: Tenant → Hierarchy → Product → Sub-product/Service → Environment; asset types (repo, pipeline, artifact, workload, host, API); tool instance binding; Finding ← Occurrences (per-tool raw records); Vulnerability (CVE/CWE/GHSA); Policy; SLA rule; Ticket link; Risk acceptance.
2. Ingestion: SARIF + CycloneDX/VEX + per-tool parsers; reimport with separate reimport-hash vs dedup-hash.
3. Scoring: pluggable explainable additive model with recompute on intel updates; per-finding "why".
4. Policy/SLA engine over hierarchy, asset tier, exploitability flags; regulatory caps; exceptions with expiry.
5. Workflow: runbook automation (trigger → filter → actions); two-way Jira/GitHub/ServiceNow with consolidated tickets.
6. Enterprise: SAML/OIDC + SCIM, roles × scopes, append-only audit log, OpenAPI + MCP, Kubernetes/Helm, air-gap-friendly feeds.
