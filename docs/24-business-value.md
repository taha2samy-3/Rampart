# 24 — Business value: what Rampart is worth when it is finished, and how to talk about it

Written 2026-11-16 for the conversations about the project: with management, a prospective customer, a partner or an investor. It says what problem Rampart solves, for whom, why now, what makes it different, how its value is measured, and what is true today, so nothing is promised that is not built.

The technical design is in [00](00-vision-and-scope.md) to [19](19-integration-sdk.md); the status is in [09](09-roadmap.md) and [23](23-phase-3-design-review.md). Every market fact below has a source at the end. Where a figure is an estimate or comes from a secondary source, it says so.

## 1. In one paragraph

Organisations run many security scanners: code, dependencies, containers, infrastructure, secrets, web. Each produces its own list, in its own format, with its own severity. Security teams spend their time merging those lists, arguing about what matters, chasing developers in Jira, and assembling evidence for auditors by hand.

**Rampart is one place that takes in every scanner's output, removes the duplicates, ranks what is left by real risk, sets a deadline for each issue, sends the work to the developer's own tools, and shows auditors the evidence.** This category is called Application Security Posture Management (ASPM). Rampart is built to run inside the customer's own Kubernetes cluster, configured as code, with the enterprise features that competitors sell separately included from the start.

## 2. The problem, in the customer's words

| What the customer lives with | What it costs them |
|---|---|
| Six or more scanners, six formats, the same flaw reported by three of them | Analysts triage the same issue several times; numbers in reports are inflated and not trusted |
| About 48,000 new CVEs were published in 2025 (about 40,000 in 2024) | "Fix all criticals" is not possible; without exploit data (KEV, EPSS) and business context, teams fix the wrong things first |
| Deadlines kept in spreadsheets | SLA breaches are found at audit time, not before |
| Tickets created by hand, and closed in Jira without the security record knowing | Work is lost between tools; nobody can say what is really fixed |
| Audit evidence assembled by hand for PCI DSS, ISO 27001 or SOC 2 | Days of senior time per audit, with weak evidence |
| Commercial ASPM platforms that run as SaaS only, with opaque pricing | Banks, government, defence and others who must keep vulnerability data in-house cannot use them |
| DefectDojo, the open-source reference | It is slow at scale (imports of 1,000+ findings take minutes; filters take minutes at 5 million findings) and runs as four services to operate. SSO and role-based access left the free edition in version 3.0 |

The vulnerability data itself is sensitive: it is a map of how to attack the organisation. That is the main reason the "self-hosted, in your own cluster" property matters commercially, and not only technically.

## 3. Why now

| Driver | What it requires | What in Rampart answers it |
|---|---|---|
| **EU Cyber Resilience Act**: reporting of actively exploited vulnerabilities applies from 11 September 2026; vulnerability handling and the rest apply from 11 December 2027. Fines reach €15 million or 2.5 % of worldwide turnover | Manufacturers must know which of their products carry which vulnerability, handle them, and report exploited ones fast | Inventory per application and component, KEV flag on every finding, deadlines, VEX export, SBOM via Dependency-Track |
| **PCI DSS 4.0.1**, requirement 6.3.3 | Critical and high vulnerabilities patched within 30 days of the patch | The `pci-dss` deadline preset, breach alerts, compliance view for requirement 6 (D52, D63) |
| **CISA KEV / BOD 22-01** and **FedRAMP** vulnerability rules | Known-exploited vulnerabilities fixed by CISA's due date; FedRAMP remediation timeframes | KEV due date caps every deadline; `cisa-bod`, `fedramp-rev5` and `fedramp-vdr` presets (D63) |
| **ISO/IEC 27001:2022 A.8.8** (technical vulnerabilities), **NIST SSDF** and US secure-software attestation | A managed, evidenced vulnerability process | Audit log, risk acceptance with owner, expiry and proof files, evidence export (D46, D52, D60) |
| **Gartner's ASPM category**: as quoted by vendors, Gartner expects 80 % of regulated organisations that use application security testing to adopt ASPM by 2027 (about 29 % when it said so). The report is paywalled; this is a secondary source | Buyers now have a budget line and a name for this product | Rampart is built to the capability list of that category (research/02 §1) |

## 4. Who buys, who uses, what each gets

| Person | Their question | What Rampart gives them |
|---|---|---|
| **CISO / head of security** (buyer) | "Are we getting safer, and can I prove it?" | Posture score and trend per business unit, deadline adherence, mean time to remediate, evidence for audits (D43, D62) |
| **Application security lead** (champion) | "What should my team fix first?" | One deduplicated list ranked by an explainable score: every point shown with its reason (KEV, EPSS, internet exposure, data sensitivity, criticality) (D40, D63) |
| **Developers and engineering managers** | "What do I have to fix, by when, and is my build blocked?" | Tickets in Jira or GitHub, a CI gate that blocks only *new* critical issues, "my work" view (D37, D59, D70) |
| **Platform / Kubernetes team** | "Can we run it, and keep it safe and boring?" | One binary, Helm chart, operator, configuration as Kubernetes resources reviewed in Git, no data leaving the cluster (ADR 0001, 0004; D49) |
| **Compliance and audit** | "Show me the evidence" | Framework views (OWASP Top 10 2021 and 2025, CWE Top 25, PCI DSS, ISO 27001, NIST SSDF), append-only audit log, exports (D46, D52, D58) |
| **Managed security providers (MSSP)** | "Can I serve many clients from one install?" | Tenants isolated in the database itself (row-level security), per-tenant identity providers (ADR 0005, D64) |

## 5. What makes it different

| | Rampart (when finished) | DefectDojo open source | DefectDojo Pro | Commercial ASPM (ArmorCode, Apiiro, Wiz, …) | Spreadsheets and Jira |
|---|---|---|---|---|---|
| Where it runs | Customer's Kubernetes, air-gapped possible | Self-hosted | SaaS or self-hosted | Mostly SaaS; on-prem sales-led | — |
| SSO and roles per application | Included | Removed in 3.0 | Included | Included | — |
| KEV and EPSS in the score | Included, explained point by point | Fields only, filled by scanners | Included | Included | Manual |
| Multi-tenant | From the first table | No | Not documented | Yes | — |
| Configuration | As code (Kubernetes resources, GitOps) | Admin screens (~100 settings) | Admin screens | Admin screens | — |
| Formats in and out | SARIF, CycloneDX, SPDX, OpenVEX in; VEX, CSV, JSON, OCSF out; no lock-in | Many parsers | Many parsers | 260 to 375+ connectors claimed | — |
| Dependency-Track | First-class: events, mapping, triage import | Receives DT's push | Receives DT's push | Varies | — |
| Operating it | One binary, PostgreSQL, object storage | Django, Celery, Beat, Redis, PostgreSQL | Managed or same | Vendor-managed | — |
| Pricing | Open core (licence to be decided) | Free | Subscription | Subscription, opaque | Staff time |

**The four sentences to remember:**
1. **Your data stays in your cluster.** It runs where regulated organisations need it, including air-gapped.
2. **Enterprise features in the core.** SSO, roles, multi-tenancy, KEV and EPSS are what DefectDojo charges for.
3. **Every score explains itself.** No black box: each point of the 0–1000 score has a named reason.
4. **Configured as code.** Deadlines, risk rules, applications and connectors are reviewed in Git like any other change.

Two further points matter in some markets:
- An Arabic interface is planned as a first-class language (Phase 4), which is rare in this category.
- Dependency-Track, which many teams already run, is treated as a partner rather than a competitor.

## 6. How the value is measured

Rampart already computes most of these numbers itself, so the value can be shown with the customer's own data rather than claimed.

| Value | Metric | Where Rampart computes it |
|---|---|---|
| Less noise | Raw records received vs distinct findings kept; findings grouped across tools | ingest run statistics (created, untouched); correlation groups (D37, D44) |
| Right things first | Share of open findings that are known-exploited (KEV) or high-EPSS, and how long they stay open | risk factors and filters `kev:`, `epss` (D35, D40) |
| Faster fixing | Mean time to remediate per risk band | Overview, Applications (D43) |
| Deadlines met | Deadline adherence over 90 days; breaches per business unit | Overview, hierarchy roll-ups (D43, D62) |
| Coverage | Applications with no scan in 14 days | Coverage (D43) |
| Audit effort | Time to produce evidence for a framework | Compliance export (D52) |
| Developer friction | Builds blocked only by *new* critical issues, not old ones | CI gate (D37, D57) |

**A simple model to fill in with the customer's numbers** (do not quote it with invented inputs):
- Triage time saved per month = (raw records − distinct findings) × minutes to triage one record ÷ 60 × cost per analyst hour.
- Audit time saved per audit = hours spent assembling evidence today − hours with the export.
- Exposure reduced = days a KEV vulnerability stays open today − days with KEV-capped deadlines.
- Operating cost avoided = services and infrastructure of the current tool − one binary, one database, one object store.

**Prove it with a pilot.** Four to six weeks, one business unit, its real scanners:
1. Week 1: connect the scanners and record the baseline (raw vs distinct findings, open KEV issues, deadline adherence).
2. Weeks 2 to 5: triage and fix in Rampart.
3. Last week: compare the same numbers.

The pilot's report is the business case.

## 7. How it can make money (options, not decisions)

The licence and the open-core boundary are still open ([09](09-roadmap.md) open decisions 1 and 2; Apache-2.0 is proposed in D7). The usual options in this market:

| Model | Who pays | Fits Rampart because | Watch out |
|---|---|---|---|
| Open core + enterprise subscription | Larger organisations | The core is useful alone and spreads; enterprise extras (support, SLAs, compliance packs, plugin certification) are sold | DefectDojo was criticised for moving SSO and roles to Pro: decide the boundary once, publicly |
| Support and services | Regulated organisations self-hosting | Self-hosting needs installation, upgrades, integration work | Services scale with people, not software |
| Managed hosting (single-tenant per customer) | Teams without a platform team | Same product, operated for them | Competes with the "your data stays with you" message unless single-tenant |
| MSSP licence | Security providers | Multi-tenancy is built in | Needs tenant self-service (Phase 5) |
| Integration catalogue and partners | Scanner vendors | Doc 19's "Verified" level: vendors maintain their own integration | Needs the plugin model finished first (23 §6) |

## 8. What is true today (say this, not more)

| Status | What |
|---|---|
| **Built and tested (the MVP, Phases 0 to 2)** | Ingest of SARIF, CycloneDX, SPDX and native reports (Trivy, Grype, Semgrep, Gitleaks, TruffleHog, Checkov, Bandit, Nuclei, ZAP, Dependency-Check, Snyk, kube-bench, Prowler); duplicates and rescans handled; triage; risk acceptance with approval and proof; explainable score with KEV and EPSS; deadlines with PCI, FedRAMP and CISA presets; compliance views; audit log; retention; roles per application; sign-in with several identity providers; CLI and CI gate; VEX in and out; operator and Helm chart; tenants isolated in the database |
| **Built in part (Phase 3)** | Slack, Teams, e-mail, webhooks, Jira and GitHub connectors work, but are built into the core rather than installable plugins. The Dependency-Track sync is written but not yet running in the server. Exports, groups and live updates have gaps. Details: [23](23-phase-3-design-review.md) |
| **Not yet (v1.0, Phase 4)** | High availability validated, air-gapped bundle, SAML, performance proven on 5 million findings, external security review, Arabic interface |

**Do not say:**
- **a throughput figure.** The 100,000-results-in-60-seconds goal was measured, not met (about 130 s), and withdrawn (D35). Say instead "streams reports of any size in bounded memory and never double-counts".
- **"hundreds of integrations" or "install any tool as a plugin".** Not until 23 §6 is built.
- **that it scans code.** It does not, by design. It works with the scanners the customer already has.
- **that it uses AI.** It does not today, and the explainable score is the selling point.
- **"production-ready".** That is v1.0. Today it is a working MVP suited to a pilot.

## 9. How to talk about it

### 30 seconds
"Every security scanner your teams run produces its own list. Rampart puts them in one place, removes the duplicates, ranks what is left by real risk (whether it is actively exploited, whether it is on the internet, what data it touches), gives each issue a deadline, and sends it to the developer's Jira. It runs inside your own Kubernetes cluster, so the map of your weaknesses never leaves your hands."

### Two minutes
Use this order:
1. **The problem** (section 2): too many scanners and duplicates, 48,000 CVEs a year, and evidence assembled by hand.
2. **Why now** (section 3): CRA reporting since September 2026, PCI DSS 6.3.3.
3. **What it does:** ingest → deduplicate → score with reasons → deadline → ticket → evidence.
4. **Why this one** (section 5): your data stays with you, enterprise features in the core, explainable, as code.
5. **The ask:** a pilot on one business unit with its real scanners, measured on the numbers in section 6.

### By audience
| Talking to | Lead with | Show |
|---|---|---|
| CISO | Proof of improvement, audit readiness, data stays in-house | Overview trend, deadline adherence, compliance view |
| AppSec lead | One ranked list, every score explained | Finding with its score breakdown; "also reported by" |
| Engineering manager | Only new criticals block the build; tickets in their tool | CI gate result; Jira ticket |
| Platform team | One binary, Helm, GitOps, NetworkPolicy, no egress needed | A `ScanSource` and `SLAPolicy` in Git, `Ready=True` |
| Compliance | Evidence on demand, append-only audit log | Framework CSV export; risk acceptance with proof and expiry |
| Investor or management | Growing category, regulation pushing it, gap for self-hosted and open | Sections 3, 5 and 7 |

### Questions you will be asked
| Question | Answer |
|---|---|
| "Why not DefectDojo?" | Its own users report minutes-long imports and filters at scale. It runs as four services. Since 3.0, SSO and roles are paid-only. Rampart keeps DefectDojo's good ideas (rescans, risk acceptance, Jira) and fixes those (research/01 §8) |
| "Why not ArmorCode or Wiz?" | They are strong, and mostly SaaS. If the vulnerability data must stay inside your network, or you need air-gapped, they are hard to adopt. Rampart is built for exactly that |
| "Does it replace our scanners?" | No. It makes the scanners you already pay for useful together |
| "Is it ready?" | The core workflow is built and tested and is ready for a pilot. Production v1.0 needs high availability, the air-gapped bundle and a security review (section 8) |
| "What about our data?" | It never leaves your cluster. Tenants are isolated in the database itself; secrets are encrypted; every action is in an append-only audit log |
| "Can it integrate with tool X?" | Today, if X writes SARIF or CycloneDX, yes. Native parsers cover the common tools. Installable integrations without a release are the next step (23 §6) |
| "What does it cost?" | Still open (section 7). For a pilot: infrastructure only, one database and one object store |

## Sources

**Project documents (the basis for every claim about Rampart):**
- [00](00-vision-and-scope.md), [01](01-features.md), [09](09-roadmap.md), [16](16-implementation-decisions.md) (the D-sections named in the text), [19](19-integration-sdk.md), [23](23-phase-3-design-review.md);
- ADR 0001, 0004, 0005;
- [research/01](research/01-defectdojo.md): DefectDojo, with its issue numbers;
- [research/02](research/02-aspm-market.md): the market, Gartner as quoted by vendors, ArmorCode, others.

**CVE counts:**
- The Stack, "CVEs in 2025" (48,185 published in 2025; other counts range from about 46,400 to 49,200 by source and date): https://www.thestack.technology/cves-in-2025-analysis/
- Socket, citing Jerry Gamblin's count (39,962 in 2024): https://www.plushcap.com/content/socket/blog/socket-cve-volume-surges-past-48000-in-2025-as-wordpress-plugin-ecosystem-drives-growth

**EU Cyber Resilience Act:**
- European Commission, CRA reporting: https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- Ireland NCSC, CRA: https://ncsc.gov.ie/cra/
- PwC on the September 2026 reporting obligations: https://www.pwc.ch/en/insights/regulation/eu-cyber-resilience-act.html

**Other regulation and standards:**
- PCI DSS v4.0.1, requirement 6.3.3;
- CISA BOD 22-01 and the KEV catalogue: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FedRAMP rules as recorded in D63;
- ISO/IEC 27001:2022 Annex A 8.8;
- NIST SP 800-218 (SSDF).
