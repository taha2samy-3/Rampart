# 24 — Business value: Rampart against the products already on the market

Written 2026-11-16, rewritten the same day from market sources. It answers one question: **why would anyone choose Rampart over what they can buy or download today?** Every market fact has a source at the end. Vendor claims are marked as vendor claims, and figures from aggregators as secondary. Where sources disagree, both figures are given. What Rampart has built today is in [09](09-roadmap.md) and [23](23-phase-3-design-review.md); this document never counts as done what is only planned.

## 1. The short answer

The ASPM market is real, small and consolidating. It is worth about $0.7 billion a year (2025) and is growing at about 9 % a year. The independent vendors are being bought by scanner and cloud-security companies:
- CrowdStrike bought Bionic.
- Wiz bought Dazz, and Google then bought Wiz for $32 billion.
- Snyk folded its ASPM product into its Enterprise plan.

Self-hosted ASPM exists. Black Duck, Invicti (formerly Kondukto), OX Security and Checkmarx sell on-prem or air-gapped options, but only as enterprise contracts with unpublished prices. The one open-source option, DefectDojo, moved single sign-on and role-based access into its paid tier in version 3.0. That paid tier is metered at $0.15 per finding.

**Rampart's opening** is the space between those two:
- open and self-hosted, like DefectDojo;
- with the enterprise basics in the core (SSO, per-application roles, multi-tenancy, KEV and EPSS in an explained score), which competitors sell;
- configured as Kubernetes resources, which none of the products reviewed here document;
- independent of any scanner vendor.

**Rampart's weaknesses are just as concrete:**
- about twenty integrations against hundreds;
- no scanners of its own;
- no AI features;
- no reachability analysis;
- no customer references.

## 2. The market in numbers

| Fact | Figure | Source quality |
|---|---|---|
| ASPM software market | about $705 M in 2025, $763 M in 2026, about $1.31 B by 2032 (9.2 % a year) | one research firm's published summary (360iResearch); other reports are paywalled |
| Gartner's expected adoption | 80 % of regulated organisations using application security testing to adopt ASPM by 2027 | Gartner via vendor summaries (the report is paywalled) |
| CrowdStrike buys Bionic (ASPM) | $239.7 M per CrowdStrike's SEC filing (press reported about $350 M), September 2023 | SEC filing |
| Wiz buys Dazz (ASPM, remediation) | about $450 M, November 2024 | press, citing sources |
| Google buys Wiz | $32 B in cash, closed 11 March 2026; Wiz keeps its brand inside Google Cloud | Google press release |
| ArmorCode | $16 M new funding in March 2026, $81 M raised in total (CB Insights: $83.5 M) | company press release |
| OX Security | $60 M Series B, May 2025 | press |
| Apiiro | says its ARR grew 104 % in 2025 and that it closed the four largest enterprise ASPM deals to date | vendor claim |
| CVEs published | about 48,000 in 2025 (about 40,000 in 2024) | independent counts, sources differ by a few percent |

**What the numbers say.** Money and buyers are there. The category is also being absorbed into larger platforms that sell their own scanners or cloud security. A buyer who picks an ASPM owned by a scanner vendor gets a correlation layer whose owner sells one of the tools being correlated.

## 3. Who is on the market

| Product | Owner and type | Deployment | Price model (published?) | Breadth | Note |
|---|---|---|---|---|---|
| **DefectDojo** (open source) | DefectDojo Inc., open core | self-hosted | free | 200+ report formats | SSO and roles removed from the open edition in 3.0 |
| **DefectDojo Pro** | same | SaaS or self-hosted | **published:** $100 a month + $0.15 per finding processed; annual by quote (AWS Marketplace once listed a team plan at $2,145 a month for up to 20,000 findings) | 140+ API connectors, 200+ parsers | metered per finding, so noisy scanners cost money |
| **ArmorCode** | independent, venture-funded | SaaS; on-prem not documented publicly | by active developers and AI usage, by quote; AWS Marketplace entry from $4,500 a year | 320–375+ integrations claimed | leading independent; pushing "agentic AI" |
| **Apiiro** | independent | not confirmed by the sources read | by quote | deep code analysis, risk graph | strong in large enterprises (vendor claim) |
| **OX Security** | independent | SaaS and **on-prem** (documented) | by quote | pipeline security, PBOM | |
| **Cycode** | independent | SaaS; on-prem listed by an aggregator only | by quote | own scanners + ingestion | bought Bearer (code scanning) |
| **Snyk (AppRisk)** | scanner vendor | SaaS | Team $25 per developer per month; Enterprise by quote (median about $45,000 a year per Vendr data, secondary); AppRisk folded into Enterprise in late 2025 | Snyk's scanners first, third-party ingestion | an ASPM from the company selling the scanner |
| **Wiz (Wiz Code, Dazz)** | Google Cloud | SaaS | by quote | code-to-cloud graph | now part of Google |
| **Checkmarx One ASPM** | scanner vendor | SaaS; self-managed in a private GovCloud; on-prem air-gapped only for SAST | by quote | Checkmarx scanners + others | |
| **Black Duck Software Risk Manager** (formerly Code Dx) | scanner vendor | SaaS, on-prem, Kubernetes (Helm), **air-gapped** | by quote | 150+ tools | closest to Rampart's deployment model; enterprise sale |
| **Invicti ASPM** (formerly Kondukto) | scanner vendor (DAST) | on-prem and **air-gapped** (vendor statement) | by quote | 110+ integrations | |
| **Aikido** | independent, SMB-focused | SaaS | **published:** free for 2 users; $350 / $700 / $1,050 a month for 10 users | bundles its own scanners | the "all-in-one for small teams" end |
| **Brinqa** | independent, risk-based vulnerability management | SaaS | by quote | 260+ connectors | asset-centric rather than application-centric |

What this table shows:
1. **Self-hosted is not unique.** Black Duck SRM, Invicti and OX offer it, and SRM supports air-gapped. All three are enterprise sales with unpublished prices, and two of the three are owned by scanner vendors.
2. **Published prices exist only at the edges:**
   - Aikido (SMB, SaaS, its own scanners);
   - Snyk Team (per developer);
   - DefectDojo Pro (per finding).
3. **Nobody documents configuration as code.** None of the products reviewed documents its policies, applications and connectors as Kubernetes resources reviewed in Git. They are configured in admin screens or APIs. This was checked against the documentation that could be read, not against every product's internals.
4. **The open-source option is DefectDojo, and its open edition lost SSO and roles in 3.0.** Its users also report the performance limits at scale listed in [research/01](research/01-defectdojo.md) §8:
   - imports of more than 1,000 findings take minutes;
   - filters take minutes at 5 million findings;
   - editing a finding takes 50 s at 100,000.

## 4. Where Rampart can win

Each segment below is a buyer the incumbents serve badly, with the reason taken from section 3.

| Segment | What they have today | Why it hurts | What Rampart offers | Status |
|---|---|---|---|---|
| **DefectDojo open-source users who outgrew it** | DefectDojo 3.x | No SSO or roles without Pro. Pro costs grow with findings ($0.15 each): 50,000 findings processed in a month is $7,600 at the published rate. Slow at scale | SSO with several identity providers, roles per application, multi-tenancy, in the core; rescans that update and close correctly; a migration path (DefectDojo-compatible import, A17, planned) | core built; migration tool not built |
| **Regulated organisations that must self-host but will not sign a six-figure contract** (banks, public sector, defence suppliers, health) | spreadsheets, DefectDojo, or an enterprise on-prem quote | Black Duck SRM, Invicti and OX on-prem are sold by quote to large buyers | the same deployment model (self-hosted, Kubernetes, air-gapped planned) with an open core | self-hosted built; air-gapped bundle is v1.0 (Phase 4) |
| **Platform teams that run everything as code** | admin screens | security policy lives outside Git and outside review | deadlines, risk rules, applications, identity providers and connectors as Kubernetes resources, reconciled by an operator, with status conditions; `rampart apply` without Kubernetes | built (D41, D55, D63, D64, D69) |
| **Buyers who want a neutral layer** | an ASPM owned by Snyk, Checkmarx, Black Duck, Invicti or Google | the correlation layer is sold by the company selling one of the scanners | no scanner of its own; standard formats in and out (SARIF, CycloneDX, SPDX, OpenVEX; VEX, CSV, JSON, OCSF) | built; OCSF class needs correcting (23 E1) |
| **Managed security providers** | per-customer instances or a SaaS ASPM licence | multi-tenancy is rare in open tools | tenants isolated in the database itself (row-level security), per-tenant identity providers | built; tenant self-service is Phase 5 |
| **Dependency-Track users** | DT pushes FPF exports to DefectDojo on a schedule | one-way, no events, no mapping | Dependency-Track as a source: webhooks, project mapping, triage import | **designed; the sync is not wired into the server yet (23 K5)** |

## 5. Where Rampart loses today, and what closes it

| Gap | Against whom | Closes it | When |
|---|---|---|---|
| About 20 integrations against 140–375+ | ArmorCode, DefectDojo, Brinqa, Black Duck | the integration SDK and installable plugins (23 §6); SARIF and CycloneDX already cover tools that emit them | plugin design, then Phase 4–5 |
| No scanners of its own | Aikido, Snyk, Cycode, Checkmarx | by design: Rampart is the neutral layer. It does not suit a buyer who wants one tool for everything | not planned |
| No AI triage or AI remediation | ArmorCode, Apiiro, DefectDojo Pro | not planned. The explainable score is the counter-argument; an MCP server is P2 | P2 |
| No reachability or deep code analysis | Apiiro, Snyk, Phoenix | reachability is consumed from other tools, not computed (01 D7) | P2 |
| No SaaS offering | everyone selling SaaS | a managed single-tenant offering is a business option (section 6) | open |
| No production references, no external security review, high availability not validated | everyone | v1.0 exit criteria (09 Phase 4) | Phase 4 |
| Connectors are compiled in, not installable | ArmorCode, DefectDojo Pro connectors | 23 §6 | next after the current fixes |

Saying these gaps out loud is part of the pitch. A buyer will find them anyway, and an honest gap list is what a regulated buyer expects.

## 6. Price positioning

There is no Rampart price yet: the licence and the open-core boundary are open ([09](09-roadmap.md) open decisions 1 and 2). The market gives these anchors:

| Anchor | Published figure | What it means for Rampart |
|---|---|---|
| DefectDojo Pro | $100 a month + $0.15 per finding | Per-finding metering punishes exactly what an ASPM exists to absorb, noisy scanners. A flat price per tenant or per application is simpler to defend |
| Aikido | $350–$1,050 a month for 10 users, its own scanners included | The price ceiling for small teams. Rampart should not compete there; that is a bundle, not a correlation layer |
| Snyk | $25 per developer a month (Team); Enterprise median about $45,000 a year (secondary) | Per-developer pricing is the norm buyers know |
| ArmorCode | by active developers and AI usage; Marketplace entry from $4,500 a year | The independent leader's model |
| Black Duck SRM, Invicti, OX on-prem | quote only | The self-hosted segment has no public price. A published price is itself a differentiator there |

**A defensible model to propose** (a recommendation, not a decision):
- the core is open, with SSO, roles and multi-tenancy inside it, because removing them is what DefectDojo's open users resent;
- paid: support with response times; compliance packs (FedRAMP, CRA evidence bundles); certified integrations; the air-gapped bundle with signed feed snapshots;
- priced per application or per tenant, published on the website.

## 7. What must be true before these claims are made

| Claim | Needs | Where |
|---|---|---|
| "Enterprise basics in the core" | the licence decided and published | 09 open decisions |
| "Air-gapped" | the OCI bundle and feed mirrors | Phase 4 |
| "Dependency-Track first-class" | the sync wired and settled correctly | 23 K5, DT1–DT4 |
| "Installable integrations" | the plugin design | 23 §6 |
| "Production-ready" | high availability, external security review, 5-million-finding performance | Phase 4 |
| "Faster than DefectDojo" | **not to be claimed.** Rampart's own ingest goal was missed and withdrawn (D35). What can be said: reports of any size stream in bounded memory, and rescans never double-count | D35 |

## 8. How to talk about it

### 30 seconds
"ASPM is a $700-million market that is being bought up by scanner and cloud companies. If you want one view of all your scanners' findings and you cannot send that data to a SaaS, you have two choices today: an enterprise contract with a quote-only price, or DefectDojo, whose free edition dropped single sign-on and roles. Rampart is the third option: open, self-hosted on your Kubernetes, with SSO, roles, multi-tenancy and an explained risk score in the core, configured as code, and owned by no scanner vendor."

### Answers to the questions that will come
| Question | Answer, with the fact behind it |
|---|---|
| "Why not DefectDojo?" | Its open edition removed SSO and roles in 3.0. Pro is $0.15 per finding, so 50,000 findings a month is $7,600. Its users report minutes-long imports and filters at scale |
| "ArmorCode is the leader, why not them?" | It is strong and has 320+ integrations. It is priced by quote per developer and AI usage, and on-prem is not publicly documented. If your data must stay in-house, or you want to own the configuration in Git, that is where Rampart fits |
| "Black Duck SRM already runs air-gapped" | True, and it is the closest model. It is an enterprise sale with no public price, from a vendor that sells one of the scanners it correlates |
| "Snyk gives us AppRisk in Enterprise" | It does, folded into Snyk Enterprise. It is SaaS, and it is Snyk's view of your other vendors' findings |
| "How many integrations?" | About twenty today, plus any tool that writes SARIF or CycloneDX. Installable integrations are the next step. Do not round this up |
| "Is it production-ready?" | No. It is a working MVP suited to a pilot; v1.0 needs high availability, the air-gapped bundle and an external security review |
| "AI?" | None. Every point of the score has a named reason, which an auditor can check and a model's output cannot |

### Do not say
- **"the only self-hosted ASPM".** Black Duck SRM, Invicti and OX are self-hosted.
- **"cheaper than X".** There is no price yet.
- **"hundreds of integrations".**
- **"production-ready".**
- **"faster than DefectDojo"**, or any throughput figure (D35).

## Sources

**Market size and adoption:**
- 360iResearch, ASPM Software market summary: https://www.marketresearch.com/360iResearch-v4164/Application-Security-Posture-Management-Software-43523152
- Frost & Sullivan, ASPM Market 2025–2030 (paywalled; scope only): https://store.frost.com/application-security-posture-management-aspm-market-global-2025-2030.html
- Gartner, as quoted by vendors: [research/02](research/02-aspm-market.md) §1.

**Acquisitions:**
- CrowdStrike–Bionic, SEC figure: https://dealroom.co/news/168660-crowdstrikes-acquisitions-what-it-paid-per-sec-filings/ (and the press report: https://www.govinfosecurity.com/crowdstrike-to-buy-appsec-startup-bionic-for-reported-350m-a-23113)
- Wiz–Dazz: https://siliconangle.com/2024/11/21/wiz-acquires-cybersecurity-startup-dazz-reported-450m/
- Google–Wiz: https://www.googlecloudpresscorner.com/2026-03-11-Google-Completes-Acquisition-of-Wiz

**Funding:**
- ArmorCode: https://www.businesswire.com/news/home/20260303648962/en/ArmorCode-Doubles-Growth-Boosts-AI-Security-Governance-with-New-Funding-and-Board-Appointment and https://www.cbinsights.com/company/armorcode/financials
- OX Security: https://www.crowdfundinsider.com/2025/05/239500-ox-security-reports-60m-series-b-to-focus-devs-on-critical-risks-as-ai-enhances-software-development/
- Apiiro (vendor claim): https://apiiro.com/news_item/apiiro-achieves-104-arr-growth-in-2025-as-fortune-500-adopt-agentic-appsec-to-reduce-massive-risk-across-the-software-development-lifecycle

**Pricing:**
- DefectDojo: https://defectdojo.com/pricing and https://aws.amazon.com/marketplace/pp/prodview-stklscizixsra
- Aikido (several aggregators, checked July 2026): https://www.capterra.com/p/10015770/Aikido/ ; https://g2.com/products/aikido-security/pricing
- Snyk: https://www.withorb.com/pricing-atlas/snyk ; https://pricingsaas.com/companies/snyk/diffs/2025Q4 ; https://us.fitgap.com/products/snyk-apprisk
- ArmorCode: https://www.rfp.wiki/it-security/application-security-testing/application-security-posture-management-tools/armorcode/apiiro

**Deployment options:**
- OX Security on-prem: https://docs.ox.security/get-started/onboarding-to-ox/prerequisites-and-access/on-prem-preparation-guide
- Invicti: https://www.invicti.com/aspm-comparison/invicti-vs-oxsecurity
- Checkmarx (FedRAMP, self-managed, SAST on-prem): https://checkmarx.com/checkmarx-fedramp/
- Black Duck SRM: https://assets.blackduck.com/images/v1777986889/ds-software_risk_manager/ds-software_risk_manager.pdf ; https://events.govexec.com/2026-fedramp-summit/download/-20260720150555-Federal_Datasheet.pdf ; https://appsecsanta.pages.dev/software-risk-manager (secondary)
- Phoenix Security, SaaS: https://www.gartner.com/reviews/market/application-security-posture-management-aspm-tools/compare/product/phoenix-security-platform-vs-checkmarx-aspm

**Other:**
- DefectDojo editions and its performance issues: [research/01](research/01-defectdojo.md); https://docs.defectdojo.com/get_started/about/defectdojo_versions/
- CVE counts: https://www.thestack.technology/cves-in-2025-analysis/
- ArmorCode, Brinqa, other vendors' integration counts: [research/02](research/02-aspm-market.md).
