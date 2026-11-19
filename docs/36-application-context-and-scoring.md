# 36 — The application's context, the Application resource, and the score

Status: a position paper for the owner, 2026-11-18. Everything marked **(code)** was read in this repository in the last hour and has a file reference. Everything marked **(standard)** is what a published standard defines; those statements are from my knowledge of the texts and are **not yet checked against the primary sources** (the research job on the standards is still running; section 10 lists what it must confirm). Section 11 reports the job on other products, which has returned. Nothing in this document was run against a cluster.

## 1. The short answer

1. **Why is the application a resource (a CRD)?** Because Rampart keeps *desired state in Git and findings in PostgreSQL* (ADR 0001, 2026-11-10), and because the same YAML must work with and without Kubernetes (D3). An application's business context (how critical it is, whether the internet reaches it, what data it holds) is exactly the kind of decision a team should review in a pull request, not click in a form. The `Application` CRD was added with the operator in the first commit that has it, 2026-11-11; D55 (2026-11-12) made it reach the stored score; D56 added selectors; D102 added `complianceScope`.
2. **Which attributes of the application help the score?** Four are read today: `businessCriticality`, `internetFacing`, `dataClassification` (only `pci`, `pii`, `phi` count) and `compensatingControls` (only `waf` and `apiGateway`, and only on findings of a dynamic scan). Section 3 has every field and who reads it.
3. **Your idea is right in direction and incomplete in two places.** Context does change priority; the standards say so. But (a) *environment* is not an attribute of the application, it belongs to where a finding was found, and today the score reads it from the **name of the branch or environment of the scan** (`production` or `prod`), so a repository scanned on `main` never gets the production points, and the application's `lifecycle` field has no effect at all; (b) *internet-facing* is a yes/no, while SSVC (to confirm) has three exposure levels and one product read in section 11 has external / internal / unknown; most products read keep a yes/no.
4. **Four things I found that are wrong or missing** (section 5): the CRD lacks two fields the code reads (`lifecycle`, `hierarchy`), so a Kubernetes API server will drop them; docs/04 designed `environments` and `services` and neither exists; docs/06 lists three scoring factors that are not in the built-in policy; and the Policies page shows SLA numbers written by hand that do not match the real ones.
5. **What I recommend** (section 7): keep the Application resource as the single place a team declares context; add an `environments` list to it (the design in docs/04 already had it) with an exposure level for each; make the score read the environment of the *finding*, resolved through that list; keep `internetFacing` as a derived value; and say on screen when an application is still at its defaults.

## 2. Why an Application resource: the history and the reasons

| Date | What | Source |
|---|---|---|
| 2026-11-10 | ADR 0001: CRDs carry desired state and bounded status; findings, occurrences, vulnerabilities and audit rows live in PostgreSQL; no resource grows with the number of findings. `Application` is on the list | `docs/adr/0001-crds-for-config-not-findings.md` |
| 2026-11-10 | D1: only the operator talks to the Kubernetes API and reads Secrets | `docs/16` D1 |
| 2026-11-10 | D3: the reconcile logic is a library (`internal/config/apply`) that turns the resource YAML into rows; the operator and `rampart apply -f` both call it, and Docker Compose mounts `/etc/rampart/resources/*.yaml`. So the resource is the product's configuration language, with or without Kubernetes | `docs/16` D3 |
| 2026-11-11 | The CRD file and the operator first appear | `git log -- deploy/crds/application.yaml` (commit `a27f7d7`) |
| 2026-11-12 | D55: the Application resource reaches the stored score. Found first: data classification was never stored, a change to criticality was lost on the second apply, the CLI and the operator mapped the resource differently, compensating controls had no field | `docs/16` D55 |
| 2026-11-12 | D56: selectors attach repositories and images to an application; the asset-to-application link had never been stored | `docs/16` D56 |
| 2026-11-16 | D102: `complianceScope` lets a framework select applications | `docs/16` D102 |

**The reasons, in the project's own words.** A CRD holds *desired state*; the UI is for reading and for work that is not configuration (docs/13 section 4: "Objects managed by a CRD show a 'Managed by Kubernetes' badge, are read-only in the UI, and offer 'View YAML' and 'Copy kubectl command'. Objects created in the UI offer 'Export as YAML' so teams can move them to GitOps"). A wrong value moves the score of every finding of the application, so it should have a review trail, which Git gives for free.

**Who owns a row** (D49, D55; `application.managed_by`): `crd` means a resource owns it, and a change made anywhere else would be undone by the next reconcile; `none` means ingest made it (a scan arrived before anyone described the application) and a resource of the same name may adopt it; `ui` means a person made it and no resource touches it.

## 3. What an Application carries today, field by field **(code)**

The resource spec is `domain.ApplicationSpec` (`internal/domain/application_spec.go:14`); the CRD schema is `deploy/crds/application.yaml` (the Helm copy is identical); the row is `domain.Application` (`internal/domain/entities.go:33`).

| Field (resource) | Values | Default | Read by | Effect on the score or the deadline |
|---|---|---|---|---|
| `displayName` | text (required) | the slug | everywhere | none |
| `businessCriticality` | low, medium, high, critical | **medium** | the score; the SLA | `critical` +100, `high` +50 (`APP_CRITICAL`, `APP_HIGH`); also chooses the **column of the deadline table**. A finding whose application is unknown is treated as `low` (`internal/scoring/scoring.go:219`) |
| `internetFacing` | true / false | **false** | the score | +100 (`INTERNET_FACING`) |
| `dataClassification` | pii, pci, phi, secret, public | none | the score | any of `pci`, `pii`, `phi`: +80 once (`SENSITIVE_DATA`). `secret` and `public` are stored and change nothing |
| `compensatingControls` | waf, apiGateway, mtls, privateNetwork | none | the score | `waf` or `apiGateway` on a finding of a **dynamic scan**: −80. `mtls` and `privateNetwork` are recorded and change nothing (D55: the exposure factor already carries who can reach the application) |
| `complianceScope` | free labels, e.g. `pci-dss`, `soc2` | none | compliance frameworks | none on the score; selects which applications a framework evaluates (D102) |
| `selectors` | repositories, images (workloads refused) | none | ingest | none; attaches assets to the application (D56) |
| `owners` | list of text | none | stored | none (no code reads it besides storing it) |
| `lifecycle` | planning, development, production, deprecated | **production** | stored | **none** |
| `hierarchy` | path of names | none | roll-ups (D62) | none on a finding's score |
| (`description`, `tags`) | | | in the row | `tags` cannot be set by a resource |

The built-in risk policy (`internal/risk/policy.go:107`, `BuiltinSpec`) has twelve factors; the four above are its whole "application" part. The deadline comes from the band of the finding and the criticality of the application (`domain.DefaultSLAPolicy`, `internal/domain/sla.go:21`).

**One more input that looks like context and is not an application field:** `PRODUCTION_ENV` (+60) is `finding.track in ["production", "prod"]` (`policy.go:121`). The track is the environment name of the upload if the pipeline passed one (`--environment`), else the **branch name**, else `default` (`internal/ingest/resolution.go:242`). So the production points depend on what a pipeline calls its branch or environment, and the application resource has no say.

## 4. How a score is made, with the numbers in force **(code)**

`score = clamp(base(severity) + Σ factors, 0, 1000)`. Bands: critical from 800, high from 600, medium from 300.

| Group | Factor | Points | Reads |
|---|---|---|---|
| Severity | critical / high / medium / low / info | 600 / 400 / 200 / 80 / 10 | the finding |
| Threat | CISA KEV | +300 | feed |
| | EPSS ≥ 0.5 / ≥ 0.1 | +150 / +60 | feed |
| | exploitation reported by another source | +300 | feed |
| | weaponized public exploit | +120 | feed |
| | secret verified live | +250 | scanner |
| Context | internet-facing | +100 | **application** |
| | sensitive data | +80 | **application** |
| | application critical / high | +100 / +50 | **application** |
| | found in production | +60 | **the finding's track** |
| Reduction | WAF or API gateway, dynamic scan only | −80 | **application** |

The page `/about` (new) shows exactly this, read from the policy in force through `GET /api/v1/scoring`, not copied by hand. A tenant or cluster `RiskPolicy` can replace any of it; the CEL conditions can read `finding.*`, `vuln.*` and `app.*` and nothing else (`internal/risk/policy.go:56`, `celEnv`). **A new application field is invisible to a policy until it is added to `AppInput` and to the CEL environment.**

## 5. What is wrong or missing **(code)**

1. **The CRD drops two fields the code reads.** `ApplicationSpec` has `lifecycle` and `hierarchy`; `deploy/crds/application.yaml` does not list them and does not set `x-kubernetes-preserve-unknown-fields` on `spec`. A Kubernetes API server with a structural schema prunes fields the schema does not describe **(standard behaviour of `apiextensions.k8s.io/v1`; I cannot confirm it on a cluster)**. `rampart apply -f` reads the YAML directly and keeps them. So the same file would behave differently in the two modes. No test compares the CRD with the Go spec (no test file names `crds/application.yaml`). Fix: add both fields to the schema, and add a parity test.
2. **docs/04 designed more than was built.** Its example has `environments: [{name: prod, kind: prod, internetFacing: true}, {name: staging, kind: staging}]`, `services`, `tags`, and `owners` as objects (`team:` / `user:`). The schema and the Go spec have none of the first three, and `owners` is a list of strings. The database already has `asset.environment_id` and `asset.service_id` columns (`internal/domain/entities.go:80`) that **nothing writes**.
3. **`lifecycle` does nothing**, and the production points read the track name. So `lifecycle: production` on the resource and `main` as the branch give no production points, and `--environment production` in a pipeline gives them even when the application's lifecycle says `development`.
4. **docs/06 lists three factors the built-in policy does not have**: fix available (+20), unreachable (−200), age over 90 days (+30). Either the policy or the document is wrong; today the document is.
5. **The Policies page is not real.** `web/src/routes/policies/PoliciesRoute.tsx` shows an SLA table written by hand (critical 7 days, high 30, ...) with grace periods and routing that no code implements. The real matrix is 3 to 365 days by band and criticality (section 4).
6. **Missing means low.** An application with nothing declared scores as `medium` criticality, not internet-facing, no sensitive data, no controls. There is no mark on screen that says "this application has not been described", so a team that never writes the resource gets the lowest context points and does not know it.
7. **Not the application, but the same family:** the product has `Asset.Type` (repository, image, host, package ...) and a track (the branch or the environment) per run, so "type" and "version" already exist; they are not shown to the user.

## 6. Your ideas, one by one

| Idea | Does it exist? | My view |
|---|---|---|
| Choose the application's **environment**, production or dev | Only as the track name of the scan, and as the unused `lifecycle` | **Yes, but not as one value on the application.** One application runs in several environments at once. Declare the environments in the resource (a list) and map the branches and environment names to them; the score then reads the environment of each finding |
| Say whether the application is **internet-facing** | Yes, a yes/no on the application | Keep it, and make it derivable: declare an **exposure per environment** (internet, internal, isolated). Production on the internet and staging behind a VPN are different risks. Evidence is mixed: most products read use a yes/no (DefectDojo, Qualys, Conviso), one uses external / internal / unknown (Cortex), SSVC has three levels. I would add the levels because the environment list makes them free, and keep the yes/no as the default |
| Say whether it holds **PCI or PII** | Yes: `dataClassification` (`pci`, `pii`, `phi`, `secret`, `public`) | Right as it is. `secret` and `public` change nothing today; either give them a meaning in the policy or say so on screen (the Settings tab I drafted does) |
| An application **type**: repository, machine | Yes, on the asset (`repository`, `image`, `host`, ...), not on the application | Show it. An application is a *product* made of assets; "type" belongs to each asset |
| **Version = a tag or a branch** | Yes: the track of each run (branch, tag or environment) | Show the track as the version in the asset list and the SBOM tab. No new field is needed |
| Put **everything about the application in the resource** | Mostly yes (section 3); the UI edit I added this session is the exception | Agree for everything a *person decides*. Not for what is *discovered* (assets, versions, SBOM) or *derived* (score, counts): those must never be in the resource (ADR 0001) |

**Is "more attributes means a better score" true?** Only up to a point. The standards use context to *adjust* a vulnerability's priority, in a few coarse steps, with a rule that is published. More fields that people must fill in correctly, and that move every finding by dozens of points, add precision nobody can check. Each field needs a clear definition, a safe default and an owner. I would add **one** field with real value (environment with exposure) and fix the ones that exist, and not more.

## 7. The model I recommend

> **Read section 14 first.** This section assumes one application per repository, with the branches as tracks inside it, which is how the product works today. The owner's rule is that every branch is its own application; that changes what is right here.

**Three kinds of fact, kept apart:**

| Kind | Where it lives | Examples |
|---|---|---|
| **Declared by a person**, reviewed in Git | the `Application` resource | criticality, owners, data classes, compensating controls, compliance scope, environments and their exposure, selectors, lifecycle |
| **Discovered** by the product | assets, runs, the SBOM | asset type, key, track (branch / tag / digest), components, versions |
| **Derived**, never written by hand | `status` and PostgreSQL | risk score, counts, posture, last ingest |

**The addition, sketched** (all fields optional, so every existing resource stays valid):

```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: Application
spec:
  displayName: Payments API
  businessCriticality: critical
  dataClassification: [pci, pii]
  compensatingControls: [waf]
  complianceScope: [pci-dss]
  lifecycle: production
  environments:                       # new (designed in docs/04, never built)
    - name: production
      kind: production                # production | staging | test | development | dr
      exposure: internet              # internet | internal | isolated
      tracks: [main, "release/*", production]   # the branches or environment names that mean this environment
    - name: staging
      kind: staging
      exposure: internal
      tracks: [staging]
  # internetFacing stays accepted: it means "exposure: internet" for an application with no environments list
```

**How the policy reads it:** the resolution of a run finds the environment whose `tracks` match, and the scorer passes `finding.environment` (the kind) and `finding.exposure` to the CEL environment next to the existing variables; `PRODUCTION_ENV` becomes `finding.environment == "production"`, and `INTERNET_FACING` becomes `finding.exposure == "internet"`. A finding of a run that matches no environment keeps today's behaviour (the track name is `production` or `prod`; the application's `internetFacing`), so nothing changes for anyone who does not opt in. It is an additive change (expand-only, D124).

**Guard rails for declared facts** (they can be wrong, or flattered):
- Git review is the audit trail; `managed_by` already stops the UI and the resource from fighting.
- Show **"not described yet"** on the application page and count such applications in the posture view, so missing context is visible and not silently low.
- Require an owner for `critical` applications (a CEL rule on the CRD).
- A change of context re-scores the application and shows in its timeline (the re-score flag exists, D55).

## 8. The UI edit I added this session, and the tension with "everything in the resource"

I added `PATCH /api/v1/applications/{id}` and a Settings tab so a person can set criticality, exposure, data and controls without writing YAML. It refuses an application a resource manages (409) and flags a re-score. This conflicts with the principle above if it becomes the normal way to configure. Two options:

- **A. Keep it only for applications no resource owns** (those ingest made, `managed_by = none`), so a team that does not use Kubernetes, or has not written the resource yet, can still set context, with "Export as YAML" next to it so the move to Git is one click (docs/13 section 4). A resource later adopts the row.
- **B. Remove it.** Configuration is YAML only, as for connectors (D82).

I recommend **A**. The product runs without Kubernetes (D3, Compose) and a first-time user scans before describing anything (D55's own finding). The state of that work: the endpoint and its tests are done; the page and the tab are drafts (one lint error, no tests) and are **paused**.

## 9. What I would do, in order

1. Fix the CRD: add `lifecycle` and `hierarchy` to the schema; add a test that compares the schema with `ApplicationSpec` (small).
2. Make docs/06 and the code agree (remove the three factors from the document, or add them to the policy: owner's choice), and make the Policies page read the real SLA matrix (small).
3. Finish the About page (version and the real rules) (drafted).
4. Add `environments` with `exposure` and `tracks`, the resolution, the two CEL variables, and the "not described yet" mark (medium; additive).
5. Show the asset type and the track as the version (frontend only).
6. Decide section 8 (A or B), then finish or remove the Settings tab.

## 10. Standards: what they define, and what is still to be verified

These are the references the score should be explained against. **None of them is implemented as the standard defines it**: Rampart uses KEV and EPSS data directly, and the weights are our own judgement, not validated against outcomes. The About page should say so.

| Standard | What it defines that matters here | Our field it relates to | Verified? |
|---|---|---|---|
| CVSS 3.1 environmental metrics | Confidentiality, Integrity and Availability **Requirement** (CR, IR, AR: not defined, low, medium, high) and the Modified base metrics, so a score can be adjusted for one organisation | data classes (CR), criticality (IR, AR), exposure (Modified Attack Vector) | to confirm |
| CVSS 4.0 | Base, **Threat** (Exploit Maturity), **Environmental** (Security Requirements and Modified base) and **Supplemental** (Safety, Automatable, Provider Urgency, ...) | the same, plus the exploit maturity our feeds give | to confirm |
| CISA SSVC | Decision points: Exploitation, **System Exposure**, Utility (Automatable, Value Density), **Human Impact** (Safety, Mission); outputs from "defer" to "immediate"; ordered levels, not summed points | exposure levels; criticality as Mission | to confirm |
| FIRST EPSS | probability of exploitation in the next 30 days | the EPSS factors | to confirm |
| CISA KEV and BOD 22-01 | the catalogue and the due dates | the KEV factor and the deadline cap | to confirm |
| NIST SP 800-40 rev 4, FIPS 199, SP 800-60 | enterprise patch management; impact levels low / moderate / high for C, I, A | the SLA matrix; data classes | to confirm |
| PCI DSS 4.0.1 (6.3.3, 6.4.2) | patching of high and critical vulnerabilities in a set time; a WAF in front of public-facing web applications (D55 already cites 6.4.2) | `pci`, the WAF control | 6.4.2 cited in D55; 6.3.3 to confirm |
| GDPR article 9, HIPAA | what personal and health data are | `pii`, `phi` | to confirm |
| OWASP Risk Rating | business-impact factors (financial, reputation, compliance, privacy) | criticality, data | to confirm |

**What the research must confirm before this table loses its "to confirm" column:** the exact metric names and values above from the FIRST and CISA texts; what EPSS and KEV add over CVSS alone, with the study; how the products named in the second job (DefectDojo, Dependency-Track, Snyk, Tenable, Qualys, Wiz and ASPM vendors) model application, environment and data sensitivity, and which of those fields they document as feeding their score; and whether any of them lets a user's declared attribute expire or be reviewed. The job on products has returned and is section 11. The job on standards has not; when it returns I will fill the 'Verified?' column and correct this document where it disagrees.

## 11. What other products do (read in their documentation; gaps marked)

A research job read the public documentation of nine products. The pages were summarised by a tool, so quotes are its rendering; what it could not read is listed at the end and is not used in the conclusions.

| Product | Application or asset attributes it documents | Feeds the score? | Environment | Declared or derived |
|---|---|---|---|---|
| **DefectDojo** (Product, now "Asset") | business criticality (6 values), platform, lifecycle, origin, `user_records` (count), `revenue`, `external_audience`, `internet_accessible`, regulations, tags | Pro: criticality, user records, revenue (as a share of the organisation's), the two booleans; platform, lifecycle, origin, regulations are **not** inputs. Weights "intentionally not published" | a field of the **Test** (a scan), "rather than directly with Assets"; "Environments do not affect Priority scoring" | all declared, except a ServiceNow connector that never overwrites a value a person edited |
| **Dependency-Track** | classifier (application, framework, library, container, operating-system, device, firmware, file, ...), name, `version` (an opaque string), tags, parent | the score is a count of severities; classifier, tags, version are not inputs | **no field**: per-environment child projects with a tag, grouped by a collection parent | declared |
| **Snyk** | business criticality (4), environment (9 deployment-style values), lifecycle stage (production, development, sandbox); asset class A to D | business criticality only is documented as an input (default High if unset; a retest applies it) | a project attribute | declared; a manual asset class can be locked so a policy cannot override it |
| **Tenable** | Asset Criticality Rating 1 to 10 | ACR and the vulnerability's VPR make the asset exposure score | environment is a tag value for reporting; "Dev only" is a reason for lowering ACR | ACR is derived from an asset profile; a person may override it with a reason and a note |
| **Qualys TruRisk** | asset criticality 1 to 5 (default 2) from tags or from an AI estimate | multiplier on the asset score; internet-facing raises it by 20% | via tags | tags manual or by rule; AI estimate only for untagged assets |
| **Orca** | exposure, "contains PII", running or paused | yes, no weights published | tags such as sandbox or dev, in custom rules | derived from the cloud; a custom rule may change a score and the change is recorded with the actor and the reason, the original score kept |
| **Palo Alto Cortex Cloud** | business criticality, status, type, deployment type, data classification (confidential, public, highly sensitive, unknown), data governance (PII, PCI, financial, PHI), compliance, **application exposure (external, internal, unknown)** | urgency = probability (EPSS, KEV, exploit maturity, reachability, exposure, deployment) **×** impact (application criticality, environment, sensitive data, privileges, number of assets) | when an environment tag is the grouping key, each environment becomes its own application | criticality and owner from tags; override history and revert by id; a `hasManualOverrides` flag |
| **Conviso** (the only one with published weights) | business impact (3), data classification (confidential, PII, PCI count), exploitability (internal 1, internet-facing 2) | 0.99 × [50 × impact/3 + 15 × threat/10 + 10 × exploitability + 15 × data] | not in the model | declared; **the score shows N/A until the required fields are filled** |
| **Rapid7 InsightVM** | criticality tags | multipliers on the asset score: very high ×2, high ×1.5, medium ×1, low ×0.75, very low ×0.5, editable | not in the page read | tags applied by hand |

**What this says about our proposals.**
1. **Environment is not an attribute of the application anywhere.** It is on the scan (DefectDojo), on a project that is itself per-environment (Dependency-Track, Snyk, Cortex), or a tag (Tenable, Orca). That supports section 7: describe the environments in the resource and resolve each finding to one, rather than putting one environment on the application.
2. **Missing data should be visible.** Conviso shows N/A until the fields are filled; Cortex and Conviso have an explicit unknown / not-defined value; Qualys defaults to a low score and AI-estimates untagged assets. None silently scores as low. This supports the "not described yet" mark (section 5, point 6; section 7).
3. **Data sensitivity is a short list in the products too**: PII, PCI, PHI, financial, sensitive or confidential, public. Ours (`pii`, `pci`, `phi`, `secret`, `public`) is in line; **`financial` is the one class others have and we do not**. Volume (record counts, revenue) exists only in DefectDojo; I would not add it.
4. **Exposure** is a yes/no in most (DefectDojo, Qualys, Conviso), external / internal / unknown in Cortex. Section 6 states this.
5. **Version is not a first-class entity** in any of them: an opaque release string (Dependency-Track), fields on a scan (`version`, `branch_tag`, `commit_hash` in DefectDojo), a free-text target reference (Snyk). Our track already plays that part.
6. **Application type:** Dependency-Track and CycloneDX have 12 to 13 values (application, framework, library, container, operating-system, device, firmware, file, ...); Cortex has SaaS, mobile, AI, desktop, other and a deployment type; Snyk has repository, image, package. Ours (`Asset.Type`) belongs to the same family. We do not need an application type for the score.
7. **How the score is combined differs, and ours is a choice.** Conviso lets business context be 65% of the score and threat 15%; Cortex multiplies probability by impact; Tenable multiplies; Rapid7 multiplies by a criticality factor; DefectDojo adds weighted factors with unpublished weights. In ours, threat dominates (KEV +300 against internet +100) and the weights are published. Neither shape is "the" standard. What the About page should do is say plainly which it is.
8. **Audit of declared values:** none of them documents an expiry or a periodic review of a declared criticality or exposure. What exists: a connector that never overwrites a manual edit (DefectDojo), reason codes and a note (Tenable), a lock (Snyk), the actor and reason on every score change (Orca), override history with revert (Cortex). **Our Git review already gives more of this than most**; an expiry would be our own addition, and I would not add it.

**Not verified, and not used above:** Apiiro (the site refused the research job), Wiz (the page was rate limited), the Snyk AppRisk "Deployed" and "Public facing" factor pages (not found), which Cortex fields are derived and which declared, Qualys' multiplier values, Tenable's exact ACR drivers, and the precise weights DefectDojo uses.

## 12. Decisions I need from you

1. **Environments:** ~~add `environments` (with `exposure` and `tracks`) to the Application resource~~ **Answered by the owner (D140): an application is one branch, so `environment` is one flat field and the score reads it from the application.** Section 16 is the shape.
2. **Exposure** as three levels, `internetFacing` kept as the old spelling? (section 7)
3. **The UI edit:** A (only for applications no resource owns, with Export as YAML) or B (remove it)? (section 8)
4. **docs/06:** remove the three unbuilt factors from the document, or add them to the policy? (section 5, point 4)
5. **Missing context:** show "not described yet" and count it in the posture, or leave it silent? (section 5, point 6)

## 13. The values of the Application resource, and what it shares with other resources **(code)**

**The ranges, as enforced today.** "CRD" means the schema in `deploy/crds/application.yaml`; "Go" means `ApplicationSpec.ToApplication` (`internal/domain/application_spec.go`), which `rampart apply` and the operator both call.

| Field | Range | Default if left out | Enforced by |
|---|---|---|---|
| `metadata.name` | the slug | | Kubernetes name rules |
| `displayName` | text, **required** | the slug | CRD (`required`) |
| `businessCriticality` | `low`, `medium`, `high`, `critical` | `medium` | CRD enum and Go |
| `internetFacing` | true / false | false | CRD |
| `dataClassification` | any of `pii`, `pci`, `phi`, `secret`, `public` | none | CRD enum and Go |
| `compensatingControls` | any of `waf`, `apiGateway`, `mtls`, `privateNetwork` (stored as `waf`, `api_gateway`, `mtls`, `private_network`) | none | CRD enum and Go |
| `complianceScope` | up to 50 labels, each `^[a-z0-9][a-z0-9:._-]{0,63}$` | none | CRD pattern and Go |
| `owners` | any text | none | nothing |
| `selectors.repositories[].url` | an exact key, or a prefix ending in `*`; `*` alone, an empty value and a `*` elsewhere are refused | none | Go |
| `selectors.images[].repository` | the same, no tag or digest | none | Go |
| `selectors.workloads` | refused (needs a connected cluster) | | Go |
| `lifecycle` | **not in the CRD.** Go takes any text and defaults to `production`; the model comments say `planning`, `development`, `production`, `deprecated` | `production` | **nothing**: no check in Go, and a Kubernetes API server drops the field (section 5, point 1) |
| `hierarchy` | a list of names, the path under the tenant | none | **not in the CRD**; Go only |

**What other resources read from an application, and what an application takes from them.**

| Application value | Read by | How | A hidden coupling to know |
|---|---|---|---|
| `businessCriticality` | `SLAPolicy`, `ClusterSLAPolicy` | `spec.matrix.<band>.<criticality>` is the deadline in days; the four criticalities are the columns | the CRD does not restrict the column names (`additionalProperties`); a column the application's value does not match is ignored, and an unknown criticality is read as `low` |
| `businessCriticality`, `internetFacing`, `dataClassification`, `compensatingControls` | `RiskPolicy`, `ClusterRiskPolicy` | the CEL conditions read `app.criticality`, `app.internet_facing`, `app.data_classification`, `app.compensating_controls` | the policy sees the **stored** spelling: `api_gateway` and `private_network`, while the Application resource says `apiGateway` and `privateNetwork`. A policy author who writes `apiGateway` gets a condition that never matches, and nothing refuses it (the values are strings) |
| `complianceScope` | `ComplianceFramework`, `ClusterComplianceFramework` | `spec.appliesTo.complianceScope` selects the applications that list that label; without `appliesTo` a framework reads every application | none |
| `hierarchy`, the application's name | `AccessBinding` | `spec.scope.hierarchy` (paths) and `spec.scope.applications` (names) | none |
| `selectors` | assets from the `ScanSource` runs | an asset whose key matches moves into the application (D56); a `ScanSource` does **not** name an application (docs/04's `defaultApplication` is not in its CRD) | none |

**Values that come into an Application from another resource: none.** Everything an application says is written on it. No tenant-wide default (a default criticality, a default exposure) comes from a `Tenant` or a policy, so an application that says nothing gets the built-in defaults of the first table.

## 14. If every branch is its own application

The owner's rule: a branch is an application. This is a different model from the one the product has, and the two do not mix.

**What the product does today (D10).** An asset is a repository, keyed by its address **without** the branch (`DeriveAssetKey`, `internal/ingest/resolution.go:45`). An asset belongs to **one** application, and stays in it (D10, D56). Each branch is a **track** inside that application: separate findings and SBOM per track, one application page.

**What "a branch is an application" needs that does not exist:**
1. The asset key would have to include the branch (`repo@branch`), or an application would have to be resolved from the pair. Today a second branch of the same repository lands in the first branch's application, as a track.
2. Selectors would need a branch (`repositories[].url` plus a branch pattern). Today they match the address only.
3. Pull requests and feature branches must stay ephemeral (D10) and never become applications, so something must say which branches are real: the `tracks` of a `ScanSource` already do (`TrackedRefs`), and could be what creates an application.
4. A vulnerability in code that both `main` and `release` contain would be two findings in two applications; counts, posture and the application list would double, and "fixed on main, still open on release" becomes two applications to compare. Findings are keyed per application and track, so nothing is shared across branches.

**What it gives:** the attributes the owner asked for sit flat on the application, with no list and no mapping of branches: one `environment`, one `exposure`, one criticality, one set of data classes, for that branch. `PRODUCTION_ENV` would read `app.environment`, not the name of a branch, and the "environment is read from the track name" defect (section 5, point 3) disappears by construction.

**The two ways, side by side.**

| | One application per repository, branches are tracks (today) | One application per branch (the owner's rule) |
|---|---|---|
| Where `environment` and `exposure` live | a list on the application, branches mapped to its entries (section 7) | flat fields on the application |
| What decides production | the environment a finding's branch maps to | the application's own `environment` |
| Changes to the product | add `environments` to the resource and the policy's variables (small) | the asset key, the selectors, the ephemeral rule, the roll-ups and the application list (large, and touches D10) |
| Applications for one repository | 1 | one per tracked branch |
| Same vulnerability on two branches | one finding per track, one application page | two findings in two applications |

**What I would do, if the rule stays.** Keep the flat fields (this is simpler to write and to read), and make the product support it deliberately instead of by accident: an application resource names a repository **and a branch** (`selectors.repositories[].url` plus `branch`), the asset key includes the branch for such applications, and only tracked branches create applications. Existing resources keep working: an application without a `branch` selector is per repository, as today. That is a design for D10 and D56 to be reopened, not a field to add.

**Answered by the owner (D140): an application is one branch. That is the rule, and it was the owner's from the start.** The question that stood here (every tracked branch, or every deployed environment) is closed: one application is one branch of one repository. The consequences are in section 16.

**An example in the owner's shape** (flat, one branch):

```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: Application
metadata: {name: payments-main}
spec:
  displayName: Payments API (main)
  type: repository               # repository | machine (new; the asset type it is made of)
  selectors:
    repositories:
      - url: github.com/acme/payments
        branch: main             # new; the version is the branch or a tag
  environment: production        # new; production | staging | test | development
  exposure: internet             # new; internet | restricted | internal | isolated (internetFacing stays accepted)
  businessCriticality: critical
  dataClassification: [pci, pii]
  compensatingControls: [waf]
  complianceScope: [pci-dss]
```

## 15. A worked example: one application and every resource that decides its score

The five files of [examples/payments-scoring/](examples/payments-scoring/) are one application, `payments-api`, with every resource that changes what a finding of it scores or how long it has to be fixed: one file per resource, numbered in the order to apply them (`for f in docs/examples/payments-scoring/*.yaml; do rampart apply -f "$f"; done`, or by the operator). Every field is commented with the values it accepts. `internal/config/apply/scoring_example_test.go` applies the files through the same library the server uses and checks every number below, so the example cannot drift from the code.

### 15.1 What each resource decides

| Resource | Scope | What it decides about the score | Where it acts |
|---|---|---|---|
| `Tenant` | cluster | which namespaces belong to the tenant; every namespaced resource below is found by it | resolution, not scoring |
| `ClusterFeed` | cluster | **which threat data exists.** A feed that is off gives the threat factors nothing to test: no KEV list, no EPSS value, no weaponized-module flag | `vuln.kev`, `vuln.epss`, `vuln.exploited`, `vuln.exploit_maturity` |
| `Application` | namespace | **the facts about the product**: criticality, internet exposure, data classes, compensating controls | `app.criticality`, `app.internet_facing`, `app.data_classification`, `app.compensating_controls`, and the column of the deadline table |
| `RiskPolicy` / `ClusterRiskPolicy` | namespace / cluster | **how a score is worked out**: base points per severity, the factors, the band limits | the score and the band |
| `SLAPolicy` / `ClusterSLAPolicy` | namespace / cluster | **how long you have**: days by band and criticality, the caps, when the clock starts, whether it restarts, whether it pauses | the due date |
| `ComplianceFramework` | namespace / cluster | nothing. It reads the applications that list its scope and reports on them | reporting only |
| `AccessBinding` | cluster | nothing. It limits who sees which applications | visibility only |

There is no `ScanSource` in the example, because the owner's decision is that it is not needed anywhere in the system: the analyzers (D128) took its role as a source of findings. The scores do not depend on it: the policy reads the branch name that the upload carries (`finding.track`), so `main` and `develop` score the same with or without it. What the code still takes from it is in section 15.5.

### 15.2 Which policy is in force

A policy is chosen **per tenant**, not per application. For one tenant, the server takes the namespaced policy named `default`, or else the first by name; if the tenant has none, the cluster policy named `default`, or else the first by name; if there is none, the built-in one (`policySpec`, `internal/store/postgres.go`). Two applications of the same tenant are therefore scored by the same factors and differ only in what they say about themselves. The same holds for the SLA policy. A tenant that wants a different formula for one application cannot have it today; this is the second reason, after section 13, that the facts an application states are the only per-application lever.

A `RiskPolicy` that lists `factors` **replaces** the whole built-in list, so the example writes all twelve, changes two (`INTERNET_FACING` and `PRODUCTION_ENV`) and adds one (`NON_PRODUCTION`), thirteen in all; the test checks that the other ten are the built-in ones. Leaving `factors` out keeps the built-in list.

### 15.3 What the example scores

`payments-api` is critical, internet-facing, holds `pci` and `pii`, and has a WAF. For three findings, the built-in policy and the example's policy give (verified by the test):

| Finding | Built-in score, band, deadline | The example's score, band, deadline |
|---|---|---|
| A high dependency finding, EPSS 20%, found on `main` | 740, high, 7 days | 850, critical, 2 days |
| The same finding found on `develop` | 740, high, 7 days | 730, high, 7 days |
| A medium finding from a dynamic scan, behind the WAF, on `main` | 400, medium, 30 days | 510, medium, 30 days |

How the first row is worked out:

| Step | Built-in | Example |
|---|---|---|
| Base points of a `high` finding | 400 | 400 |
| EPSS 20% (`EPSS_MODERATE`, 10% or more) | +60 | +60 |
| `INTERNET_FACING` | +100 | **+150** (changed) |
| `SENSITIVE_DATA` (`pci` is listed) | +80 | +80 |
| `APP_CRITICAL` | +100 | +100 |
| `PRODUCTION_ENV` | 0: the track is `main`, and the built-in rule only accepts `production` and `prod` | **+60** (changed: `main` and `release/*` count) |
| `NON_PRODUCTION` | n/a | 0 (the track is `main`) |
| Total, band | 740, high (600 to 799) | 850, critical (800 and up) |
| Deadline: row = band, column = `critical` | high row: 7 days | critical row: **2 days** (the example's matrix) |

On `develop`, `PRODUCTION_ENV` does not apply and the new `NON_PRODUCTION` gives -60: 400 + 60 + 150 + 80 + 100 - 60 = 730. The built-in policy still gives 740 there, because it does not know about `develop`. The third row shows the compensating control: -80 on a finding of category `dast` only.

The two caps are asserted as well. `maxDays: 90` brings the 365 days of a low finding of a low-criticality application down to 90 (the built-in policy keeps 365). `kevDueDate: true` makes a finding that is on the CISA list due at the end of the CISA due date when that is earlier than the matrix deadline, and leaves the matrix deadline when it is not.

### 15.4 What the example shows about the model

1. **One file, one tenant, three layers.** Facts about the product (the `Application`), facts about the world (the `ClusterFeed`) and rules (the two policies) are separate resources. The score is their product, and only the first is per application.
2. **The environment is a branch name today.** `PRODUCTION_ENV` and `NON_PRODUCTION` read `finding.track`, so the policy has to list branch names (`main`, `release/*`, `develop`). This is the defect of section 5, point 3, and the reason for the decision in section 12 (a list of environments on the application, or one application per branch, section 14). The example works around it in the policy, which is the only place it can be done today.
3. **A tenant's policy is a copy that can drift.** Because `factors` replaces the list, a tenant that only wants `INTERNET_FACING` to be 150 has to restate the other eleven, and does not receive a factor the product adds later. A way to change one built-in factor by name, without restating the list, would remove this (not built; recorded here as an option).
4. **A value the policy writes must be a value the application can have.** The policy reads `"pci"`, `"waf"`, `"critical"`. They are the stored spellings (`api_gateway`, not `apiGateway`), listed in section 13.

### 15.5 `ScanSource` is to be retired: what it still carries in the code, and what has no replacement yet

The owner's decision (D139): `ScanSource` is not needed in the system, because the analyzers (`SBOMAnalyzer`, `ClusterSBOMAnalyzer`, `ExternalAnalyzer`, D128) took the role of a source of findings. The code has not been changed: the kind is in the CRD, the apply library, the store, the operator and the ingest path. An analyzer takes over one of its roles; the others are not about where findings come from, and nothing else holds them yet.

| Field | Read by | What it does today | Replaced by an analyzer? |
|---|---|---|---|
| `connector`, `schedule`, `secretRef`, `dependencyTrack` | `internal/operator`, `internal/store`; `dependencyTrack` is in the CRD only | pulling findings from a connector on a schedule; `dependencyTrack` is a leftover of the removed Dependency-Track source | **yes in intent.** But the analyzers are not finished: the matcher is not wired to anything and the analyzer CRDs have no controller (docs/34 F26 and F30) |
| `trustRules` (issuer, provider, repository and project ids) | `internal/ingest/federation.go`, `internal/ingest/merge.go`, `internal/store/federation.go` (the `source_trust` table, D-entry on Trust Rules) | **which CI identities may upload.** A token exchange is accepted only if the issuer matches a trust rule | **no.** Without a home, a CI job cannot authenticate by OIDC |
| `trackedRefs` | `internal/ingest/resolution.go`, `internal/domain/scansource.go` | which branches are real; a run on any other branch is ephemeral. Section 14 proposed using it to decide which branches become applications | **no** |
| `ingestionPolicy` (`closeOldFindings`, `closeScope`, `maxClosePercent`, `minimumSeverity`, `acceptedFormats`, ...) | `internal/ingest/merge.go`, `internal/ingest/resolution.go`, `internal/store/held_close.go` | what a report may close and merge, and how much | **no** |

So the removal is not a deletion, but the rule of D140 (an application is one branch) settles one of the three roles and points at the others:
- **`trackedRefs` goes away.** An application names its repository and its branch, so a branch is real because an application names it. Nothing else lists branches.
- **`ingestionPolicy` moves to the `Application`** as `ingestion`, because what a report may close is now the findings of one branch, which is one application.
- **`trustRules` move to the `Tenant`** as `ciTrust`, not to the `Application`. The reason is who may write them: an `Application` is written by a product team, in a namespace; a trust rule says which CI identity may upload findings, which is an administrator's decision, and `Tenant` is the cluster-scoped, administrator-written resource. It is also per repository (the token names the repository, not a branch), so on an application it would be repeated for every branch.

These two homes are my proposal; the owner has not answered. Section 16 shows them in the target file.

## 16. The target shape: an application is one branch, and a `type`

Decided (D140): **an application is one branch of one repository.** Proposed in this section, for the owner to confirm: a `type` that says what kind of thing is watched (a repository, a machine, an image, a website), and the file that follows from the rule. **Nothing here is accepted by the server yet.** The guarded example in `examples/payments-scoring/` is the shape of today's code and is rewritten into this one when the first two slices of docs/35 (AB1, AB2) land.

### 16.1 What `type` is for: the kind of thing that is watched

An application is a thing the product watches, and `type` says **what kind of thing**: a repository, a machine, an image, a website. The type is the first fact about an application, because everything else follows from it: what names it, what can report on it, what the page shows. This was the owner's point, and an earlier version of this section reduced it to "which fields name it" and to a single value; that was too small.

What a type decides:

| | `repository` | `machine` | `image` | `url` |
|---|---|---|---|---|
| **What it is** | one branch of one repository (the rule of D140); later a tag | one machine: a server, a VM, a node | one container image | one web application or API as it is reached |
| **Named by** | `repository` and `branch` | `machine.hostname`, and optionally an address or a cloud instance id | `image.repository` (no tag, no digest, as D10) | `url.base` (scheme, host, path prefix) |
| **Its "version"** | the branch (or a tag) | none: a machine has a state over time, not versions | the digest, with the tags kept as attributes | none |
| **The asset it claims** (D10) | `repository` | `host` | `image` | `url` |
| **What reports on it** | code scanners (SAST, secrets, SCA), SBOMs from CI | a host scanner or an agent: installed packages, patch level, open ports | an image scanner, an SBOM of the image | a dynamic scanner |
| **What its page shows** | findings, SBOM, dependency graph, licences, attestations | findings, installed packages and their vulnerabilities | findings, SBOM, layers | findings by endpoint |
| **State in the code** | buildable now (AB1, AB2) | **not buildable yet**: `AssetHost` is an enum value, but nothing in ingest creates a host asset and no parser reports host findings (AB6) | the asset type exists and image findings already resolve to it (D10); naming it by an application is a small step after AB2 | the asset type exists (D10); same |

What a type does **not** decide is the score. Every type is scored from the same flat facts (`businessCriticality`, `environment`, `internetFacing`, `dataClassification`, `compensatingControls`), so a tenant has one `RiskPolicy` for all of them; a factor can read `app.type` when a tenant wants a machine to weigh differently from a repository, and the built-in policy does not. The type does decide which of the facts can mean something: a machine has no branch, so `PRODUCTION_ENV` reads `environment`, which every type has.

**The names.** The kind is `repository`, not `branch`: a branch is the *version* of a repository, and the rule "an application is one branch" is written by making `branch` required for that type (a tag can join it later without a new type). The second kind is `machine`, the owner's word; it maps to the `host` asset type of D10 inside, so no stored value changes. `node` is not used: the dependency graph already calls a component a node, and a Kubernetes node is one particular kind of machine.

**Until a type is built, the CRD does not list it.** `repository` is the only value accepted in AB1; `machine`, `image` and `url` are refused with a reason, as D56 refuses workload selectors, so a resource never says something the server will not do. The field and the fields that name each type are designed now, so adding a type later changes no existing resource. An application with no `type` is a repository-wide application, as today.

**Fields that name a type are one object per type, not a list.** `selectors.repositories` can hold many entries and patterns, which is the wrong shape for "one branch": it allows two. A `repository` application has exactly one `repository` and one `branch`; a `machine` application has exactly one `machine`.

### 16.2 The target file (not accepted by the server yet)

```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: Tenant
metadata: {name: acme}
spec:
  displayName: Acme
  namespaces: [acme-payments]
  ciTrust:                                  # moved here from ScanSource.trustRules: which CI identities may upload
    - {provider: github, issuer: "https://token.actions.githubusercontent.com", repositoryId: "123456", repositoryOwnerId: "789"}
---
apiVersion: rampart.aspm.dev/v1alpha1
kind: Application
metadata: {name: payments-main, namespace: acme-payments}
spec:
  type: repository
  displayName: Payments API (main)
  repository: github.com/acme/payments
  branch: main
  environment: production                   # production | staging | test | development
  internetFacing: true
  businessCriticality: critical
  dataClassification: [pci, pii]
  compensatingControls: [waf]
  complianceScope: [pci-dss]
  owners: [team-payments]
  ingestion: {closeOldFindings: true, maxClosePercent: 50}   # moved here from ScanSource.ingestionPolicy
---
apiVersion: rampart.aspm.dev/v1alpha1
kind: Application
metadata: {name: payments-develop, namespace: acme-payments}
spec:
  type: repository
  displayName: Payments API (develop)
  repository: github.com/acme/payments
  branch: develop
  environment: development
  internetFacing: false
  businessCriticality: medium
  # no personal data and no WAF in front of develop: say so by saying nothing
---
# The same product's database server: another kind of thing, the same facts that decide the score. Not buildable yet (AB6).
apiVersion: rampart.aspm.dev/v1alpha1
kind: Application
metadata: {name: payments-db-01, namespace: acme-payments}
spec:
  type: machine
  displayName: Payments database 01
  machine: {hostname: db-01.acme.internal}
  environment: production
  internetFacing: false
  businessCriticality: critical
  dataClassification: [pci]
```

The `ClusterFeed`, `RiskPolicy` and `SLAPolicy` stay as they are, with one change in the policy: `PRODUCTION_ENV` reads `app.environment == "production"` instead of the name of a branch, and `NON_PRODUCTION` reads `app.environment in ["development", "test"]`. The same finding then scores differently on the two applications because of what each says about itself, not because of a branch name written in a policy.

**By hand with the built-in policy** (to be asserted by the test when the slices land): a high dependency finding with EPSS 20% is 400 + 60 (EPSS) + 100 (internet) + 80 (data) + 100 (critical) + 60 (production) = **800, critical, 3 days** on `payments-main`, and 400 + 60 = **460, medium, 90 days** on `payments-develop`.

### 16.3 What the rule costs, and the defaults taken

1. **Asset and resolution.** The asset key includes the branch for such applications (`repository@branch`), so one application is one asset and everything built on that (findings, SBOM, graph, `MoveAssetToApplication`) keeps working. Selectors match the repository **and** the branch. D10 and D56 are reopened for this and amended, not replaced.
2. **A branch no application names.** It is handled as D56 handles any unclaimed asset (the Unassigned application, resolved again on every run), except that a name that is recognisably ephemeral (a pull request, `feature/*`) never becomes an asset. Today that test reads `ScanSource.trackedRefs`; it will read the tenant's applications.
3. **Exact branch names only** in this version. A family such as `release/*` would be one application with several branches, which is the model this rule removes. If release branches make this expensive in practice, a trailing-`*` pattern is the way back, decided then.
4. **`environment` has no default.** An application that does not say shows "not described yet" and takes no points from `PRODUCTION_ENV` (which is what an unset branch name does today), so no score of an existing tenant changes without a person writing the field.
5. **Counts.** A repository with four branches is four applications, so the list, the posture and the counts grow; a view that groups applications by repository is part of the slices (AB5), not an afterthought.
6. **`exposure`** (internet, restricted, internal, isolated) is still open (section 12, item 2); the boolean `internetFacing` stays and is what this file uses.
