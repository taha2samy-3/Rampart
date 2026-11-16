# 27. Compliance: reading a framework, and adding your own

This guide is for two readers:
- the security lead who reads the Compliance page and hands its export to an auditor;
- the person who writes a framework Rampart does not ship, such as an internal secure-coding policy.

The decisions behind it, and why, are docs/16 D52 and D102.

## 1. What the page tells you

Pick a framework and, if you want, one application. Each control shows one of three readings, and a sentence that says why.

| Reading | What it means | What changes it |
|---|---|---|
| **Not met** | Open findings break the control, or a person attested that it is not met. | Fix or triage the findings; the link lists them. |
| **Met** | A scan that could show a problem ran recently and found nothing open, or a person attested that it is met. | A new finding, or the evidence growing old. |
| **Not assessed** | Nothing can be said: no scan of the right kind ran in the window, or it ran in only some of the applications, or nobody attested a manual control. | Run the missing scan, or attest. |

"Met" is evidence for an auditor. It is not a certification.

Three rules keep "Met" honest:
- **A scan must be of the right kind.** A control about injection needs a SAST or DAST scan. A dependency scan finds weaknesses in other people's code, not yours.
- **The evidence must be recent.** By default a scan counts for 30 days. A framework can set its own window.
- **Every application in scope needs it.** Tenant-wide, one application's scan does not make a control met for an application nobody scanned. The sentence says, for example, "Assessed in 2 of 3 applications."

**Accepted exceptions.** A finding someone risk-accepted does not make a control "not met", but it is never hidden. The sentence says how many there are, the "accepted exceptions" link lists them with who approved them, and the CSV has a column for them.

**The findings link.** It lists what the control counts. When a control is matched in two ways, by weakness and by kind of scan, one link cannot list both. It then reads "See part of the findings", so the numbers never differ without a word.

**History.** Rampart keeps one reading of every framework a day, as it was shown, for 400 days. Choose a day under "As of" to see it, or add `&at=2026-06-30` to the export. History is kept for the whole tenant, not for each application.

**The export.** "Download CSV" gives every control with:
- its reading and the sentence;
- the open findings by band;
- the accepted exceptions;
- how many applications were assessed;
- the scanners that gave evidence;
- for a manual control, who attested it and until when.

Downloading it is recorded in the audit log.

## 2. Frameworks Rampart ships

OWASP Top 10 (2025 and 2021) and the CWE Top 25 are matched by weakness (CWE). PCI DSS 4.0.1 requirement 6, ISO/IEC 27001:2022 Annex A 8 and NIST SSDF 1.1 are matched by the kind of scan, because those standards do not list weaknesses. Each says so in its note.

## 3. Adding your own framework

Write a `ComplianceFramework` in your tenant's namespace and apply it with `kubectl apply -f` or `rampart apply -f`. A platform administrator can write a `ClusterComplianceFramework` instead, which every tenant sees. If both exist with the same name, the tenant's replaces the platform's for that tenant.

```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: ComplianceFramework
metadata:
  name: acme-secure-coding
  namespace: team-payments
spec:
  displayName: ACME secure coding policy
  version: "2026.1"
  source: https://wiki.acme.example/secpol
  note: Our own policy. Evidence, not certification.
  appliesTo:
    complianceScope: pci         # only applications that list "pci"; leave out to read all
  evidenceWindowDays: 30         # how recent a scan must be; 1 to 366, default 30
  controls:
    - id: SC-1
      name: No critical or high injection flaws
      match:
        cwes: [77, 78, 79, 89]
        minSeverity: high        # only findings whose risk band is high or critical
    - id: SC-2
      name: No hard-coded credentials
      match:
        categories: [secret]
    - id: SC-3
      name: Dependencies with a known exploited vulnerability are patched
      match:
        categories: [sca, container]
    - id: SC-4
      name: No use of eval in Python
      match:
        rules:
          - {scannerFamily: semgrep, ruleId: "python.lang.security.audit.eval*"}
    - id: SC-5
      name: A threat model is reviewed for each release
      manual: true
```

### The fields

| Field | Meaning |
|---|---|
| `displayName`, `version` | Required. The version appears in every reading and export, so an auditor knows which edition was read. |
| `source`, `note`, `description` | Optional. Where the framework comes from, and anything a reader must know. |
| `appliesTo.complianceScope` | Optional. A label, such as `pci`. Only applications whose `complianceScope` lists it are read. |
| `evidenceWindowDays` | Optional. How recent a scan must be to count. Default 30. |
| `controls[].id`, `name` | Required. The id is unique in the framework. |
| `controls[].match` | What breaks the control. A finding counts if it has one of the `cwes`, or is of one of the `categories`, or was raised by one of the `rules`. Then, if `minSeverity` is set, only from that risk band up. |
| `controls[].evidence.categories` | Optional. The kinds of scan that must have run. Without it: the match's categories; for a control matched by CWE only, SAST or DAST; for rules, their scanners. |
| `controls[].manual` | `true` for a control a person attests. It has no `match` and no `evidence`. |

The categories are `sast`, `sca`, `secret`, `iac`, `container`, `dast`, `cspm`, `compliance`, `license` and `supply_chain`. The severities are `critical`, `high`, `medium` and `low`.

### Putting an application in scope

```yaml
kind: Application
metadata: {name: checkout, namespace: team-payments}
spec:
  displayName: Checkout
  complianceScope: [pci]
```

### When the framework is refused

Rampart checks the framework when you apply it, and refuses it with a reason that names the control, for example `control "SC-9": unknown category "sasst"`. It refuses:
- a misspelled field;
- a control that matches nothing and is not manual;
- an unknown category;
- a repeated id;
- a manual control with a match;
- a framework named like a built-in one, such as `owasp-top10-2025`.

The resource's `Ready` condition shows the reason. If an earlier version was valid, that version stays in force. The Compliance page lists the refused one under "Not applied".

## 4. Attesting a manual control

Some controls no scan can read: a threat model, a yearly penetration test, a review of access. A maintainer of the application, or an administrator, opens the control and chooses **Attest**:
- **Met** or **Not met**;
- **What you checked**: required, in a sentence an auditor can follow;
- **Link to the evidence**: optional, an https link to where the report is kept;
- **Valid until**: by default a year, at most three. After that the control reads "not assessed" again.

An attestation is kept with your name and the date, and is never changed or removed. A new one becomes the reading, and the older ones stay as history. An attestation made with one application selected applies to that application only; one made with "All applications" applies to the whole tenant.

## 5. What counts as a scan of each kind

A scan counts for the categories of the scanner that ran it:
- **Built-in tools:** Rampart knows the ones it ships parsers for, plus CodeQL, OSV-Scanner, hadolint and Scorecard.
- **A clean run counts too:** a run that found nothing is recorded under the parser's id, and still counts.
- **A parser package** (docs/25) counts for the `category` it declares.
- **Any other tool,** such as a Generic JSON upload, counts for the categories of the findings it produced. A run of such a tool that found nothing therefore counts for nothing. Install it as a parser package if its clean runs should count.

## 6. Not built yet

| Not built | Instead |
|---|---|
| History for each application | The tenant-wide reading is kept daily; export per application now and keep the file. |
| Conditions in CEL on a control | `match` with `minSeverity`, or a narrower `rules` list. |
| Importing a framework from OSCAL | Write the resource; the fields map one to one. |
| A signed export | Keep the CSV with the audit log entry of its download. |
