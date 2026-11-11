# ADR 0006 — Dependency-Track is the SCA system of record when connected; Rampart integrates in four flows

Status: accepted (API details marked "confirm" in doc 10 must be verified against a live instance before implementation) · Date: 2026-11-11

## Context
Teams adopting an ASPM usually already run OWASP Dependency-Track for SBOM management and continuous component analysis. DefectDojo's link to DT is one-way: DT pushes a Finding Packaging Format export on a schedule and only `FALSE_POSITIVE` is honoured. That loses events, triage, policy violations and the SBOM itself. Building our own continuous component analysis would duplicate DT.

## Decision
- When a DT connector is configured for an asset, DT is the source of truth for SCA findings on that asset. Rampart does not create its own SCA findings from SBOMs it forwards to DT.
- Four flows, each independently switchable: (A) forward CycloneDX SBOMs from Rampart ingestion to DT, (B) receive DT webhook notifications as untrusted triggers, (C) pull projects, findings, policy violations and SBOMs through the DT REST API, (D) write triage decisions back to DT analysis.
- Webhook payloads are never used as data. They only schedule a debounced project re-pull ("thin event, fat fetch"), because DT webhooks are not signed.
- A dedicated `sync` target and River queues (`dtrack-sync`, `dtrack-push`) isolate upstream API work from report parsing.
- Triage sync has modes `off | import | export | bidirectional` with an explicit authority setting. Default mode is `import`; default authority in bidirectional mode is Rampart. v1.0 ships pull, webhook trigger and `import` only.
- DT project to application mapping uses, in order: project properties (`integrations / rampart.application`), tags, existing asset link, purl or repository match, parent project, CEL rules, default. Unmapped projects are synced and surfaced, never dropped.
- A DefectDojo-compatible import shim lets DT's existing DefectDojo integration and legacy CI scripts post to Rampart unchanged, as a migration aid.

## Consequences
- One SBOM upload from CI feeds both systems. SCA findings join SAST, DAST, secrets and IaC findings under one risk score and SLA.
- Cross-tool correlation with Trivy or Grype depends on the DT project resolving to the same asset; mapping quality is visible in `ScanSource` status.
- We depend on DT API v1 stability; a versioned client interface and contract tests per DT minor version contain that risk.
- Without DT, Rampart's own CycloneDX VDR parsing and OSV enrichment still provide SCA findings, with less continuous re-analysis.
