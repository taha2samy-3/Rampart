# ADR 0003 — Standards-first ingestion: SARIF and CycloneDX are the primary formats; native parsers add enrichment

Status: accepted · Date: 2026-11-10

## Context
DefectDojo maintains ~360 parsers, each a bespoke mapping, with per-parser hash field lists. Most modern scanners emit SARIF 2.1.0 (SAST, IaC, secrets, DAST, container) or CycloneDX (SBOM/VDR/VEX). Kubernetes scanners emit PolicyReport/OpenReports. Native formats carry extra data (per-source CVSS, EPSS/KEV, dataflow, CIS ids) that SARIF loses.

## Decision
- Tier 1 ingestion: SARIF 2.1.0, CycloneDX 1.4–1.7, OpenVEX/CSAF VEX, PolicyReport/OpenReports/Trivy Operator CRDs.
- Tier 2: native JSON parsers for the top ~15 scanners, chosen when they add data over SARIF or when SARIF is unavailable (kube-bench, Prowler OCSF, SonarQube).
- The canonical internal model is our own entity-oriented `Finding`/`Occurrence`, not OCSF; we export to SARIF, CycloneDX VDR/VEX, OpenVEX and OCSF 2007.
- Internal triage states use the OpenVEX vocabulary (`under_investigation`, `affected`, `not_affected` + 5 justifications, `fixed`) extended with `risk_accepted`, `out_of_scope`, `duplicate`.
- A parser's `scanner_family` is the same whether the input was SARIF or native, so fingerprints are stable across formats.

## Consequences
- Day-one coverage of ~25 scanners with ~6 parsers.
- Long tail handled by the Generic JSON format and later a declarative `ParserMapping`.
- VEX round-trips losslessly, which matters for supply-chain and CRA/FedRAMP VDR reporting.
