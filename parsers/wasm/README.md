# Rampart WebAssembly (WASM) Parsers

This directory contains standalone security report parsers compiled to **WebAssembly System Interface (WASI Preview 1)** and distributed as **OCI Artifacts** on GitHub Packages (`ghcr.io`).

## Architecture & Guarantees

Every WASM parser adheres to the Rampart Parser Contract:
1. **Zero-Network Air-Gapped Sandbox**:
   - Executed using [wazero](https://wazero.io/) with no network syscalls exposed.
   - Fully deterministic and safe to run in air-gapped environments.
2. **Standard Streaming I/O**:
   - `os.Stdin`: Streaming input report (JSON, XML, text).
   - `os.Stdout`: Streaming newline-delimited JSON (`domain.RawFinding`).
   - `os.Stderr`: Diagnostic logs, syntax warnings, and panic traces.
3. **Bounded Resources**:
   - Memory is strictly capped by `spec.limits.maxMemoryMB` (default 256MB).
   - Execution is bounded by `spec.limits.timeoutSeconds` (default 30-60s).
4. **100% Finding Key Equivalence**:
   - WASM modules produce finding keys identical to the native Go parsers down to the SHA-256 fingerprint bit.

---

## Directory Structure

```
parsers/wasm/
├── checkov/            # Bridgecrew Checkov IaC scanner
├── cyclonedx/          # CycloneDX 1.4/1.5 SBOM and VEX standard
├── dependencycheck/    # OWASP Dependency-Check scanner
├── dependencytrack/    # OWASP Dependency-Track audit findings
├── gitlab/             # GitLab Security Report (SAST, DAST, Container)
├── gitleaks/           # Gitleaks secret scanner with redaction & secret hashing
├── grype/              # Anchore Grype vulnerability scanner
├── kubebench/          # Aqua Security kube-bench CIS benchmark
├── openvex/            # OpenVEX exploitability statements
├── prowler/            # AWS/Azure/GCP Prowler cloud security
├── sarif/              # OASIS SARIF 2.1.0 standard parser (Trivy, CodeQL, etc.)
├── semgrep/            # Semgrep SAST JSON parser
├── snyk/               # Snyk vulnerability scanner
├── spdx/               # SPDX 2.2/2.3 SBOM standard
├── syft/               # Anchore Syft SBOM generator
├── trivy/              # Aqua Security Trivy scanner
├── trufflehog/         # TruffleHog v3 secrets scanner
└── README.md           # This document
```

---

## Building Locally

To compile any parser to WASI WebAssembly:

```bash
cd parsers/wasm/<parser-name>
GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags="-s -w" -o parser.wasm main.go
```

---

## Running Tests

Run the complete WASM test suite across all parsers:

```bash
go test -v ./parsers/wasm/...
```

The tests verify:
- **Equivalence**: Comparing WASM output against native Go parsers on identical fixtures.
- **Conformance**: Running the standard `conformance.RunSuite` (idempotency, secret redaction, detection score).
- **Diagnostics**: Ensuring malformed JSON reports produce actionable line-level errors or stderr traces.

---

## CI/CD Pipeline & OCI Releases

Automated by [`.github/workflows/wasm-parsers.yml`](../../.github/workflows/wasm-parsers.yml):
1. **Matrix Discovery**: Automatically detects any folder in `parsers/wasm/*/` containing `main.go` and `parser.yaml`.
2. **Compilation & Testing**: Builds WASM binaries and runs tests on Ubuntu runners.
3. **OCI Release**: Packages `parser.wasm` into a scratch container image.
4. **Publishing**: Pushes to `ghcr.io/rampart/parsers/<name>:<version>` and `:latest`.
5. **Supply Chain Security**:
   - Keyless signing with **Cosign**.
   - **SLSA Level 3 Provenance** generation.

---

## CRD Usage

```yaml
apiVersion: rampart.security/v1alpha1
kind: ClusterParser
metadata:
  name: sarif
spec:
  name: sarif
  family: sarif
  category: sast
  version: 1.0.0
  runtime: wasm
  source:
    oci: ghcr.io/rampart/parsers/sarif:1.0.0
  limits:
    maxMemoryMB: 256
    timeoutSeconds: 60
  detect:
    filenames:
      - "*.sarif"
      - "*.sarif.json"
    probes:
      - jsonHasKeys: ["runs"]
```
