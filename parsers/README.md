# Rampart Modular Parsers

This directory contains all 21 Rampart parsers implemented as standalone, unprivileged modules following the **"All Come In Front Door"** architectural principle (docs/29):

```
parsers/
├── wasm/                 # 17 WebAssembly WASI Preview 1 modules (distributed as OCI artifacts on GHCR)
│   ├── checkov/          # IaC misconfiguration scanner
│   ├── cyclonedx/        # CycloneDX SBOM & VEX standard
│   ├── dependencycheck/  # OWASP Dependency-Check scanner
│   ├── dependencytrack/  # OWASP Dependency-Track audit API
│   ├── gitlab/           # GitLab security report format
│   ├── gitleaks/         # Secret detection with strict secret redaction
│   ├── grype/            # Anchore Grype vulnerability scanner
│   ├── kubebench/        # Kubernetes CIS benchmark scanner
│   ├── openvex/          # OpenVEX exploitability statements
│   ├── prowler/          # AWS/Azure/GCP Cloud security scanner
│   ├── sarif/            # OASIS SARIF 2.1.0 standard parser
│   ├── semgrep/          # Semgrep SAST JSON parser
│   ├── snyk/             # Snyk test JSON scanner
│   ├── spdx/             # SPDX SBOM standard
│   ├── syft/             # Anchore Syft SBOM generator
│   ├── trivy/            # Aqua Security Trivy scanner
│   └── trufflehog/       # TruffleHog v3 secrets scanner
│
└── lua/                  # 4 Sandboxed Lua scripts for lightweight reports
    ├── bandit/           # Python Bandit SAST JSON
    ├── genericjson/      # Generic findings JSON
    ├── nuclei/           # ProjectDiscovery Nuclei JSONL
    └── zap/              # OWASP ZAP DAST alert report
```

## Why WASM vs Lua?

1. **WASM (17 Parsers):**
   - Used for heavy standards (SARIF, CycloneDX, SPDX), secret detection requiring redaction (`gitleaks`, `trufflehog`), and complex nested scanners.
   - Compiled to `wasip1/wasm` from Go.
   - Executed under `wazero` with JIT native performance, strict memory caps (`limits.maxMemoryMB`), zero network access, and air-gapped readiness.
   - Packaged and published as versioned OCI artifacts to `ghcr.io/rampart/parsers/<name>:<version>`.

2. **Lua (4 Parsers):**
   - Used for simple, flat JSON or line-delimited text reports (`bandit`, `zap`, `nuclei`, `genericjson`).
   - Runs in-memory with `gopher-lua`, providing streaming output with minimal footprint and zero compilation needed.

## Running Tests

- Run all WASM parser equivalence and error tests:
  ```bash
  go test -v ./parsers/wasm/...
  ```
- Run all Lua parser tests:
  ```bash
  go test -v ./parsers/lua/...
  ```
