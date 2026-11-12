# 08 — Technology stack (Go)

> Corrected after Phases 0–2 (D54): rows marked **built** are what the code uses (`go.mod`); rows marked **planned** name the phase that brings them. Where the first plan named a library that was not used, the row says what replaced it and why.

| Concern | Choice | Alternative considered | Why |
|---|---|---|---|
| Language / toolchain | Go 1.25+, modules, `go vet`, `golangci-lint`, `govulncheck` | — | single static binary, k8s ecosystem |
| HTTP | **built**: `net/http` with the Go 1.22+ `ServeMux` (method and path patterns) | chi, echo, gin | the standard mux covers every route we have; chi was the plan and was not needed |
| OpenAPI | **planned**: no OpenAPI document is served yet; the SPA types are written by hand (13 §10). Choosing the generator (huma or oapi-codegen) is open | oapi-codegen (spec-first), ogen | |
| Internal RPC | none initially (all targets share Postgres + jobs); **connect-go** if cross-target RPC becomes necessary | gRPC + gateway | avoid premature service mesh |
| Database | **built**: **PostgreSQL 16+** via **pgx/v5** with hand-written SQL and a small builder for the filter grammar (D16); **goose** embedded migrations. sqlc was not adopted | GORM/ent, Atlas, sqlc | explicit SQL, no ORM overhead at 5M rows |
| Jobs / events | **River** (Postgres-backed, transactional) as default `EventBus`; **NATS JetStream** adapter optional | Kafka, Redis Streams, RabbitMQ, pgmq | zero extra infra, outbox for free, scales to NATS |
| Object storage | S3 API via **aws-sdk-go-v2** (bundled default **SeaweedFS**; also Garage, Ceph RGW, AWS S3, GCS/Azure via gateway. MinIO community edition is not used: it is in maintenance mode, see D31) | — | |
| Cache / rate limit | **Valkey** (optional), in-process fallback | Redis | |
| Kubernetes | **built**: **controller-runtime** (v0.25), CRDs as YAML in `deploy/crds` kept identical to the chart's by CI, envtest | kubebuilder scaffolding, operator-sdk | |
| Integration plugins | **planned (Phases 4–5)**: **wazero** (pure-Go WebAssembly runtime, WASI) for parser plugins; **connect-go** for gRPC connector plugins; OCI artifacts via `oras-go`, verification via `sigstore-go` | Extism, hashicorp/go-plugin | sandbox for untrusted parsers without CGO; out-of-process connectors with their own identity |
| Policy language | **planned (Phase 2, `RiskPolicy`)**: **cel-go** | OPA/Rego (optional later) | same as k8s/Kyverno, sandboxed |
| AuthN | **built**: **coreos/go-oidc** + `golang.org/x/oauth2`; argon2id for the first administrator. **planned (Phase 4)**: SAML with crewjam/saml | | |
| AuthZ | **built**: role comparisons in code (D48); casbin was not needed for five ordered roles and per-application bindings | casbin, OpenFGA / SpiceDB | ReBAC later if asset-level sharing needed |
| SARIF, CycloneDX, SPDX, OpenVEX, native formats | **built**: our own token-walk parsers and structs over `encoding/json` / `encoding/xml` (D15, D54); fuzzed | go-sarif, cyclonedx-go, tools-golang, go-vex | streaming with bounded memory and our own limits; no library gave both |
| VEX | **built**: OpenVEX and CycloneDX VEX in `internal/vex` (D47). **planned (P1)**: CSAF | go-vex | |
| purl / CPE | **built**: **package-url/packageurl-go**. **planned**: CPE parsing | go-cpe | |
| CVSS | **planned (P1, D54)**: vectors are stored as given and a base score maps to a severity; parsing and computing vectors (**pandatix/go-cvss**, v2/v3.x/v4) comes later | goark/go-cvss (no v4) | |
| Vulnerability feeds | OSV (`api.osv.dev` + bulk dumps), NVD 2.0, EPSS CSV/API, KEV JSON, CWE XML; mirror-aware HTTP client with ETag | | |
| Observability | **OpenTelemetry Go** (traces, metrics, logs via `otelslog`), **prometheus/client_golang**, `log/slog`, `logr` adapter | | |
| CLI / config | **built**: the standard `flag` package and a small config loader (file, then env `RAMPART_*`, then flags, D6) | cobra, koanf, viper | |
| Templating (notifications) | Go `text/template` with sprig subset | | |
| PDF reports | server-side HTML → PDF via headless Chromium Job (rod) or `maroto`; HTML/CSV/JSON first | | |
| Web UI | **React + TypeScript + Vite**, TanStack Query/Table, generated OpenAPI client; embedded into the binary with `embed` for monolithic mode | htmx/templ | rich findings explorer needs a real SPA |
| Testing | **built**: standard `testing`; PostgreSQL in Docker started by `TestMain` (or `RAMPART_TEST_POSTGRES_URL` in CI), SeaweedFS in CI, **envtest** for the operator, fixtures and fuzz tests for parsers; Vitest for the web. kind end to end only in CI | testify, testcontainers-go | |
| Build / release | **ko** (multi-arch, distroless, SBOM) or buildx; **goreleaser** for CLI; **cosign** sign + attest; Helm chart as OCI | | |
| Docs | this `docs/` folder; OpenAPI served at `/api/v1/openapi.json`; CRD reference generated with `crd-ref-docs` | | |

## Repository layout (as built; planned directories are marked)

```
.
├── cmd/rampart/                 # main: -target flag
├── internal/
│   ├── targets/                 # per-target wiring
│   ├── domain/                  # entities, state machine, value objects
│   ├── parsers/{sarif,cyclonedx,spdx,openvex,syft,trivy,grype,semgrep,gitleaks,trufflehog,parseutil}   # wave 2 (Phase 3) adds checkov, nuclei, zap, …
│   ├── normalize/               # ids, purl, cpe, paths, severity, cwe, taxonomy
│   ├── ingest/                  # uploads, staging, merge, reimport
│   ├── enrich/                  # feeds, mirrors, aliases
│   ├── risk/, scoring/          # score, SLA, sweeps
│   ├── workflow/                # risk acceptance
│   ├── vex/, compliance/, retention/, integrations/, objectstore/, secrets/, telemetry/, ui/
│   ├── connectors/              # planned (Phase 3)
│   ├── query/                   # read models, API handlers
│   ├── store/                   # SQL, migrations, rls
│   ├── jobs/                    # river workers
│   ├── events/                  # EventBus (river, nats)
│   ├── auth/                    # oidc, tokens, roles, first administrator
│   └── operator/                # reconcilers
├── web/                         # SPA
├── deploy/helm/rampart/         # Helm chart
├── deploy/crds/                 # CRDs
├── deploy/compose/              # docker-compose for -target=all
├── docs/
└── hack/                        # scripts, fixtures, load tests
```

## Coding conventions

- Domain package has no imports from store/http/k8s.
- Every DB write goes through a `store.Tx` that sets `app.tenant_id`.
- Parsers: streaming, no allocation of whole document; fixtures + golden tests mandatory.
- Jobs are idempotent and keyed (River `UniqueOpts`) by `(kind, ingest_run_id)` etc.
- Errors wrapped with `%w`; sentinel errors in `domain`.
- No global state except the compiled CEL env cache.
- Context deadlines on every outbound call; connectors use per-connector circuit breakers.
