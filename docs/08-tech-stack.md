# 08 — Technology stack (Go)

| Concern | Choice | Alternative considered | Why |
|---|---|---|---|
| Language / toolchain | Go 1.25+, modules, `go vet`, `golangci-lint`, `govulncheck` | — | single static binary, k8s ecosystem |
| HTTP | `net/http` + **chi** router | echo, gin | zero deviation from `http.Handler`, middleware ecosystem |
| OpenAPI | **huma** (code-first OpenAPI 3.1, router-agnostic) for public API; generated TS client for the SPA | oapi-codegen (spec-first), ogen | one source of truth in Go types; fast iteration |
| Internal RPC | none initially (all targets share Postgres + jobs); **connect-go** if cross-target RPC becomes necessary | gRPC + gateway | avoid premature service mesh |
| Database | **PostgreSQL 16+** via **pgx/v5**; **sqlc** for queries (`:copyfrom` for bulk); **goose** embedded migrations | GORM/ent, Atlas | explicit SQL, no ORM overhead at 5M rows |
| Jobs / events | **River** (Postgres-backed, transactional) as default `EventBus`; **NATS JetStream** adapter optional | Kafka, Redis Streams, RabbitMQ, pgmq | zero extra infra, outbox for free, scales to NATS |
| Object storage | S3 API via **aws-sdk-go-v2** (works with MinIO, SeaweedFS, Garage, Ceph, GCS/Azure via gateway) | — | |
| Cache / rate limit | **Valkey** (optional), in-process fallback | Redis | |
| Kubernetes | **kubebuilder v4** + **controller-runtime v0.23**, **controller-gen** for CRDs/RBAC, CEL validation markers | operator-sdk | |
| Integration plugins | **wazero** (pure-Go WebAssembly runtime, WASI) for parser plugins; **connect-go** for gRPC connector plugins; OCI artifacts via `oras-go`, verification via `sigstore-go` | Extism, hashicorp/go-plugin | sandbox for untrusted parsers without CGO; out-of-process connectors with their own identity |
| Policy language | **cel-go** | OPA/Rego (optional later) | same as k8s/Kyverno, sandboxed |
| AuthN | **coreos/go-oidc** + `golang.org/x/oauth2`; SAML bridge (crewjam/saml or Dex) | | |
| AuthZ | **casbin** (RBAC with domains) | OpenFGA / SpiceDB | embedded; ReBAC later if asset-level sharing needed |
| SARIF | **owenrumney/go-sarif/v3** | gosarif | typed, maintained, used by Trivy |
| CycloneDX | **CycloneDX/cyclonedx-go** | | spec 1.0–1.7 |
| SPDX | **spdx/tools-golang** | | 2.x; 3.0 hand-rolled JSON-LD later |
| VEX | **openvex/go-vex**; CSAF via custom structs | | |
| purl / CPE | **package-url/packageurl-go**, **knqyf263/go-cpe** | | |
| CVSS | **pandatix/go-cvss** (v2/v3.x/v4) | goark/go-cvss (no v4) | |
| Vulnerability feeds | OSV (`api.osv.dev` + bulk dumps), NVD 2.0, EPSS CSV/API, KEV JSON, CWE XML; mirror-aware HTTP client with ETag | | |
| Observability | **OpenTelemetry Go** (traces, metrics, logs via `otelslog`), **prometheus/client_golang**, `log/slog`, `logr` adapter | | |
| CLI / config | **cobra** + **koanf** | viper | |
| Templating (notifications) | Go `text/template` with sprig subset | | |
| PDF reports | server-side HTML → PDF via headless Chromium Job (rod) or `maroto`; HTML/CSV/JSON first | | |
| Web UI | **React + TypeScript + Vite**, TanStack Query/Table, generated OpenAPI client; embedded into the binary with `embed` for monolithic mode | htmx/templ | rich findings explorer needs a real SPA |
| Testing | `testing` + testify, **testcontainers-go** (Postgres, MinIO), **envtest** for operator, golden files for parsers, k6 for load | | |
| Build / release | **ko** (multi-arch, distroless, SBOM) or buildx; **goreleaser** for CLI; **cosign** sign + attest; Helm chart as OCI | | |
| Docs | this `docs/` folder; OpenAPI served at `/api/v1/openapi.json`; CRD reference generated with `crd-ref-docs` | | |

## Repository layout (target)

```
.
├── cmd/rampart/                 # main: -target flag
├── api/v1alpha1/                # CRD types (+kubebuilder markers)
├── internal/
│   ├── targets/                 # per-target wiring
│   ├── domain/                  # entities, state machine, value objects
│   ├── parsers/{sarif,cyclonedx,spdx,openvex,csaf,trivy,grype,semgrep,gitleaks,checkov,nuclei,zap,bandit,depcheck,kubebench,prowler,snyk,syft,gitlab,generic,policyreport}
│   ├── normalize/               # ids, purl, cpe, paths, severity, cwe, taxonomy
│   ├── ingest/                  # uploads, staging, merge, reimport
│   ├── enrich/                  # feeds, mirrors, aliases
│   ├── risk/                    # scoring, rollups
│   ├── policy/                  # cel env, sla, automation
│   ├── connectors/{jira,github,gitlab,azureboards,slack,teams,email,webhook}
│   ├── query/                   # read models, API handlers
│   ├── store/                   # sqlc output, migrations, rls
│   ├── jobs/                    # river workers
│   ├── events/                  # EventBus (river, nats)
│   ├── auth/                    # oidc, tokens, casbin
│   └── operator/                # reconcilers
├── web/                         # SPA
├── charts/rampart/              # Helm
├── config/                      # kustomize (crd, rbac, manager)
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
