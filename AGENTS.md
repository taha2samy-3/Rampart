# Rampart AI Assistant Guidelines (Anti-Hallucination & Architecture Guardrails)

This document defines strict operational rules for AI agents working on Rampart to prevent hallucinations, schema drifts, and broken assumptions.

## 1. Ground Truth & Zero-Mock Principle
- **No Invented Values**: Never render fake numbers, hardcoded SLA schedules, or placeholder metrics in UI components (as previously flagged in `PoliciesRoute.tsx`). Always bind to live API contracts (`/api/v1/scoring`, `/api/v1/feeds`, `/api/v1/parsers`).
- **Honest Status**: If a feature or data source is not yet active, explicitly render "Not configured" or "Not synced yet" rather than guessing.
- **Fail-Fast Ingestion**: A parser or SBOM reader that cannot execute (e.g. missing WASM module) must be surfaced as `unavailable` with a 503 error before creating empty applications or orphan runs.

## 2. CRD and Model Synchronization
- When editing any CRD in `deploy/crds/`:
  - Always mirror the change to `deploy/helm/rampart/crds/`.
  - Re-run `python3 hack/crds-bundle.py` to regenerate `deploy/rampart-crds.yaml`.
  - Validate with `python3 hack/crds-bundle.py --check`.

## 3. WASM Modules & Parser Execution
- In local development and backend tests:
  - WASM modules are built into `.cache/wasm/<name>/parser.wasm`.
  - When running Go tests touching `internal/ingest` or parsers, always set: `RAMPART_WASM_DIR=$PWD/.cache/wasm`.
  - In Helm charts, support both `imageVolume` (K8s 1.35+ / containerd 2.1+) and `initContainer` (`values-parsers-v1-init.yaml`) delivery modes.

## 4. Concurrency, Freshness & Quotas (docs/38 & docs/39)
- **Single-Flight Rule**: Manual triggers (`/refresh-vulnerabilities`, `/analyze`) must deduplicate in flight via database claims (`ClaimSBOMAnalysis`).
- **Cooldown & Rate Limiting**: Apply a 5-minute cooldown on manual application analyses to safeguard external analyzer quotas (e.g. Sonatype OSS Index).
- **Stream Over Polling**: Use the Server-Sent Events stream (`live_event` table) for UI updates instead of short-interval HTTP polling.

## 5. Mandatory Verification Cycle Before Merging / Releasing
Never mark a task complete or push without running the full check battery:
1. Frontend: `bun run typecheck`, `bun run lint`, `bun run build`, and `bun run test` (via Vitest).
2. Backend: `go test -race` on affected packages with `RAMPART_WASM_DIR=$PWD/.cache/wasm`.
3. Helm: `helm lint deploy/helm/rampart` and template validation against `values-parsers-v1.yaml` and `values-parsers-v1-init.yaml`.
