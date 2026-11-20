---
name: rampart-domain-guard
description: Enforces Rampart domain boundaries, CRD validation, live API bindings, and prevents hallucinating unverified metrics or schemas.
---

# Rampart Domain Guard Skill

Use this skill whenever:
- Designing or implementing new API endpoints in `internal/query` or `internal/ingest`.
- Creating or editing frontend routes and components in `web/src/routes`.
- Working with SBOM analyzers, security feeds, or parser modules.

## Key Rules & Verification Steps

1. **Verify Backend Contract First**:
   - Inspect `internal/query` and `internal/domain` to verify the actual structure of JSON responses before building UI mockups or state hooks.
   - Do NOT assume fields like `lifecycle`, `environments`, or `sla_days` exist unless backed by DB models and migration files.

2. **Check WASM Dependencies**:
   - Verify parser availability with `wasmstore.Default().Has(...)`.
   - Never register a parser in UI without checking its readiness status from `/api/v1/parsers`.

3. **Multi-User Scale Checklist (docs/39)**:
   - For any action button that triggers backend work (e.g., "Check again", "Sync feed", "Analyze SBOM"):
     - Ensure backend implements atomic claiming (`ClaimSBOMAnalysis` or advisory lock).
     - Ensure UI disables button during in-progress state and displays when the current run started.
     - Ensure responses return structured status: `queued`, `already_running`, or `cooldown_active`.
