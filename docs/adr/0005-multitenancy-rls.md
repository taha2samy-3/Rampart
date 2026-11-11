# ADR 0005 — Multi-tenancy with tenant_id + Postgres Row-Level Security, tenant ↔ namespace

Status: accepted · Date: 2026-11-10

## Context
DefectDojo has no tenancy; ArmorCode and others offer business-unit hierarchies and MSSP segregation. We need tenancy from the first migration because retrofitting it is the most expensive change in this class of system.

## Decision
- Every tenant-owned table has `tenant_id uuid not null` as the leading column of its primary/unique indexes.
- RLS policies on all tenant tables; the application role is not the table owner; `FORCE ROW LEVEL SECURITY`; each transaction sets `app.tenant_id` with `set_config(..., true)` (works with PgBouncer transaction pooling). Four database roles (owner, app, system with `BYPASSRLS`, read-only) separate tenant work from cross-tenant maintenance.
- A `Tenant` CR lists the namespaces it owns (one by default). The binding comes only from that list, never from a namespace label; namespaced CRDs are therefore tenant-scoped by construction; cluster-scoped `Cluster*` policies provide defaults.
- Within a tenant, `HierarchyNode` trees provide business units and scoped RBAC.
- Dedicated-database tenants are a later option behind the same store interface.

## Consequences
- Shared-DB efficiency for most installs; a bug in a WHERE clause cannot leak across tenants because RLS blocks it.
- Vulnerability intelligence tables (CVE, CWE, EPSS, KEV, taxonomies) are global and read-only for tenants.
- Cross-tenant reporting for MSSPs is done by iterating tenants with a platform-admin role, never by joins.
