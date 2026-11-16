package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// StoredFramework is a ComplianceFramework or ClusterComplianceFramework as stored (D102).
type StoredFramework struct {
	Origin    string // "tenant" | "cluster"
	Name      string
	Spec      []byte // the last valid spec (applied_spec); nil when it never validated
	Error     string // why the current spec is not applied, if it is not
	UpdatedAt time.Time
}

// ComplianceFrameworkStore lists the frameworks a tenant sees: its own and every cluster one.
type ComplianceFrameworkStore interface {
	ListComplianceFrameworks(ctx context.Context, tenantID uuid.UUID) ([]StoredFramework, error)
}

var _ ComplianceFrameworkStore = (*PostgresStore)(nil)

// ListComplianceFrameworks implements ComplianceFrameworkStore. The tenant's own frameworks are read through
// row-level security; the cluster ones are global (cluster_policy has no RLS and rampart_app may read it).
// Sorted by origin ("cluster" before "tenant"), then name.
func (s *PostgresStore) ListComplianceFrameworks(ctx context.Context, tenantID uuid.UUID) ([]StoredFramework, error) {
	var out []StoredFramework
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT 'cluster' AS origin, name, applied_spec, CASE WHEN compiled_ok THEN '' ELSE coalesce(compile_error, '') END, updated_at
			  FROM cluster_policy WHERE kind = 'compliance'
			UNION ALL
			SELECT 'tenant', name, applied_spec, CASE WHEN compiled_ok THEN '' ELSE coalesce(compile_error, '') END, updated_at
			  FROM policy_object WHERE tenant_id = $1 AND kind = 'compliance'
			ORDER BY origin, name`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f StoredFramework
			if err := rows.Scan(&f.Origin, &f.Name, &f.Spec, &f.Error, &f.UpdatedAt); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// ApplicationComplianceScopes returns the compliance scopes of every application of the tenant (D102): an
// application that lists none maps to an empty slice.
func (s *PostgresStore) ApplicationComplianceScopes(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID][]string, error) {
	out := map[uuid.UUID][]string{}
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, compliance_scope FROM application WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var scopes []string
			if err := rows.Scan(&id, &scopes); err != nil {
				return err
			}
			if scopes == nil {
				scopes = []string{}
			}
			out[id] = scopes
		}
		return rows.Err()
	})
	return out, err
}
