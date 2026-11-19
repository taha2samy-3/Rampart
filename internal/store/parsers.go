package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
)

var _ domain.ParserStore = (*PostgresStore)(nil)

// ListParsers lists the parsers available to a tenant: cluster-wide parsers and tenant-scoped ones.
func (s *PostgresStore) ListParsers(ctx context.Context, tenantID uuid.UUID) ([]domain.StoredParserObject, error) {
	var out []domain.StoredParserObject
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT 'cluster' AS origin, name, applied_spec, CASE WHEN compiled_ok THEN '' ELSE coalesce(compile_error, '') END, updated_at
			  FROM cluster_policy WHERE kind = 'parser'
			UNION ALL
			SELECT 'tenant', name, applied_spec, CASE WHEN compiled_ok THEN '' ELSE coalesce(compile_error, '') END, updated_at
			  FROM policy_object WHERE tenant_id = $1 AND kind = 'parser'
			ORDER BY origin, name`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p domain.StoredParserObject
			if err := rows.Scan(&p.Origin, &p.Name, &p.Spec, &p.Error, &p.UpdatedAt); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}
