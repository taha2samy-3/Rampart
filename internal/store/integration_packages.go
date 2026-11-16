package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/domain"
)

func (s *PostgresStore) SaveIntegrationPackage(ctx context.Context, p domain.IntegrationPackageRecord) error {
	var errMsg *string
	if p.Error != "" {
		errMsg = &p.Error
	}
	return s.withTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO integration_package (tenant_id, name, kind, runtime, version, spec, error, generation, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
			ON CONFLICT (tenant_id, name) DO UPDATE SET kind = EXCLUDED.kind, runtime = EXCLUDED.runtime, version = EXCLUDED.version,
				spec = EXCLUDED.spec, error = EXCLUDED.error, generation = EXCLUDED.generation, updated_at = NOW()`,
			p.TenantID, p.Name, p.Kind, p.Runtime, p.Version, p.Spec, errMsg, p.Generation)
		return err
	})
}

const pkgCols = `tenant_id, name, kind, runtime, version, spec, COALESCE(error, ''), generation, updated_at`

func scanPkg(row pgx.Row) (domain.IntegrationPackageRecord, error) {
	var p domain.IntegrationPackageRecord
	err := row.Scan(&p.TenantID, &p.Name, &p.Kind, &p.Runtime, &p.Version, &p.Spec, &p.Error, &p.Generation, &p.UpdatedAt)
	return p, err
}

func (s *PostgresStore) GetIntegrationPackage(ctx context.Context, tenantID uuid.UUID, name string) (*domain.IntegrationPackageRecord, error) {
	var p domain.IntegrationPackageRecord
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		p, err = scanPkg(tx.QueryRow(ctx, `SELECT `+pkgCols+` FROM integration_package WHERE tenant_id = $1 AND name = $2`, tenantID, name))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *PostgresStore) ListIntegrationPackages(ctx context.Context, tenantID uuid.UUID) ([]domain.IntegrationPackageRecord, error) {
	var out []domain.IntegrationPackageRecord
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pkgCols+` FROM integration_package WHERE tenant_id = $1 ORDER BY name`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanPkg(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PostgresStore) DeleteIntegrationPackage(ctx context.Context, tenantID uuid.UUID, name string) error {
	return s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM integration_package WHERE tenant_id = $1 AND name = $2`, tenantID, name)
		return err
	})
}

// StageFeedPush keeps the latest file a feed plugin pushed (D94). The syncer loads it.
func (s *PostgresStore) StageFeedPush(ctx context.Context, feed string, body []byte, sha string, records int) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO feed_push (feed, body, sha256, records, received_at) VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (feed) DO UPDATE SET body = EXCLUDED.body, sha256 = EXCLUDED.sha256, records = EXCLUDED.records, received_at = NOW()`,
		feed, body, sha, records)
	return err
}
