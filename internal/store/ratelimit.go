package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// IncrementQuota increments the usage counter for a given tenant, key, and windowStart by amount.
// Returns the updated total usage within that window.
func (s *PostgresStore) IncrementQuota(ctx context.Context, tenantID uuid.UUID, key string, windowStart time.Time, amount int64) (int64, error) {
	var used int64
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			INSERT INTO quota_usage (tenant_id, key, window_start, used)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, key, window_start)
			DO UPDATE SET used = quota_usage.used + EXCLUDED.used
			RETURNING used`
		return tx.QueryRow(ctx, query, tenantID, key, windowStart.UTC(), amount).Scan(&used)
	})
	return used, err
}

// GetQuotaUsage retrieves the current usage counter for a given tenant, key, and windowStart.
func (s *PostgresStore) GetQuotaUsage(ctx context.Context, tenantID uuid.UUID, key string, windowStart time.Time) (int64, error) {
	var used int64
	err := s.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		query := `
			SELECT used
			FROM quota_usage
			WHERE tenant_id = $1 AND key = $2 AND window_start = $3`
		err := tx.QueryRow(ctx, query, tenantID, key, windowStart.UTC()).Scan(&used)
		if err == pgx.ErrNoRows {
			used = 0
			return nil
		}
		return err
	})
	return used, err
}
