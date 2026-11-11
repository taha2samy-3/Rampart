package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MaintainPartitions ensures monthly range partitions for finding_event and audit_event
// are pre-created three months into the future (normative D4).
func MaintainPartitions(ctx context.Context, pool *pgxpool.Pool, now time.Time) error {
	if pool == nil {
		return fmt.Errorf("store: database pool is required for partition maintenance")
	}

	utcNow := now.UTC()
	// Create partitions for current month + next 3 months (4 months total)
	for i := 0; i <= 3; i++ {
		start := time.Date(utcNow.Year(), utcNow.Month()+time.Month(i), 1, 0, 0, 0, 0, time.UTC)
		end := start.AddDate(0, 1, 0)

		startStr := start.Format("2006-01-02 15:04:05-07")
		endStr := end.Format("2006-01-02 15:04:05-07")

		findingPart := fmt.Sprintf("finding_event_y%04d_m%02d", start.Year(), start.Month())
		auditPart := fmt.Sprintf("audit_event_y%04d_m%02d", start.Year(), start.Month())

		findingSQL := fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS %s PARTITION OF finding_event FOR VALUES FROM ('%s') TO ('%s')",
			findingPart, startStr, endStr,
		)
		if _, err := pool.Exec(ctx, findingSQL); err != nil {
			return fmt.Errorf("store: failed to create partition %s: %w", findingPart, err)
		}

		auditSQL := fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS %s PARTITION OF audit_event FOR VALUES FROM ('%s') TO ('%s')",
			auditPart, startStr, endStr,
		)
		if _, err := pool.Exec(ctx, auditSQL); err != nil {
			return fmt.Errorf("store: failed to create partition %s: %w", auditPart, err)
		}
	}

	return nil
}
