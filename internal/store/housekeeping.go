package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Housekeeping windows (docs/23 R1, docs/16 D99). Each table below exists to answer a question for a short time;
// past that, a row answers nothing and only grows the table.
const (
	// QuotaKeep keeps two days of hourly quota windows (D73): the limiter reads only the current hour.
	QuotaKeep = 48 * time.Hour
	// HeldCloseKeep keeps a decided held close for 90 days, so the run page still shows who decided and when.
	HeldCloseKeep = 90 * 24 * time.Hour
	// ComplianceSnapshotKeep keeps the daily compliance readings 400 days: a year of evidence for an annual audit
	// (PCI DSS, SOC 2 Type II), with a month to spare (D102).
	ComplianceSnapshotKeep = 400 * 24 * time.Hour
)

// HousekeepingResult counts what Housekeeping removed, by table.
type HousekeepingResult map[string]int64

// Housekeeping removes rows that no longer serve their purpose from the tables nothing else cleans (docs/23 R1):
// spent federation token ids and webhook delivery ids past their replay window, hourly quota windows past
// QuotaKeep, and held closes decided more than HeldCloseKeep ago. It runs as rampart_system (BYPASSRLS), once
// per retention sweep, under the sweep's advisory lock. Retention being off does not stop it: these rows are not
// tenant data a policy keeps, they are bookkeeping.
func Housekeeping(ctx context.Context, system *pgxpool.Pool, now time.Time) (HousekeepingResult, error) {
	out := HousekeepingResult{}
	if system == nil {
		return out, nil
	}
	for _, q := range []struct {
		table, sql string
		arg        time.Time
	}{
		{"federation_jti", `DELETE FROM federation_jti WHERE expires_at < $1`, now},
		{"webhook_delivery", `DELETE FROM webhook_delivery WHERE expires_at < $1`, now},
		{"quota_usage", `DELETE FROM quota_usage WHERE window_start < $1`, now.Add(-QuotaKeep)},
		{"held_close", `DELETE FROM held_close WHERE decided_at IS NOT NULL AND decided_at < $1`, now.Add(-HeldCloseKeep)},
		{"compliance_snapshot", `DELETE FROM compliance_snapshot WHERE day < $1::date`, now.Add(-ComplianceSnapshotKeep)},
	} {
		tag, err := system.Exec(ctx, q.sql, q.arg)
		if err != nil {
			return out, fmt.Errorf("store: housekeeping %s: %w", q.table, err)
		}
		if n := tag.RowsAffected(); n > 0 {
			out[q.table] = n
		}
	}
	return out, nil
}
