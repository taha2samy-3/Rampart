package analysis

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SweepInterval is how often the sweep looks for analyses that are due: Dependency-Track's scheduled task runs every minute.
const SweepInterval = time.Minute

// RunSweeper queues the analyses that are due every interval until ctx ends. The service must read across tenants, so it is built on the system
// database role. One replica works at a time: the sweep takes a PostgreSQL advisory lock on pool, and without a pool (a single process) it
// does not lock.
func RunSweeper(ctx context.Context, svc *Service, pool *pgxpool.Pool, interval time.Duration, log *slog.Logger) {
	const lockKey = int64(0x52414d50_414e4c5a) // "RAMPANLZ"
	if log == nil {
		log = slog.Default()
	}
	sweep := func() {
		if pool != nil {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				return
			}
			defer conn.Release()
			var got bool
			if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil || !got {
				return
			}
			defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockKey) }()
		}
		n, err := svc.Sweep(ctx)
		switch {
		case err != nil:
			log.Warn("analysis sweep failed", "error", err)
		case n > 0:
			log.Info("analyses queued by the sweep", "count", n)
		}
	}
	sweep()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}
