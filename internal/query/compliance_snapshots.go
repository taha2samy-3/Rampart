package query

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"rampart/internal/store"
)

// SnapshotCompliance keeps today's reading of every framework of every tenant (D102), so a later question about a
// past day ("what did 6.3.3 read on 30 June?") has the answer that was shown then, not one recomputed from data
// that has since changed. A reading taken twice the same day replaces the first.
func (a *API) SnapshotCompliance(ctx context.Context, tenantIDs []uuid.UUID, now time.Time, log *slog.Logger) (kept int) {
	rd, ok := a.store.(store.ComplianceReader)
	if !ok {
		return 0
	}
	for _, t := range tenantIDs {
		fws, _, err := a.frameworks(ctx, t)
		if err != nil {
			log.Warn("compliance snapshot: listing frameworks failed", "tenant", t, "error", err)
			continue
		}
		for _, fw := range fws {
			res, err := a.evaluate(ctx, t, fw, nil, now)
			if err != nil {
				log.Warn("compliance snapshot: evaluation failed", "tenant", t, "framework", fw.ID, "error", err)
				continue
			}
			raw, err := json.Marshal(res)
			if err != nil {
				continue
			}
			if err := rd.SaveComplianceSnapshot(ctx, t, fw.ID, now, raw); err != nil {
				log.Warn("compliance snapshot: saving failed", "tenant", t, "framework", fw.ID, "error", err)
				continue
			}
			kept++
		}
	}
	return kept
}

// RunComplianceSnapshots takes the readings now and then every interval. One replica takes them at a time: lock
// (rampart_system) holds a session advisory lock for the length of a round. tenants lists every tenant.
func (a *API) RunComplianceSnapshots(ctx context.Context, tenants func(context.Context) ([]uuid.UUID, error), lock *pgxpool.Pool, interval time.Duration, log *slog.Logger) {
	const lockKey = int64(0x52414d50_434f4d50) // "RAMPCOMP"
	round := func() {
		if lock != nil {
			conn, err := lock.Acquire(ctx)
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
		ids, err := tenants(ctx)
		if err != nil {
			log.Warn("compliance snapshot: listing tenants failed", "error", err)
			return
		}
		if n := a.SnapshotCompliance(ctx, ids, time.Now().UTC(), log); n > 0 {
			log.Info("compliance readings kept", "readings", n)
		}
	}
	round()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			round()
		}
	}
}
