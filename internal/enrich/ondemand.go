package enrich

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrSyncBusy is returned when a feed sync is already running (on this or another replica).
var ErrSyncBusy = errors.New("a feed sync is already running")

// ErrFeedOff is returned when the feed asked for is not run by this server's configuration (NVD switched off, OSV with
// no ecosystem chosen): a click would mark it "syncing" and then do nothing.
var ErrFeedOff = errors.New("this feed is switched off in the server's configuration")

// OnDemand runs a feed sync when someone asks for it on the feeds page. The query API runs as rampart_app, which
// cannot write the global tables (D19), so the sync must run with the system pool, under the same advisory lock as
// the scheduler: two syncs never run at once, and the one asked for does the same work as the scheduled one.
type OnDemand struct {
	base context.Context // the server's: a sync does not outlive it, and is not tied to the request that asked
	pool *pgxpool.Pool
	cfg  FeedConfig
	log  *slog.Logger
}

// NewOnDemand takes the server's context, the system pool and the same configuration as the scheduler.
func NewOnDemand(base context.Context, pool *pgxpool.Pool, cfg FeedConfig, log *slog.Logger) *OnDemand {
	cfg.defaults()
	return &OnDemand{base: base, pool: pool, cfg: cfg, log: log}
}

// runs reports whether a round would run the feed under this configuration.
func (o *OnDemand) runs(feed string) bool {
	switch feed {
	case "nvd":
		return !o.cfg.NVDDisabled
	case "osv":
		return len(o.cfg.OSVEcosystems) > 0
	}
	return true
}

// Start marks the feeds as syncing, before it returns, so the page sees the state at once, and runs the sync in the
// background. feed is one feed's name, or empty for all of names (the feeds that are switched on).
func (o *OnDemand) Start(ctx context.Context, feed string, names []string) error {
	if feed != "" {
		if !o.runs(feed) {
			return ErrFeedOff
		}
		names = []string{feed}
	} else {
		var run []string
		for _, n := range names {
			if o.runs(n) {
				run = append(run, n)
			}
		}
		names = run
	}
	conn, err := o.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, fnvKey("rampart/feed-sync")).Scan(&got); err != nil || !got {
		conn.Release()
		if err != nil {
			return err
		}
		return ErrSyncBusy
	}
	syncer := NewFeedSyncer(o.pool)
	syncer.clearStaleSyncing(ctx) // the lock is ours: whatever still says syncing is left over
	if err := syncer.markSyncing(ctx, names); err != nil {
		unlockAndRelease(o.base, conn, fnvKey("rampart/feed-sync"))
		return fmt.Errorf("marking the feeds as syncing: %w", err)
	}
	cfg := o.cfg
	cfg.Only = feed
	go func() {
		bg, cancel := context.WithTimeout(o.base, 30*time.Minute)
		defer cancel()
		// What follows must run when the sync itself ran out of time, so it has a context of its own.
		defer func() {
			if r := recover(); r != nil {
				o.log.Error("feed sync (on demand) panicked", "panic", r)
			}
			cctx, ccancel := context.WithTimeout(context.WithoutCancel(o.base), 30*time.Second)
			defer ccancel()
			// A feed asked for that no step ran, or one cut off, must not stay "syncing".
			syncer.clearSyncing(cctx, names)
			unlockAndRelease(cctx, conn, fnvKey("rampart/feed-sync"))
		}()
		if err := syncer.SyncAll(bg, cfg, o.log); err != nil {
			o.log.Warn("feed sync (on demand) finished with errors", "feed", feed, "error", err)
		}
		if cfg.OnSynced != nil {
			cfg.OnSynced(bg)
		}
	}()
	return nil
}

func (s *FeedSyncer) markSyncing(ctx context.Context, feeds []string) error {
	for _, f := range feeds {
		if _, err := s.pool.Exec(ctx, `INSERT INTO feed_state (feed, status) VALUES ($1, 'syncing')
			ON CONFLICT (feed) DO UPDATE SET status = 'syncing', error = NULL`, f); err != nil {
			return err
		}
	}
	return nil
}

// clearSyncing puts feeds that still say syncing back to idle.
func (s *FeedSyncer) clearSyncing(ctx context.Context, feeds []string) {
	_, _ = s.pool.Exec(ctx, `UPDATE feed_state SET status = 'idle' WHERE status = 'syncing' AND feed = ANY($1)`, feeds)
}

// clearStaleSyncing is called with the sync lock held: no sync is running, so "syncing" is a round a restart cut off.
func (s *FeedSyncer) clearStaleSyncing(ctx context.Context) {
	_, _ = s.pool.Exec(ctx, `UPDATE feed_state SET status = 'error', error = 'the sync was interrupted (the server restarted)' WHERE status = 'syncing'`)
}

// unlockAndRelease frees a session advisory lock and returns the connection to the pool. When the unlock fails the
// connection may still hold the lock, so it is closed rather than pooled: every later round would read "busy" for as
// long as that connection lived.
func unlockAndRelease(ctx context.Context, conn *pgxpool.Conn, key int64) {
	if _, err := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key); err != nil {
		_ = conn.Hijack().Close(context.WithoutCancel(ctx))
		return
	}
	conn.Release()
}
