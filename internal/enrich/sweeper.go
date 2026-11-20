package enrich

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"rampart/internal/jobs"
)

const (
	// AdvisorySweeperLockID is the PostgreSQL advisory lock key for the advisory sweeper.
	// Generated deterministically so only one replica executes the sweep at a time.
	AdvisorySweeperLockID = int64(0x41647669736f7279) // "Advisory" in ASCII hex

	// DefaultAdvisorySweepInterval is how often the sweeper looks for CVEs due for refresh.
	DefaultAdvisorySweepInterval = 15 * time.Minute
)

// AdvisoryEnqueuer abstracts enqueueing into River so tests can mock it easily.
type AdvisoryEnqueuer interface {
	EnqueueAdvisoryRefresh(ctx context.Context, args jobs.AdvisoryRefreshArgs, priority int) error
}

// AdvisorySweeper coordinates periodic re-checking and cache invalidation of threat advisories.
type AdvisorySweeper struct {
	pool     *pgxpool.Pool
	enqueuer AdvisoryEnqueuer
	logger   *slog.Logger
}

// NewAdvisorySweeper creates a new AdvisorySweeper.
func NewAdvisorySweeper(pool *pgxpool.Pool, enqueuer AdvisoryEnqueuer, logger *slog.Logger) *AdvisorySweeper {
	if logger == nil {
		logger = slog.Default()
	}
	return &AdvisorySweeper{
		pool:     pool,
		enqueuer: enqueuer,
		logger:   logger,
	}
}

// Sweep checks the vulnerability table for pending or stale entries and enqueues refresh jobs.
func (s *AdvisorySweeper) Sweep(ctx context.Context) (int, error) {
	if s.pool == nil || s.enqueuer == nil {
		return 0, nil
	}

	query := `
		SELECT id, (cvss_best_score IS NULL OR cvss_best_score = 0) AS is_pending
		FROM vulnerability
		WHERE 
			((cvss_best_score IS NULL OR cvss_best_score = 0) AND updated_at < NOW() - INTERVAL '1 hour')
			OR (updated_at < NOW() - INTERVAL '24 hours')
		ORDER BY (cvss_best_score IS NULL OR cvss_best_score = 0) DESC, updated_at ASC
		LIMIT 100`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("advisory sweeper: query failed: %w", err)
	}
	defer rows.Close()

	enqueued := 0
	for rows.Next() {
		var (
			id        string
			isPending bool
		)
		if err := rows.Scan(&id, &isPending); err != nil {
			s.logger.Warn("advisory sweeper: failed to scan row", "err", err)
			continue
		}

		reason := "stale_cache"
		priority := 0
		if isPending {
			reason = "pending_scoring"
			priority = 10 // Higher priority for CVEs waiting on NIST NVD scoring
		}

		args := jobs.AdvisoryRefreshArgs{
			VulnerabilityID: id,
			Reason:          reason,
			Force:           false,
		}

		if err := s.enqueuer.EnqueueAdvisoryRefresh(ctx, args, priority); err != nil {
			s.logger.Warn("advisory sweeper: failed to enqueue job", "id", id, "err", err)
			continue
		}
		enqueued++
	}

	if enqueued > 0 {
		s.logger.Info("advisory sweeper: enqueued refresh jobs", "count", enqueued)
	}
	return enqueued, rows.Err()
}

// RunAdvisorySweeper runs the sweeper periodically using a PostgreSQL advisory lock across replicas.
func RunAdvisorySweeper(ctx context.Context, sweeper *AdvisorySweeper, pool *pgxpool.Pool, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultAdvisorySweepInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if pool == nil {
				continue
			}

			// Try to acquire the advisory lock
			var locked bool
			err := pool.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", AdvisorySweeperLockID).Scan(&locked)
			if err != nil || !locked {
				continue
			}

			_, _ = sweeper.Sweep(ctx)

			// Release advisory lock
			_, _ = pool.Exec(ctx, "SELECT pg_advisory_unlock($1)", AdvisorySweeperLockID)
		}
	}
}
