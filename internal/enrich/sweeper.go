package enrich

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
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

	// AdvisoryPriorityPending and AdvisoryPriorityStale are the River priorities (1 to 4, 1 first) of the sweep's jobs.
	AdvisoryPriorityPending = 3
	AdvisoryPriorityStale   = 4
)

// AdvisoryEnqueuer abstracts enqueueing into River so tests can mock it easily.
type AdvisoryEnqueuer interface {
	EnqueueAdvisoryRefresh(ctx context.Context, args jobs.AdvisoryRefreshArgs, priority int) error
}

// AdvisorySweeper coordinates periodic re-checking and cache invalidation of threat advisories.
type AdvisorySweeper struct {
	pool        *pgxpool.Pool
	enqueuer    AdvisoryEnqueuer
	logger      *slog.Logger
	lastSweepAt time.Time
	mu          sync.RWMutex
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

// LastSweepAt returns the timestamp of the most recent sweep run.
func (s *AdvisorySweeper) LastSweepAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSweepAt
}

// Sweep checks the vulnerability table for pending or stale entries and enqueues refresh jobs.
func (s *AdvisorySweeper) Sweep(ctx context.Context) (int, error) {
	if s.pool == nil || s.enqueuer == nil {
		return 0, nil
	}

	s.mu.Lock()
	s.lastSweepAt = time.Now().UTC()
	s.mu.Unlock()

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

		// River priorities are 1 (first) to 4 (last); a value outside is refused at insert. Both are background
		// work: a CVE waiting on NVD's score goes before a stale one, and both after anything a person asked for.
		reason := "stale_cache"
		priority := AdvisoryPriorityStale
		if isPending {
			reason = "pending_scoring"
			priority = AdvisoryPriorityPending
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

// RunAdvisorySweeper runs the sweeper periodically using a PostgreSQL advisory lock across replicas. The lock is
// session-level, so it is taken and released on one acquired connection (as analysis.RunSweeper does): taken through
// the pool, the unlock could run on another connection, fail, and leave the lock held for ever by an idle connection.
//
// It is not started by the server (docs/51 step 1.5: the owner decides whether it is wired or removed).
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
			sweepLocked(ctx, sweeper, pool)
		}
	}
}

// sweepLocked runs one sweep while holding the advisory lock on a single connection; another replica holding it skips.
func sweepLocked(ctx context.Context, sweeper *AdvisorySweeper, pool *pgxpool.Pool) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		sweeper.logger.Warn("advisory sweeper: no database connection", "err", err)
		return
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", AdvisorySweeperLockID).Scan(&locked); err != nil {
		sweeper.logger.Warn("advisory sweeper: taking the lock failed", "err", err)
		return
	}
	if !locked {
		return // another replica sweeps
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", AdvisorySweeperLockID); err != nil {
			sweeper.logger.Warn("advisory sweeper: releasing the lock failed", "err", err)
		}
	}()
	if _, err := sweeper.Sweep(ctx); err != nil {
		sweeper.logger.Warn("advisory sweeper: sweep failed", "err", err)
	}
}
