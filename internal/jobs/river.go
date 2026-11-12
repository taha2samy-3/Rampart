package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

var (
	// ErrNoHandler fails a job instead of acknowledging work nobody did: River retries it
	// (25 attempts) until a handler is registered.
	ErrNoHandler = errors.New("jobs: no handler registered for this job kind")

	ErrConcurrencyLimitExceeded = errors.New("jobs: tenant queue concurrency limit exceeded")
)

// RiverQueue implements JobQueue on top of River (D2, D4, D25).
type RiverQueue struct {
	client *river.Client[pgx.Tx]
	pool   *pgxpool.Pool
}

// NewRiverQueue initializes the River job queue with optional LISTEN/NOTIFY or poll-only fallback (D4).
func NewRiverQueue(ctx context.Context, pool *pgxpool.Pool, directURL string, workers *river.Workers) (*RiverQueue, error) {
	if pool == nil {
		return nil, fmt.Errorf("jobs: database connection pool is required")
	}

	if workers == nil {
		workers = NewWorkers(nil)
	}

	driver := riverpgxv5.New(pool)

	cfg := &river.Config{
		Workers: workers,
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 50},
			"parse":            {MaxWorkers: 20},
			"enrich":           {MaxWorkers: 20},
			"policy":           {MaxWorkers: 20},
			"notify":           {MaxWorkers: 20},
		},
		FetchPollInterval: 1 * time.Second,
		Schema:            "river", // doc 12; keep in sync with store.RiverSchema
	}

	// D4 line 55: If no direct URL, River runs in poll-only mode
	if directURL == "" {
		cfg.PollOnly = true
	}

	client, err := river.NewClient(driver, cfg)
	if err != nil {
		return nil, fmt.Errorf("jobs: failed to initialize river client: %w", err)
	}

	return &RiverQueue{
		client: client,
		pool:   pool,
	}, nil
}

// Client returns the underlying River client.
func (q *RiverQueue) Client() *river.Client[pgx.Tx] {
	return q.client
}

// Start begins processing River jobs.
func (q *RiverQueue) Start(ctx context.Context) error {
	return q.client.Start(ctx)
}

// Stop gracefully drains and stops the River client.
func (q *RiverQueue) Stop(ctx context.Context) error {
	return q.client.Stop(ctx)
}

// EnqueueParse inserts a ParseJob into River with UniqueOpts (D2 line 23).
func (q *RiverQueue) EnqueueParse(ctx context.Context, args ParseJobArgs) error {
	_, err := q.client.Insert(ctx, args, &river.InsertOpts{
		Queue: "parse",
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
		},
		MaxAttempts: ParseMaxAttempts,
	})
	return err
}

// EnqueueParseTx enqueues a ParseJob inside an ongoing transaction (D2 line 23).
func (q *RiverQueue) EnqueueParseTx(ctx context.Context, tx pgx.Tx, args ParseJobArgs) error {
	_, err := q.client.InsertTx(ctx, tx, args, &river.InsertOpts{
		Queue: "parse",
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
		},
		MaxAttempts: ParseMaxAttempts,
	})
	return err
}

// EnqueueEnrich inserts an EnrichJob into River.
func (q *RiverQueue) EnqueueEnrich(ctx context.Context, args EnrichJobArgs) error {
	_, err := q.client.Insert(ctx, args, &river.InsertOpts{
		Queue:       "enrich",
		MaxAttempts: 25,
	})
	return err
}

// EnqueuePolicy inserts a PolicyJob into River.
func (q *RiverQueue) EnqueuePolicy(ctx context.Context, args PolicyJobArgs) error {
	_, err := q.client.Insert(ctx, args, &river.InsertOpts{
		Queue:       "policy",
		MaxAttempts: 25,
	})
	return err
}

// EnqueueNotify inserts a NotifyJob into River.
func (q *RiverQueue) EnqueueNotify(ctx context.Context, args NotifyJobArgs) error {
	_, err := q.client.Insert(ctx, args, &river.InsertOpts{
		Queue:       "notify",
		MaxAttempts: 25,
	})
	return err
}

// AcquireTenantSlot enforces per-tenant queue concurrency using the tenant_queue_limit semaphore (D25 line 434).
func AcquireTenantSlot(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, queueName string) (func(), error) {
	if pool == nil || tenantID == uuid.Nil {
		return func() {}, nil
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("jobs: failed to begin semaphore transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Ensure tenant_queue_limit row exists
	ensureQuery := `
		INSERT INTO tenant_queue_limit (tenant_id, queue_name, max_concurrency, current_concurrency)
		VALUES ($1, $2, 5, 0)
		ON CONFLICT (tenant_id, queue_name) DO NOTHING`
	if _, err := tx.Exec(ctx, ensureQuery, tenantID, queueName); err != nil {
		return nil, fmt.Errorf("jobs: failed to ensure semaphore entry: %w", err)
	}

	var maxConcurrency, currentConcurrency int
	lockQuery := `
		SELECT max_concurrency, current_concurrency
		FROM tenant_queue_limit
		WHERE tenant_id = $1 AND queue_name = $2
		FOR UPDATE`
	if err := tx.QueryRow(ctx, lockQuery, tenantID, queueName).Scan(&maxConcurrency, &currentConcurrency); err != nil {
		return nil, fmt.Errorf("jobs: failed to lock tenant semaphore: %w", err)
	}

	if currentConcurrency >= maxConcurrency {
		return nil, ErrConcurrencyLimitExceeded
	}

	// Increment
	incQuery := `
		UPDATE tenant_queue_limit
		SET current_concurrency = current_concurrency + 1
		WHERE tenant_id = $1 AND queue_name = $2`
	if _, err := tx.Exec(ctx, incQuery, tenantID, queueName); err != nil {
		return nil, fmt.Errorf("jobs: failed to acquire concurrency slot: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("jobs: failed to commit concurrency acquisition: %w", err)
	}

	release := func() {
		relCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		decQuery := `
			UPDATE tenant_queue_limit
			SET current_concurrency = GREATEST(0, current_concurrency - 1)
			WHERE tenant_id = $1 AND queue_name = $2`
		_, _ = pool.Exec(relCtx, decQuery, tenantID, queueName)
	}

	return release, nil
}

// ParseMaxAttempts is the River retry budget of a parse job (D17: 25 with exponential backoff).
const ParseMaxAttempts = 25

// PermanentError marks a failure no retry can fix (an unparseable report, a hash mismatch, an unknown
// format, D17). The worker cancels the job instead of retrying it, and the ingest run carries Code.
type PermanentError struct {
	Code string // stable, typed: sha256_mismatch, size_mismatch, parse_error, unsupported_format, ...
	Err  error
}

func (e *PermanentError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// IsPermanent reports whether err is, or wraps, a PermanentError.
func IsPermanent(err error) bool {
	var p *PermanentError
	return errors.As(err, &p)
}

// ParseHandler processes one parse job. attempt starts at 1.
type ParseHandler func(ctx context.Context, args ParseJobArgs, attempt int) error

// ParseWorker processes parse jobs via River.
type ParseWorker struct {
	river.WorkerDefaults[ParseJobArgs]
	Handle ParseHandler
}

func (w *ParseWorker) Work(ctx context.Context, job *river.Job[ParseJobArgs]) error {
	if w.Handle == nil {
		return ErrNoHandler
	}
	err := w.Handle(ctx, job.Args, job.Attempt)
	if IsPermanent(err) {
		return river.JobCancel(err) // retrying cannot help
	}
	return err
}

// NewWorkers builds the worker set. A kind with no handler fails its jobs (ErrNoHandler) instead of
// pretending to have done the work.
func NewWorkers(parse ParseHandler) *river.Workers {
	w := river.NewWorkers()
	river.AddWorker(w, &ParseWorker{Handle: parse})
	river.AddWorker(w, &EnrichWorker{})
	river.AddWorker(w, &PolicyWorker{})
	river.AddWorker(w, &NotifyWorker{})
	return w
}

// EnrichWorker processes enrichment jobs via River.
type EnrichWorker struct {
	river.WorkerDefaults[EnrichJobArgs]
	Handler func(ctx context.Context, job *river.Job[EnrichJobArgs]) error
}

func (w *EnrichWorker) Work(ctx context.Context, job *river.Job[EnrichJobArgs]) error {
	if w.Handler != nil {
		return w.Handler(ctx, job)
	}
	return ErrNoHandler
}

// PolicyWorker processes risk scoring and SLA evaluations via River.
type PolicyWorker struct {
	river.WorkerDefaults[PolicyJobArgs]
	Handler func(ctx context.Context, job *river.Job[PolicyJobArgs]) error
}

func (w *PolicyWorker) Work(ctx context.Context, job *river.Job[PolicyJobArgs]) error {
	if w.Handler != nil {
		return w.Handler(ctx, job)
	}
	return ErrNoHandler
}

// NotifyWorker processes downstream alert and ticketing notifications via River.
type NotifyWorker struct {
	river.WorkerDefaults[NotifyJobArgs]
	Handler func(ctx context.Context, job *river.Job[NotifyJobArgs]) error
}

func (w *NotifyWorker) Work(ctx context.Context, job *river.Job[NotifyJobArgs]) error {
	if w.Handler != nil {
		return w.Handler(ctx, job)
	}
	return ErrNoHandler
}
