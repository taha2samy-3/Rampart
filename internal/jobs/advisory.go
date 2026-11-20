package jobs

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
)

// AdvisoryRefreshArgs is the work unit for refreshing a vulnerability's narrative advisory,
// CVSS metrics, CWEs, and exploitation status from upstream threat intelligence providers.
type AdvisoryRefreshArgs struct {
	VulnerabilityID string `json:"vulnerability_id"`
	Reason          string `json:"reason"` // "pending_scoring", "stale_cache", "manual_request"
	Force           bool   `json:"force"`
}

// Kind returns the job kind for River.
func (AdvisoryRefreshArgs) Kind() string { return "advisory_refresh" }

const (
	// AdvisoryQueue is the dedicated River queue for advisory synchronizations and live lookups.
	// Bounded with its own MaxWorkers so it never starves ingest or analysis workers.
	AdvisoryQueue = "advisory"

	// AdvisoryMaxAttempts is River's retry budget for advisory synchronizations.
	AdvisoryMaxAttempts = 5

	// AdvisoryJobTimeout bounds one attempt against upstream NIST NVD and OSV endpoints.
	AdvisoryJobTimeout = 5 * time.Minute
)

// AdvisoryRefreshHandler processes one advisory refresh job.
type AdvisoryRefreshHandler func(ctx context.Context, args AdvisoryRefreshArgs, attempt, maxAttempts int) error

// AdvisoryRefreshWorker executes advisory_refresh jobs via River.
type AdvisoryRefreshWorker struct {
	river.WorkerDefaults[AdvisoryRefreshArgs]
	Handle AdvisoryRefreshHandler
}

// Work implements river.Worker.
func (w *AdvisoryRefreshWorker) Work(ctx context.Context, job *river.Job[AdvisoryRefreshArgs]) error {
	if w.Handle == nil {
		return ErrNoHandler
	}
	attempt := 1
	maxAttempts := AdvisoryMaxAttempts
	if job.JobRow != nil {
		attempt = job.Attempt
		maxAttempts = job.MaxAttempts
	}
	err := w.Handle(ctx, job.Args, attempt, maxAttempts)
	if IsPermanent(err) {
		return river.JobCancel(err)
	}
	return err
}

// Timeout bounds one attempt.
func (w *AdvisoryRefreshWorker) Timeout(*river.Job[AdvisoryRefreshArgs]) time.Duration {
	return AdvisoryJobTimeout
}

// EnqueueAdvisoryRefresh inserts an advisory refresh job into River with deduplication.
func (q *RiverQueue) EnqueueAdvisoryRefresh(ctx context.Context, args AdvisoryRefreshArgs, priority int) error {
	opts := &river.InsertOpts{
		Queue:       AdvisoryQueue,
		MaxAttempts: AdvisoryMaxAttempts,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
		},
	}
	if priority > 0 {
		opts.Priority = priority
	}
	_, err := q.client.Insert(ctx, args, opts)
	return err
}

// EnqueueAdvisoryRefreshTx inserts an advisory refresh job inside an ongoing database transaction.
func (q *RiverQueue) EnqueueAdvisoryRefreshTx(ctx context.Context, tx pgx.Tx, args AdvisoryRefreshArgs, priority int) error {
	opts := &river.InsertOpts{
		Queue:       AdvisoryQueue,
		MaxAttempts: AdvisoryMaxAttempts,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
		},
	}
	if priority > 0 {
		opts.Priority = priority
	}
	_, err := q.client.InsertTx(ctx, tx, args, opts)
	return err
}
