package jobs

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// ParseJobArgs encapsulates the parameters for a parse worker (D2, ADR 0002).
type ParseJobArgs struct {
	IngestRunID uuid.UUID `json:"ingest_run_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
}

// Kind returns the job queue identifier for River.
func (ParseJobArgs) Kind() string {
	return "parse"
}

// EnrichJobArgs encapsulates parameters for the enrichment worker.
type EnrichJobArgs struct {
	IngestRunID uuid.UUID `json:"ingest_run_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
}

// Kind returns the job queue identifier for River.
func (EnrichJobArgs) Kind() string {
	return "enrich"
}

// PolicyJobArgs encapsulates parameters for the policy/scoring worker.
type PolicyJobArgs struct {
	IngestRunID uuid.UUID `json:"ingest_run_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
}

// Kind returns the job queue identifier for River.
func (PolicyJobArgs) Kind() string {
	return "policy"
}

// NotifyJobArgs encapsulates parameters for downstream ticketing/notification.
type NotifyJobArgs struct {
	IngestRunID uuid.UUID `json:"ingest_run_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
}

// Kind returns the job queue identifier for River.
func (NotifyJobArgs) Kind() string {
	return "notify"
}

// JobQueue defines the interface for enqueueing pipeline work.
type JobQueue interface {
	EnqueueParse(ctx context.Context, args ParseJobArgs) error
	EnqueueEnrich(ctx context.Context, args EnrichJobArgs) error
	EnqueuePolicy(ctx context.Context, args PolicyJobArgs) error
	EnqueueNotify(ctx context.Context, args NotifyJobArgs) error
}

// InMemJobQueue provides an in-memory dispatcher for tests and monolithic standalone mode.
type InMemJobQueue struct {
	ParseJobs  chan ParseJobArgs
	EnrichJobs chan EnrichJobArgs
	PolicyJobs chan PolicyJobArgs
	NotifyJobs chan NotifyJobArgs
}

// NewInMemJobQueue initializes buffered channels for pipeline jobs.
func NewInMemJobQueue() *InMemJobQueue {
	return &InMemJobQueue{
		ParseJobs:  make(chan ParseJobArgs, 1000),
		EnrichJobs: make(chan EnrichJobArgs, 1000),
		PolicyJobs: make(chan PolicyJobArgs, 1000),
		NotifyJobs: make(chan NotifyJobArgs, 1000),
	}
}

func (q *InMemJobQueue) EnqueueParse(ctx context.Context, args ParseJobArgs) error {
	select {
	case q.ParseJobs <- args:
		return nil
	default:
		return fmt.Errorf("jobs: parse queue is full")
	}
}

func (q *InMemJobQueue) EnqueueEnrich(ctx context.Context, args EnrichJobArgs) error {
	select {
	case q.EnrichJobs <- args:
		return nil
	default:
		return fmt.Errorf("jobs: enrich queue is full")
	}
}

func (q *InMemJobQueue) EnqueuePolicy(ctx context.Context, args PolicyJobArgs) error {
	select {
	case q.PolicyJobs <- args:
		return nil
	default:
		return fmt.Errorf("jobs: policy queue is full")
	}
}

func (q *InMemJobQueue) EnqueueNotify(ctx context.Context, args NotifyJobArgs) error {
	select {
	case q.NotifyJobs <- args:
		return nil
	default:
		return fmt.Errorf("jobs: notify queue is full")
	}
}
