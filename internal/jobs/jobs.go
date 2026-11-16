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

// JobQueue defines the interface for enqueueing pipeline work.
type JobQueue interface {
	EnqueueParse(ctx context.Context, args ParseJobArgs) error
}

// InMemJobQueue provides an in-memory dispatcher for tests and monolithic standalone mode.
type InMemJobQueue struct {
	ParseJobs chan ParseJobArgs
}

// NewInMemJobQueue initializes buffered channels for pipeline jobs.
func NewInMemJobQueue() *InMemJobQueue {
	return &InMemJobQueue{
		ParseJobs: make(chan ParseJobArgs, 1000),
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
