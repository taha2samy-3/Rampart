package jobs_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/jobs"
)

func TestInMemJobQueue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	q := jobs.NewInMemJobQueue()
	runID := uuid.New()
	tenantID := uuid.New()

	// Parse
	parseArgs := jobs.ParseJobArgs{IngestRunID: runID, TenantID: tenantID}
	if parseArgs.Kind() != "parse" {
		t.Errorf("expected kind 'parse', got %q", parseArgs.Kind())
	}
	if err := q.EnqueueParse(ctx, parseArgs); err != nil {
		t.Fatalf("EnqueueParse failed: %v", err)
	}
	select {
	case item := <-q.ParseJobs:
		if item.IngestRunID != runID {
			t.Errorf("got run ID %s, want %s", item.IngestRunID, runID)
		}
	default:
		t.Fatal("expected item in ParseJobs channel")
	}
}
