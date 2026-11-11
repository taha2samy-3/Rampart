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

	// Enrich
	enrichArgs := jobs.EnrichJobArgs{IngestRunID: runID, TenantID: tenantID}
	if enrichArgs.Kind() != "enrich" {
		t.Errorf("expected kind 'enrich', got %q", enrichArgs.Kind())
	}
	if err := q.EnqueueEnrich(ctx, enrichArgs); err != nil {
		t.Fatalf("EnqueueEnrich failed: %v", err)
	}

	// Policy
	policyArgs := jobs.PolicyJobArgs{IngestRunID: runID, TenantID: tenantID}
	if policyArgs.Kind() != "policy" {
		t.Errorf("expected kind 'policy', got %q", policyArgs.Kind())
	}
	if err := q.EnqueuePolicy(ctx, policyArgs); err != nil {
		t.Fatalf("EnqueuePolicy failed: %v", err)
	}

	// Notify
	notifyArgs := jobs.NotifyJobArgs{IngestRunID: runID, TenantID: tenantID}
	if notifyArgs.Kind() != "notify" {
		t.Errorf("expected kind 'notify', got %q", notifyArgs.Kind())
	}
	if err := q.EnqueueNotify(ctx, notifyArgs); err != nil {
		t.Fatalf("EnqueueNotify failed: %v", err)
	}
}
