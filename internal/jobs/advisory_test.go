package jobs_test

import (
	"context"
	"errors"
	"testing"

	"github.com/riverqueue/river"
	"rampart/internal/jobs"
)

func TestAdvisoryRefreshArgs(t *testing.T) {
	args := jobs.AdvisoryRefreshArgs{
		VulnerabilityID: "CVE-2026-2359",
		Reason:          "pending_scoring",
		Force:           true,
	}
	if args.Kind() != "advisory_refresh" {
		t.Fatalf("expected kind 'advisory_refresh', got %q", args.Kind())
	}
}

func TestAdvisoryRefreshWorker_Execution(t *testing.T) {
	ctx := context.Background()
	called := false
	w := &jobs.AdvisoryRefreshWorker{
		Handle: func(ctx context.Context, args jobs.AdvisoryRefreshArgs, attempt, maxAttempts int) error {
			called = true
			if args.VulnerabilityID != "CVE-2026-2359" {
				t.Errorf("expected vuln ID CVE-2026-2359, got %s", args.VulnerabilityID)
			}
			return nil
		},
	}

	job := &river.Job[jobs.AdvisoryRefreshArgs]{
		Args: jobs.AdvisoryRefreshArgs{VulnerabilityID: "CVE-2026-2359"},
	}

	if err := w.Work(ctx, job); err != nil {
		t.Fatalf("Work returned error: %v", err)
	}
	if !called {
		t.Fatal("worker handler was not called")
	}
}

func TestAdvisoryRefreshWorker_NoHandler(t *testing.T) {
	ctx := context.Background()
	w := &jobs.AdvisoryRefreshWorker{}
	job := &river.Job[jobs.AdvisoryRefreshArgs]{
		Args: jobs.AdvisoryRefreshArgs{VulnerabilityID: "CVE-2026-2359"},
	}
	if err := w.Work(ctx, job); !errors.Is(err, jobs.ErrNoHandler) {
		t.Fatalf("expected ErrNoHandler, got %v", err)
	}
}
