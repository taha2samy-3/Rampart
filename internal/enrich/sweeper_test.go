package enrich_test

import (
	"context"
	"testing"

	"rampart/internal/enrich"
	"rampart/internal/jobs"
)

type mockAdvisoryEnqueuer struct {
	enqueued []jobs.AdvisoryRefreshArgs
}

func (m *mockAdvisoryEnqueuer) EnqueueAdvisoryRefresh(ctx context.Context, args jobs.AdvisoryRefreshArgs, priority int) error {
	m.enqueued = append(m.enqueued, args)
	return nil
}

func TestAdvisorySweeper_NilPool(t *testing.T) {
	ctx := context.Background()
	mock := &mockAdvisoryEnqueuer{}
	sweeper := enrich.NewAdvisorySweeper(nil, mock, nil)

	n, err := sweeper.Sweep(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 enqueued with nil pool, got %d", n)
	}
}
