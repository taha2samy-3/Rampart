package scoring

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// flagStore is the part of the store a recompute reads: the tenants whose policy changed, and their findings.
type flagStore struct {
	store.Store
	mu      sync.Mutex
	flagged []uuid.UUID
	cleared []uuid.UUID
	listErr error
}

func (f *flagStore) TenantsNeedingSLARecompute(context.Context) ([]uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uuid.UUID(nil), f.flagged...), nil
}
func (f *flagStore) ClearSLARecompute(_ context.Context, t uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleared = append(f.cleared, t)
	f.flagged = nil
	return nil
}
func (f *flagStore) ListActiveFindings(context.Context, uuid.UUID, uuid.UUID, int) ([]*domain.Finding, error) {
	return nil, f.listErr
}
func (f *flagStore) ListTenantIDs(context.Context) ([]uuid.UUID, error) { return nil, nil }
func (f *flagStore) clearedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cleared)
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRecomputeChanged(t *testing.T) {
	a, b := domain.NewID(), domain.NewID()
	st := &flagStore{flagged: []uuid.UUID{a, b}}
	if n := RecomputeChanged(context.Background(), New(st, nil, nil), st, quiet()); n != 2 || len(st.cleared) != 2 {
		t.Fatalf("both flagged tenants are recomputed and cleared: n=%d cleared=%v", n, st.cleared)
	}
	// A recompute that failed must keep its flag, so the next check tries again instead of losing the change.
	st = &flagStore{flagged: []uuid.UUID{a}, listErr: errors.New("db down")}
	if n := RecomputeChanged(context.Background(), New(st, nil, nil), st, quiet()); n != 0 || len(st.cleared) != 0 {
		t.Fatalf("a failed recompute must not clear its flag: n=%d cleared=%v", n, st.cleared)
	}
}

// A RiskPolicy or SLAPolicy change waited for the breach sweep, 15 minutes by default, and for that time the list
// was sorted by the old scores while the inspector explained the new ones. The flag is now looked for on its own,
// short, interval, whatever the sweep interval is.
func TestRunSweeper_RecomputesAfterAPolicyChangeWithoutWaitingForTheSweep(t *testing.T) {
	old := recomputeCheckEvery
	recomputeCheckEvery = 10 * time.Millisecond
	defer func() { recomputeCheckEvery = old }()

	st := &flagStore{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunSweeper(ctx, New(st, nil, nil), st, nil, time.Hour, quiet()) // the sweep itself is an hour away
		close(done)
	}()
	time.Sleep(30 * time.Millisecond) // the first sweep has run; the policy changes after it
	st.mu.Lock()
	st.flagged = []uuid.UUID{domain.NewID()}
	st.mu.Unlock()

	deadline := time.Now().Add(3 * time.Second)
	for st.clearedCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if st.clearedCount() != 1 {
		t.Fatal("the policy change was not recomputed within 3 seconds, with a sweep interval of an hour")
	}
}
