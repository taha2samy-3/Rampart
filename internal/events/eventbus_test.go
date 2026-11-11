package events_test

import (
	"context"
	"sync/atomic"
	"testing"

	"rampart/internal/events"
)

func TestMemoryEventBus(t *testing.T) {
	bus := events.NewMemoryEventBus()
	ctx := context.Background()

	var count atomic.Int32

	err := bus.Subscribe("finding.created", func(ctx context.Context, payload []byte) error {
		count.Add(1)
		return nil
	})
	if err != nil {
		t.Fatalf("subscription failed: %v", err)
	}

	payload := map[string]string{"id": "finding-123"}
	if err := bus.Publish(ctx, "finding.created", payload); err != nil {
		t.Fatalf("publish failed: %v", err)
	}

	if count.Load() != 1 {
		t.Errorf("expected 1 event handled, got %d", count.Load())
	}
}
