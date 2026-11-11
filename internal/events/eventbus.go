package events

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Handler processes an asynchronous event payload.
type Handler func(ctx context.Context, payload []byte) error

// EventBus defines the event publishing and subscription contract (ADR 0002).
type EventBus interface {
	Publish(ctx context.Context, topic string, payload any) error
	Subscribe(topic string, handler Handler) error
}

// MemoryEventBus provides a thread-safe, in-process EventBus implementation.
type MemoryEventBus struct {
	mu          sync.RWMutex
	subscribers map[string][]Handler
}

// NewMemoryEventBus creates a new in-process event bus.
func NewMemoryEventBus() *MemoryEventBus {
	return &MemoryEventBus{
		subscribers: make(map[string][]Handler),
	}
}

// Publish serializes and broadcasts an event to all topic subscribers.
func (b *MemoryEventBus) Publish(ctx context.Context, topic string, payload any) error {
	var data []byte
	switch p := payload.(type) {
	case []byte:
		data = p
	case string:
		data = []byte(p)
	default:
		marshaled, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("events: failed to marshal payload for %q: %w", topic, err)
		}
		data = marshaled
	}

	b.mu.RLock()
	handlers := append([]Handler(nil), b.subscribers[topic]...)
	b.mu.RUnlock()

	for _, h := range handlers {
		if err := h(ctx, data); err != nil {
			// In event bus, log/accumulate errors without halting other handlers
			return fmt.Errorf("events: handler failed for %q: %w", topic, err)
		}
	}
	return nil
}

// Subscribe adds a handler for the given topic.
func (b *MemoryEventBus) Subscribe(topic string, handler Handler) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[topic] = append(b.subscribers[topic], handler)
	return nil
}
