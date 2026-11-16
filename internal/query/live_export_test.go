package query

import (
	"github.com/google/uuid"
	"rampart/internal/domain"
)

// LiveHubSubscribe subscribes a test to the hub's rows for one tenant.
func LiveHubSubscribe(h *LiveHub, tenant uuid.UUID) <-chan []domain.LiveEvent {
	sub, err := h.subscribe(tenant, "test|"+tenant.String())
	if err != nil {
		panic(err)
	}
	return sub.ch
}

// LiveHubCursor returns the hub's cursor.
func LiveHubCursor(h *LiveHub) int64 { return h.cursor }
