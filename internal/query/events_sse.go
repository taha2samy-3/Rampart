package query

import (
	"fmt"
	"net/http"
	"time"
)

// handleEventsSSE streams Server-Sent Events to the client for live UI reactivity (docs/21 §6.4).
func (a *API) handleEventsSSE(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		writeJSONProblem(w, http.StatusUnauthorized, "https://rampart.aspm.dev/problems/unauthorized", "Authentication required")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", "Streaming unsupported by client/proxy")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Emit initial connection established event
	_, _ = fmt.Fprintf(w, "event: connected\ndata: {\"tenant_id\":\"%s\"}\n\n", tenantID)
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Heartbeat loop until client disconnects
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			// 15-second heartbeat comment per docs/21 §6.4
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
