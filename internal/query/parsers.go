package query

import (
	"encoding/json"
	"net/http"

	"rampart/internal/integrations"
)

// handleListParsers returns all registered Tier 1 and Tier 2 parsers (docs/19 §2, docs/13 §9).
func (a *API) handleListParsers(w http.ResponseWriter, r *http.Request) {
	if _, err := a.resolveTenant(r); err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	reg := integrations.DefaultRegistry()
	parsers := reg.ListParsers()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"parsers": parsers,
		"total":   len(parsers),
	})
}
