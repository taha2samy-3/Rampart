package query

import (
	"net/http"
	"strconv"

	"rampart/internal/store"
)

const (
	inventoryAssetLimit     = 1000
	inventoryComponentLimit = 500
	inventoryComponentMax   = 2000
)

// handleInventoryAssets is GET /api/v1/inventory: the scanned targets of the tenant with their open findings.
// The inventory page asked for it and got 404, so an uploaded and parsed SBOM never showed.
func (a *API) handleInventoryAssets(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	rd, ok := a.store.(store.InventoryReader)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "The inventory needs PostgreSQL")
		return
	}
	assets, err := rd.ListInventoryAssets(r.Context(), tenantID, inventoryAssetLimit)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the inventory")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": assets})
}

// handleInventoryComponents is GET /api/v1/inventory/components?q=&limit=: the packages of the latest SBOM of every
// asset. total is the number that match q, which is more than components when the page is cut by limit.
func (a *API) handleInventoryComponents(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	rd, ok := a.store.(store.InventoryReader)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "The inventory needs PostgreSQL")
		return
	}
	limit := inventoryComponentLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > inventoryComponentMax {
			problem(w, http.StatusBadRequest, "validation", "limit must be between 1 and "+strconv.Itoa(inventoryComponentMax))
			return
		}
		limit = n
	}
	q := r.URL.Query().Get("q")
	if len(q) > 200 {
		problem(w, http.StatusBadRequest, "validation", "q is longer than 200 characters")
		return
	}
	components, total, err := rd.ListInventoryComponents(r.Context(), tenantID, q, limit)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the packages")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"components": components, "total": total, "truncated": total > len(components)})
}
