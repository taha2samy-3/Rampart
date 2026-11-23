package query

import (
	"net/http"

	"github.com/google/uuid"

	"rampart/internal/auth"
	"rampart/internal/domain"
)

// ApplicationScanSourcesResponse represents the response payload for GET /api/v1/applications/{id}/sources.
type ApplicationScanSourcesResponse struct {
	Sources []domain.ApplicationScanSource `json:"sources"`
	Total   int                            `json:"total"`
}

// handleApplicationSources returns all live ScanSources bound to the specified Application (D140).
func (a *API) handleApplicationSources(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}

	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Application not found")
		return
	}

	app, err := a.store.GetApplication(r.Context(), tenantID, appID)
	if err != nil || app == nil {
		problem(w, http.StatusNotFound, "not-found", "Application not found")
		return
	}

	sources, err := a.store.GetApplicationScanSources(r.Context(), tenantID, appID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "storage-error", "Failed to retrieve scan sources")
		return
	}
	if sources == nil {
		sources = []domain.ApplicationScanSource{}
	}

	writeJSON(w, http.StatusOK, ApplicationScanSourcesResponse{
		Sources: sources,
		Total:   len(sources),
	})
}
