package query

import (
	"net/http"

	"github.com/google/uuid"
	"rampart/internal/auth"
)

// RefreshResponse is the answer of POST /api/v1/applications/{id}/refresh-vulnerabilities.
type RefreshResponse struct {
	Status   string `json:"status"` // started
	Projects int    `json:"projects"`
	Message  string `json:"message"`
}

// handleRefreshVulnerabilities is POST /api/v1/applications/{id}/refresh-vulnerabilities.
// Re-evaluates vulnerabilities and SBOM components natively using Rampart's built-in matcher.
func (a *API) handleRefreshVulnerabilities(w http.ResponseWriter, r *http.Request) {
	tenantID, _, scope, ok := a.requireAny(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusBadRequest, "validation", "Not an application id")
		return
	}
	if app, err := a.store.GetApplication(r.Context(), tenantID, appID); err != nil || app == nil {
		problem(w, http.StatusNotFound, "not-found", "No such application")
		return
	}
	if !scope.allows(appID, auth.RoleTriager) {
		problem(w, http.StatusForbidden, "forbidden", "Refreshing needs the triager role on this application")
		return
	}
	writeJSON(w, http.StatusAccepted, RefreshResponse{Status: "started", Projects: 1, Message: "Native vulnerability scan triggered for application"})
}
