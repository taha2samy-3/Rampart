package query

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
)

type mappedProjectLister interface {
	ListMappedDTrackProjects(ctx context.Context, tenantID, sourceID uuid.UUID) ([]domain.DTrackProjectRecord, error)
}

// RefreshResponse is the answer of POST /api/v1/applications/{id}/refresh-vulnerabilities.
type RefreshResponse struct {
	Status   string `json:"status"` // started
	Projects int    `json:"projects"`
	Message  string `json:"message"`
}

// handleRefreshVulnerabilities is POST /api/v1/applications/{id}/refresh-vulnerabilities (D126). Matching an SBOM to
// vulnerabilities is Dependency-Track's work and is done per project, so "scan this application" is: sync, now, each
// Dependency-Track project mapped to it. The sync is queued, like the one a webhook or a manual mapping starts, and
// pulls what Dependency-Track has already analysed; it does not ask Dependency-Track to re-analyse (that needs a
// client call this version does not make).
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
	lister, ok := a.store.(mappedProjectLister)
	if !ok || a.dtEnqueue == nil {
		problem(w, http.StatusNotImplemented, "unsupported", "Dependency-Track is not connected to this server")
		return
	}
	projects, err := lister.ListMappedDTrackProjects(r.Context(), tenantID, uuid.Nil)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "The Dependency-Track projects could not be listed")
		return
	}
	n := 0
	for _, p := range projects {
		if p.ApplicationID == nil || *p.ApplicationID != appID {
			continue
		}
		if err := a.dtEnqueue.EnqueueDTrackProject(r.Context(), tenantID, p.SourceID, p.ProjectUUID, 0); err != nil {
			problem(w, http.StatusInternalServerError, "internal", "A sync could not be queued: "+err.Error())
			return
		}
		n++
	}
	if n == 0 {
		problem(w, http.StatusConflict, "conflict", "No Dependency-Track project is mapped to this application, so there is nothing to refresh")
		return
	}
	writeJSON(w, http.StatusAccepted, RefreshResponse{Status: "started", Projects: n, Message: "Pulling the vulnerabilities of its Dependency-Track projects"})
}
