package query

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// Sources pulled from upstream tools (doc 11 `GET /sources/{id}/unmapped`, `POST /sources/{id}/map`; docs/23 DT6;
// docs/16 D92). The routes name the source, so a second Dependency-Track instance, or another upstream later, uses
// the same API.

// DTrackEnqueuer schedules a project sync after a mapping, so a mapped project is read without waiting for the
// next portfolio sync.
type DTrackEnqueuer interface {
	EnqueueDTrackProject(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string, delay time.Duration) error
}

// SetDTrackEnqueuer attaches the dtrack-sync queue.
func (a *API) SetDTrackEnqueuer(e DTrackEnqueuer) { a.dtEnqueue = e }

type sourceStatusLister interface {
	ListTenantDTrackSources(ctx context.Context, tenantID uuid.UUID) ([]store.DTrackSourceStatus, error)
}

type decisionLister interface {
	ListDTrackDecisions(ctx context.Context, tenantID, sourceID uuid.UUID, pendingOnly bool) ([]store.DTrackDecision, error)
}

// handleListSources answers GET /api/v1/sources: the tenant's upstream sources and their real state.
func (a *API) handleListSources(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	out := []store.DTrackSourceStatus{}
	if l, ok := a.store.(sourceStatusLister); ok {
		list, err := l.ListTenantDTrackSources(r.Context(), tenantID)
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "Listing the sources failed")
			return
		}
		if list != nil {
			out = list
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"sources": out})
}

func pathSource(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", "Invalid source id")
		return uuid.Nil, false
	}
	return id, true
}

// handleListUnmapped answers GET /api/v1/sources/{id}/unmapped (docs/10 §3).
func (a *API) handleListUnmapped(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	sourceID, ok := pathSource(w, r)
	if !ok {
		return
	}
	projects, err := a.store.ListUnmappedDTrackProjects(r.Context(), tenantID, sourceID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Listing the unmapped projects failed")
		return
	}
	if projects == nil {
		projects = []domain.DTrackProjectRecord{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"projects": projects, "count": len(projects)})
}

// MapProjectRequest is the body of POST /api/v1/sources/{id}/map.
type MapProjectRequest struct {
	ProjectUUID   string    `json:"project_uuid"`
	ApplicationID uuid.UUID `json:"application_id"`
}

// handleMapProject answers POST /api/v1/sources/{id}/map: a person maps an unmapped project to an application.
// It needs maintainer on that application (D48). The mapping survives later syncs, and the project is synced now.
func (a *API) handleMapProject(w http.ResponseWriter, r *http.Request) {
	tenantID, _, scope, ok := a.requireAny(w, r, auth.RoleMaintainer)
	if !ok {
		return
	}
	sourceID, ok := pathSource(w, r)
	if !ok {
		return
	}
	var req MapProjectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil || req.ApplicationID == uuid.Nil || strings.TrimSpace(req.ProjectUUID) == "" {
		problem(w, http.StatusBadRequest, "bad-request", "project_uuid and application_id are required")
		return
	}
	if !scope.allows(req.ApplicationID, auth.RoleMaintainer) {
		problem(w, http.StatusForbidden, "forbidden", "Mapping a project to this application needs maintainer on it")
		return
	}
	if app, err := a.store.GetApplication(r.Context(), tenantID, req.ApplicationID); err != nil || app == nil {
		problem(w, http.StatusUnprocessableEntity, "validation", "No such application")
		return
	}
	unmapped, err := a.store.ListUnmappedDTrackProjects(r.Context(), tenantID, sourceID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Reading the source's projects failed")
		return
	}
	found := false
	for _, p := range unmapped {
		found = found || p.ProjectUUID == req.ProjectUUID
	}
	if !found {
		problem(w, http.StatusNotFound, "not-found", "No unmapped project with that id on this source")
		return
	}
	if err := a.store.MapDTrackProject(r.Context(), tenantID, req.ProjectUUID, req.ApplicationID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problem(w, http.StatusNotFound, "not-found", "No unmapped project with that id on this source")
			return
		}
		problem(w, http.StatusInternalServerError, "internal", "Mapping the project failed")
		return
	}
	syncing := false
	if a.dtEnqueue != nil {
		if ok, err := a.store.EnqueueDTrackSync(r.Context(), tenantID, sourceID, req.ProjectUUID); err == nil {
			syncing = true
			if ok {
				syncing = a.dtEnqueue.EnqueueDTrackProject(r.Context(), tenantID, sourceID, req.ProjectUUID, 0) == nil
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "mapped", "project_uuid": req.ProjectUUID, "application_id": req.ApplicationID, "sync_queued": syncing,
	})
}

// handleListDecisions answers GET /api/v1/sources/{id}/decisions: what Dependency-Track decided about findings,
// pending ones first (docs/23 DT5). ?pending=false lists the applied ones too.
func (a *API) handleListDecisions(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	sourceID, ok := pathSource(w, r)
	if !ok {
		return
	}
	out := []store.DTrackDecision{}
	if l, ok := a.store.(decisionLister); ok {
		list, err := l.ListDTrackDecisions(r.Context(), tenantID, sourceID, r.URL.Query().Get("pending") != "false")
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "Listing the decisions failed")
			return
		}
		if list != nil {
			out = list
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"decisions": out})
}
