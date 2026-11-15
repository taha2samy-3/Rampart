package query

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// handleListUnmappedDTrackProjects handles GET /api/v1/dtrack/unmapped (docs/10 §3, §13).
func (a *API) handleListUnmappedDTrackProjects(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}

	var sourceID uuid.UUID
	if sIDStr := r.URL.Query().Get("source_id"); sIDStr != "" {
		parsed, err := uuid.Parse(sIDStr)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_parameter", "Invalid source_id parameter")
			return
		}
		sourceID = parsed
	}

	projects, err := a.store.ListUnmappedDTrackProjects(r.Context(), tenantID, sourceID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal_error", "Failed to list unmapped Dependency-Track projects")
		return
	}
	if projects == nil {
		projects = []domain.DTrackProjectRecord{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"projects": projects,
		"count":    len(projects),
	})
}

// MapProjectRequest payload for POST /api/v1/dtrack/projects/{uuid}/map
type MapProjectRequest struct {
	ApplicationID uuid.UUID `json:"application_id"`
}

// handleMapDTrackProject handles POST /api/v1/dtrack/projects/{uuid}/map (docs/10 §3, §13).
func (a *API) handleMapDTrackProject(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleMaintainer)
	if !ok {
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		problem(w, http.StatusBadRequest, "invalid_path", "Missing project UUID in path")
		return
	}
	projectUUID := parts[len(parts)-2]
	if projectUUID == "" {
		problem(w, http.StatusBadRequest, "invalid_path", "Missing project UUID in path")
		return
	}

	var req MapProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ApplicationID == uuid.Nil {
		problem(w, http.StatusBadRequest, "invalid_payload", "Valid application_id is required")
		return
	}

	if err := a.store.MapDTrackProject(r.Context(), tenantID, projectUUID, req.ApplicationID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problem(w, http.StatusNotFound, "not_found", "Dependency-Track project not found")
			return
		}
		problem(w, http.StatusInternalServerError, "internal_error", "Failed to map Dependency-Track project")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":         "mapped",
		"project_uuid":   projectUUID,
		"application_id": req.ApplicationID,
	})
}
