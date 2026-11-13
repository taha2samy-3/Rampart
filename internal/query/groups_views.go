package query

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/query/grammar"
	"rampart/internal/store"
)

// --- Saved Views Handlers (docs/21 §6.2) ---

type createViewRequest struct {
	Name  string `json:"name"`
	Query string `json:"query"`
	Sort  string `json:"sort,omitempty"`
	Scope string `json:"scope,omitempty"` // tenant | user
}

func (a *API) handleListViews(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		writeJSONProblem(w, http.StatusUnauthorized, "https://rampart.aspm.dev/problems/unauthorized", "Authentication required")
		return
	}

	owner := a.callerEmail(r)
	views, err := a.store.ListSavedViews(r.Context(), tenantID, owner)
	if err != nil {
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", err.Error())
		return
	}
	if views == nil {
		views = []domain.SavedView{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"views": views})
}

func (a *API) handleCreateView(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		writeJSONProblem(w, http.StatusUnauthorized, "https://rampart.aspm.dev/problems/unauthorized", "Authentication required")
		return
	}

	var req createViewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/bad-request", "Invalid request payload")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Query = strings.TrimSpace(req.Query)
	if req.Name == "" || req.Query == "" {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/validation", "Name and query are required")
		return
	}
	if len([]rune(req.Name)) > 255 {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/validation", "View name cannot exceed 255 characters")
		return
	}

	// Validate query syntax through the grammar (D59)
	if _, err := grammar.Parse(req.Query); err != nil {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/validation", fmt.Sprintf("Invalid query grammar: %v", err))
		return
	}

	scope := req.Scope
	if scope != "user" {
		scope = "tenant"
	}

	view := &domain.SavedView{
		ID:       uuid.New(),
		TenantID: tenantID,
		Owner:    a.callerEmail(r),
		Name:     req.Name,
		Query:    req.Query,
		Sort:     req.Sort,
		Scope:    scope,
	}

	if err := a.store.CreateSavedView(r.Context(), view); err != nil {
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(view)
}

func (a *API) handleDeleteView(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		writeJSONProblem(w, http.StatusUnauthorized, "https://rampart.aspm.dev/problems/unauthorized", "Authentication required")
		return
	}

	idStr := r.PathValue("id")
	viewID, err := uuid.Parse(idStr)
	if err != nil {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/bad-request", "Invalid view ID")
		return
	}

	if err := a.store.DeleteSavedView(r.Context(), tenantID, viewID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSONProblem(w, http.StatusNotFound, "https://rampart.aspm.dev/problems/not-found", "Saved view not found")
			return
		}
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Finding Groups Handlers (docs/21 §6.1) ---

type createGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type groupMembersRequest struct {
	FindingIDs []uuid.UUID `json:"finding_ids"`
}

func (a *API) handleListGroups(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		writeJSONProblem(w, http.StatusUnauthorized, "https://rampart.aspm.dev/problems/unauthorized", "Authentication required")
		return
	}

	groups, err := a.store.ListFindingGroups(r.Context(), tenantID)
	if err != nil {
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", err.Error())
		return
	}
	if groups == nil {
		groups = []domain.FindingGroup{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"groups": groups})
}

func (a *API) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		writeJSONProblem(w, http.StatusUnauthorized, "https://rampart.aspm.dev/problems/unauthorized", "Authentication required")
		return
	}

	var req createGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/bad-request", "Invalid request payload")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/validation", "Group name is required")
		return
	}
	if len([]rune(req.Name)) > 255 {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/validation", "Group name cannot exceed 255 characters")
		return
	}

	grp := &domain.FindingGroup{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Owner:       a.callerEmail(r),
	}

	if err := a.store.CreateFindingGroup(r.Context(), grp); err != nil {
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(grp)
}

func (a *API) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		writeJSONProblem(w, http.StatusUnauthorized, "https://rampart.aspm.dev/problems/unauthorized", "Authentication required")
		return
	}

	idStr := r.PathValue("id")
	groupID, err := uuid.Parse(idStr)
	if err != nil {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/bad-request", "Invalid group ID")
		return
	}

	grp, err := a.store.GetFindingGroup(r.Context(), tenantID, groupID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSONProblem(w, http.StatusNotFound, "https://rampart.aspm.dev/problems/not-found", "Group not found")
		return
	}
	if err != nil {
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", err.Error())
		return
	}

	findings, _ := a.store.ListGroupFindings(r.Context(), tenantID, groupID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"group":        grp,
		"findings_ids": findings,
	})
}

func (a *API) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		writeJSONProblem(w, http.StatusUnauthorized, "https://rampart.aspm.dev/problems/unauthorized", "Authentication required")
		return
	}

	idStr := r.PathValue("id")
	groupID, err := uuid.Parse(idStr)
	if err != nil {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/bad-request", "Invalid group ID")
		return
	}

	if err := a.store.DeleteFindingGroup(r.Context(), tenantID, groupID); err != nil {
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleAddGroupMembers(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		writeJSONProblem(w, http.StatusUnauthorized, "https://rampart.aspm.dev/problems/unauthorized", "Authentication required")
		return
	}

	idStr := r.PathValue("id")
	groupID, err := uuid.Parse(idStr)
	if err != nil {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/bad-request", "Invalid group ID")
		return
	}

	var req groupMembersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.FindingIDs) == 0 {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/bad-request", "Invalid finding_ids array")
		return
	}

	if err := a.store.AddGroupMembers(r.Context(), tenantID, groupID, req.FindingIDs); err != nil {
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleRemoveGroupMembers(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		writeJSONProblem(w, http.StatusUnauthorized, "https://rampart.aspm.dev/problems/unauthorized", "Authentication required")
		return
	}

	idStr := r.PathValue("id")
	groupID, err := uuid.Parse(idStr)
	if err != nil {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/bad-request", "Invalid group ID")
		return
	}

	var req groupMembersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.FindingIDs) == 0 {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/bad-request", "Invalid finding_ids array")
		return
	}

	if err := a.store.RemoveGroupMembers(r.Context(), tenantID, groupID, req.FindingIDs); err != nil {
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func writeJSONProblem(w http.ResponseWriter, status int, probType, title string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   probType,
		"title":  title,
		"status": status,
	})
}
