package query

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"rampart/internal/auth"
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

// --- Finding Groups Handlers (docs/21 §6.1; docs/16 D90) ---
//
// Who may do what (docs/07, docs/23 C8):
//   - read: viewer;
//   - create or delete: maintainer on the group's application, or admin for a tenant-wide group (no application);
//   - add a finding: triager on that finding's application, and the finding must belong to the group's application;
//   - remove a finding: triager on its application (a finding that is gone needs the group's own role);
//   - open the group's ticket: maintainer on every application in the group.

type createGroupRequest struct {
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	ApplicationID *uuid.UUID `json:"application_id,omitempty"`
}

type groupMembersRequest struct {
	FindingIDs []uuid.UUID `json:"finding_ids"`
}

// maxGroupMembersPerCall bounds one add or remove call, so a request cannot make the server read without limit.
const maxGroupMembersPerCall = 500

// groupRole is the role the group's own scope needs: on its application, or on the tenant when it has none.
func groupAllows(scope roleScope, g *domain.FindingGroup, min auth.Role) bool {
	if g.ApplicationID == nil {
		if min.Rank() < auth.RoleAdmin.Rank() {
			min = auth.RoleAdmin
		}
		return scope.tenant.Rank() >= min.Rank()
	}
	return scope.allows(*g.ApplicationID, min)
}

func (a *API) handleListGroups(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	groups, err := a.store.ListFindingGroups(r.Context(), tenantID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Listing the groups failed")
		return
	}
	if groups == nil {
		groups = []domain.FindingGroup{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"groups": groups})
}

func (a *API) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, user, scope, ok := a.requireAny(w, r, auth.RoleMaintainer)
	if !ok {
		return
	}
	var req createGroupRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "bad-request", "Invalid request payload")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		problem(w, http.StatusBadRequest, "validation", "Group name is required")
		return
	}
	if len([]rune(req.Name)) > 255 {
		problem(w, http.StatusBadRequest, "validation", "Group name cannot exceed 255 characters")
		return
	}
	grp := &domain.FindingGroup{
		ID: uuid.New(), TenantID: tenantID, Name: req.Name, Description: req.Description,
		Owner: actorOf(user), ApplicationID: req.ApplicationID,
	}
	if !groupAllows(scope, grp, auth.RoleMaintainer) {
		if grp.ApplicationID == nil {
			problem(w, http.StatusForbidden, "forbidden", "A group with no application is tenant-wide and needs admin; give it an application_id")
		} else {
			problem(w, http.StatusForbidden, "forbidden", "Creating a group needs maintainer on its application")
		}
		return
	}
	if grp.ApplicationID != nil {
		if app, err := a.store.GetApplication(r.Context(), tenantID, *grp.ApplicationID); err != nil || app == nil {
			problem(w, http.StatusUnprocessableEntity, "validation", "No such application")
			return
		}
	}
	if err := a.store.CreateFindingGroup(r.Context(), grp); err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Creating the group failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(grp)
}

// loadGroup reads the group named in the path, answering 400 or 404 itself.
func (a *API) loadGroup(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (*domain.FindingGroup, bool) {
	groupID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", "Invalid group ID")
		return nil, false
	}
	grp, err := a.store.GetFindingGroup(r.Context(), tenantID, groupID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && grp == nil) {
		problem(w, http.StatusNotFound, "not-found", "Group not found")
		return nil, false
	}
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Reading the group failed")
		return nil, false
	}
	return grp, true
}

func (a *API) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	grp, ok := a.loadGroup(w, r, tenantID)
	if !ok {
		return
	}
	findings, err := a.store.ListGroupFindings(r.Context(), tenantID, grp.ID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Reading the group's findings failed")
		return
	}
	if findings == nil {
		findings = []uuid.UUID{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"group": grp, "finding_ids": findings})
}

func (a *API) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, _, scope, ok := a.requireAny(w, r, auth.RoleMaintainer)
	if !ok {
		return
	}
	grp, ok := a.loadGroup(w, r, tenantID)
	if !ok {
		return
	}
	if !groupAllows(scope, grp, auth.RoleMaintainer) {
		problem(w, http.StatusForbidden, "forbidden", "Deleting this group needs maintainer on its application (admin for a tenant-wide group)")
		return
	}
	if err := a.store.DeleteFindingGroup(r.Context(), tenantID, grp.ID); err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Deleting the group failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// readMembers decodes and de-duplicates the finding ids of an add or remove call.
func readMembers(w http.ResponseWriter, r *http.Request) ([]uuid.UUID, bool) {
	var req groupMembersRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || len(req.FindingIDs) == 0 {
		problem(w, http.StatusBadRequest, "bad-request", "Invalid finding_ids array")
		return nil, false
	}
	seen := map[uuid.UUID]bool{}
	var ids []uuid.UUID
	for _, id := range req.FindingIDs {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) > maxGroupMembersPerCall {
		problem(w, http.StatusBadRequest, "validation", fmt.Sprintf("At most %d findings per call", maxGroupMembersPerCall))
		return nil, false
	}
	return ids, true
}

func (a *API) handleAddGroupMembers(w http.ResponseWriter, r *http.Request) {
	tenantID, _, scope, ok := a.requireAny(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	grp, ok := a.loadGroup(w, r, tenantID)
	if !ok {
		return
	}
	ids, ok := readMembers(w, r)
	if !ok {
		return
	}
	for _, id := range ids {
		f, _, err := a.store.GetFinding(r.Context(), tenantID, id)
		if err != nil || f == nil {
			problem(w, http.StatusUnprocessableEntity, "validation", "No such finding: "+id.String())
			return
		}
		if grp.ApplicationID != nil && f.ApplicationID != *grp.ApplicationID {
			problem(w, http.StatusUnprocessableEntity, "validation", "Finding "+id.String()+" belongs to another application than the group")
			return
		}
		if !scope.allows(f.ApplicationID, auth.RoleTriager) {
			problem(w, http.StatusForbidden, "forbidden", "Adding finding "+id.String()+" needs triager on its application")
			return
		}
	}
	if err := a.store.AddGroupMembers(r.Context(), tenantID, grp.ID, ids); err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Adding the findings failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleRemoveGroupMembers(w http.ResponseWriter, r *http.Request) {
	tenantID, _, scope, ok := a.requireAny(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	grp, ok := a.loadGroup(w, r, tenantID)
	if !ok {
		return
	}
	ids, ok := readMembers(w, r)
	if !ok {
		return
	}
	for _, id := range ids {
		f, _, err := a.store.GetFinding(r.Context(), tenantID, id)
		allowed := false
		if err == nil && f != nil {
			allowed = scope.allows(f.ApplicationID, auth.RoleTriager)
		} else {
			allowed = groupAllows(scope, grp, auth.RoleTriager)
		}
		if !allowed {
			problem(w, http.StatusForbidden, "forbidden", "Removing finding "+id.String()+" needs triager on its application")
			return
		}
	}
	if err := a.store.RemoveGroupMembers(r.Context(), tenantID, grp.ID, ids); err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Removing the findings failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGroupTicket reserves one ticket for the whole group (doc 11, docs/23 C8). The ticket sweeper opens it on
// the tenant's tracker and links it to every member; nothing is sent to the tracker inside this request (D70).
func (a *API) handleGroupTicket(w http.ResponseWriter, r *http.Request) {
	tenantID, user, scope, ok := a.requireAny(w, r, auth.RoleMaintainer)
	if !ok {
		return
	}
	grp, ok := a.loadGroup(w, r, tenantID)
	if !ok {
		return
	}
	apps, err := a.store.GroupMemberApplications(r.Context(), tenantID, grp.ID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Reading the group's applications failed")
		return
	}
	if len(apps) == 0 {
		problem(w, http.StatusUnprocessableEntity, "validation", "The group has no findings to ticket")
		return
	}
	for _, app := range apps {
		if !scope.allows(app, auth.RoleMaintainer) {
			problem(w, http.StatusForbidden, "forbidden", "Opening a ticket for this group needs maintainer on every application in it")
			return
		}
	}
	reserved, err := a.store.RequestGroupTicket(r.Context(), tenantID, grp.ID, actorOf(user))
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Reserving the ticket failed")
		return
	}
	if !reserved {
		problem(w, http.StatusConflict, "conflict", "The group already has a ticket, or one is being opened")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"group_id": grp.ID, "ticket": map[string]string{"status": "reserved"}})
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
