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

func (a *API) bindingStore(w http.ResponseWriter) (store.AccessBindings, bool) {
	bs, ok := a.store.(store.AccessBindings)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Access bindings need PostgreSQL")
	}
	return bs, ok
}

// handleListBindings is GET /api/v1/access-bindings?application=: the bindings of the applications the caller
// owns (an admin owns them all).
func (a *API) handleListBindings(w http.ResponseWriter, r *http.Request) {
	tenantID, _, scope, ok := a.requireAny(w, r, auth.RoleOwner)
	if !ok {
		return
	}
	bs, ok := a.bindingStore(w)
	if !ok {
		return
	}
	var app *uuid.UUID
	if s := r.URL.Query().Get("application"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			problem(w, http.StatusBadRequest, "validation", "application is not an application id")
			return
		}
		app = &id
	}
	all, err := bs.ListAccessBindings(r.Context(), tenantID, app)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to list access bindings")
		return
	}
	out := []domain.AccessBinding{}
	for _, b := range all {
		if scope.allows(b.ApplicationID, auth.RoleOwner) {
			out = append(out, b)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// BindingBody is POST /api/v1/access-bindings.
type BindingBody struct {
	Subject       string `json:"subject"`
	Role          string `json:"role"`
	ApplicationID string `json:"applicationId"`
}

// handleCreateBinding gives a person or token a role on one application. The caller must own that application,
// and can give any role up to owner, never admin: admin is the tenant's and is not scoped.
func (a *API) handleCreateBinding(w http.ResponseWriter, r *http.Request) {
	tenantID, user, scope, ok := a.requireAny(w, r, auth.RoleOwner)
	if !ok {
		return
	}
	bs, ok := a.bindingStore(w)
	if !ok {
		return
	}
	var body BindingBody
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body) != nil {
		problem(w, http.StatusBadRequest, "validation", "Invalid JSON payload")
		return
	}
	subject := strings.TrimSpace(body.Subject)
	role, rok := auth.ParseRole(body.Role)
	app, aerr := uuid.Parse(body.ApplicationID)
	switch {
	case subject == "" || len(subject) > 254 || strings.ContainsAny(subject, " \t\r\n"):
		problem(w, http.StatusBadRequest, "validation", "subject is an e-mail address or a token subject, with no spaces")
		return
	case !rok || role == auth.RoleAdmin:
		problem(w, http.StatusBadRequest, "validation", "role is viewer, triager, maintainer or owner; admin belongs to the whole tenant")
		return
	case aerr != nil:
		problem(w, http.StatusBadRequest, "validation", "applicationId is not an application id")
		return
	}
	if !scope.allows(app, auth.RoleOwner) {
		problem(w, http.StatusForbidden, "forbidden", "Only an owner of the application, or an admin, can give access to it")
		return
	}
	b := &domain.AccessBinding{Subject: subject, Role: string(role), ApplicationID: app, CreatedBy: actorOf(user)}
	if err := bs.UpsertAccessBinding(r.Context(), tenantID, b); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problem(w, http.StatusNotFound, "not-found", "No such application")
			return
		}
		problem(w, http.StatusInternalServerError, "internal", "Failed to save the binding")
		return
	}
	if got, err := bs.GetAccessBinding(r.Context(), tenantID, b.ID); err == nil {
		b = got
	}
	writeJSON(w, http.StatusCreated, b)
}

// handleDeleteBinding removes a binding; the caller must own its application.
func (a *API) handleDeleteBinding(w http.ResponseWriter, r *http.Request) {
	tenantID, _, scope, ok := a.requireAny(w, r, auth.RoleOwner)
	if !ok {
		return
	}
	bs, ok := a.bindingStore(w)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Access binding not found")
		return
	}
	b, err := bs.GetAccessBinding(r.Context(), tenantID, id)
	if err != nil || !scope.allows(b.ApplicationID, auth.RoleOwner) { // what the caller cannot manage, they cannot see
		problem(w, http.StatusNotFound, "not-found", "Access binding not found")
		return
	}
	if b.ManagedBy != "api" {
		problem(w, http.StatusConflict, "managed", "This binding is managed by "+b.ManagedBy+" and is changed there")
		return
	}
	if err := bs.DeleteAccessBinding(r.Context(), tenantID, id); err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to remove the binding")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleMyAccess is GET /api/v1/me/access: the caller's tenant role and the roles they hold on applications, so
// the UI can offer a decision only where it will be accepted.
func (a *API) handleMyAccess(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	sc := a.scopeOf(r.Context(), tenantID, user)
	apps := map[string]string{}
	for id, role := range sc.apps {
		apps[id.String()] = string(role)
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": sc.tenant, "applications": apps})
}
