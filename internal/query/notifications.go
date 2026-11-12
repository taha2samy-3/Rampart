package query

import (
	"net/http"
	"strconv"
	"time"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// handleListNotifications is GET /api/v1/notifications?limit=: the newest first, each marked unread for the
// caller, and how many are unread in all (docs/16 D45).
func (a *API) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	nt, ok := a.store.(store.Notifications)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Notifications need PostgreSQL")
		return
	}
	limit := 30
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 100 {
		limit = n
	}
	items, unread, err := nt.ListNotifications(r.Context(), tenantID, actorOf(user), limit)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to list notifications")
		return
	}
	if items == nil {
		items = []domain.Notification{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "unread": unread})
}

// handleReadNotifications is POST /api/v1/notifications/read: everything up to now is read for the caller.
func (a *API) handleReadNotifications(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	nt, ok := a.store.(store.Notifications)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Notifications need PostgreSQL")
		return
	}
	if err := nt.MarkNotificationsRead(r.Context(), tenantID, actorOf(user), time.Now().UTC()); err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to mark notifications read")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
