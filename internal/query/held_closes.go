package query

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
)

// handleListHeldCloses lists the mass-closes held for review (D22, Section 3.2).
func (a *API) handleListHeldCloses(w http.ResponseWriter, r *http.Request) {
	tenantID, _, _, ok := a.requireAny(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	decision := r.URL.Query().Get("decision")
	items, err := a.store.ListHeldCloses(r.Context(), tenantID, decision)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal-error", err.Error())
		return
	}
	if items == nil {
		items = []domain.HeldClose{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"items": items,
		"total": len(items),
	})
}

// handleConfirmHeldClose confirms a held close, closing those findings that are still open and absent (D22, Section 3.2).
func (a *API) handleConfirmHeldClose(w http.ResponseWriter, r *http.Request) {
	tenantID, user, scope, ok := a.requireAny(w, r, auth.RoleMaintainer)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Held close not found")
		return
	}
	hc, err := a.store.GetHeldClose(r.Context(), tenantID, id)
	if err != nil || hc == nil {
		problem(w, http.StatusNotFound, "not-found", "Held close not found")
		return
	}
	run, err := a.store.GetIngestRun(r.Context(), tenantID, hc.IngestRunID)
	if err != nil || run == nil {
		problem(w, http.StatusNotFound, "not-found", "Ingest run not found")
		return
	}
	if !scope.allows(run.ApplicationID, auth.RoleMaintainer) {
		problem(w, http.StatusForbidden, "forbidden", "Confirming a held close requires the maintainer role on the application")
		return
	}

	actor := actorOf(user)
	closed, err := a.store.ApplyHeldClose(r.Context(), tenantID, id, actor)
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}

	_ = a.store.RecordAudit(r.Context(), auth.AuditEvent{
		TenantID:     tenantID,
		Actor:        actor,
		Action:       "POST /api/v1/held-closes/{id}/confirm",
		ResourceType: "held_close",
		ResourceID:   id.String(),
		Detail: map[string]any{
			"closed": closed,
			"run_id": hc.IngestRunID.String(),
		},
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":       id,
		"decision": domain.HeldCloseDecisionConfirmed,
		"closed":   closed,
	})
}

// handleDiscardHeldClose discards a held close without closing any findings (D22, Section 3.2).
func (a *API) handleDiscardHeldClose(w http.ResponseWriter, r *http.Request) {
	tenantID, user, scope, ok := a.requireAny(w, r, auth.RoleMaintainer)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Held close not found")
		return
	}
	hc, err := a.store.GetHeldClose(r.Context(), tenantID, id)
	if err != nil || hc == nil {
		problem(w, http.StatusNotFound, "not-found", "Held close not found")
		return
	}
	run, err := a.store.GetIngestRun(r.Context(), tenantID, hc.IngestRunID)
	if err != nil || run == nil {
		problem(w, http.StatusNotFound, "not-found", "Ingest run not found")
		return
	}
	if !scope.allows(run.ApplicationID, auth.RoleMaintainer) {
		problem(w, http.StatusForbidden, "forbidden", "Discarding a held close requires the maintainer role on the application")
		return
	}

	actor := actorOf(user)
	if err := a.store.DecideHeldClose(r.Context(), tenantID, id, domain.HeldCloseDecisionDiscarded, actor); err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}

	_ = a.store.RecordAudit(r.Context(), auth.AuditEvent{
		TenantID:     tenantID,
		Actor:        actor,
		Action:       "POST /api/v1/held-closes/{id}/discard",
		ResourceType: "held_close",
		ResourceID:   id.String(),
		Detail: map[string]any{
			"run_id": hc.IngestRunID.String(),
		},
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":       id,
		"decision": domain.HeldCloseDecisionDiscarded,
	})
}
