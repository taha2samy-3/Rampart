package query

import (
	"net/http"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/store"
)

// handleRetryAttestationTicket is POST /api/v1/attestation-tickets/{id}/retry (D126): a renewal ticket that gave up after
// its tries goes back to the outbox, and the sweeper tries again. {id} is the attestation's. An administrator, because a
// ticket is opened on the tenant's tracker with the tenant's credentials.
func (a *API) handleRetryAttestationTicket(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleAdmin)
	if !ok {
		return
	}
	rt, ok := a.store.(store.AttestationTicketRetrier)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Renewal tickets need PostgreSQL")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusBadRequest, "validation", "Not an attestation id")
		return
	}
	done, err := rt.RetryFailedAttestationTicket(r.Context(), tenantID, id)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "The ticket could not be sent back")
		return
	}
	if !done {
		problem(w, http.StatusConflict, "conflict", "There is no failed ticket for this attestation")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
