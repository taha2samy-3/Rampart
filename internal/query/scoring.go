package query

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/risk"
	"rampart/internal/scoring"
	"rampart/internal/store"
	"rampart/internal/version"
)

// ScoringResponse is GET /api/v1/scoring: the version of the program and what decides a score, read from the policy
// that is in force for the caller's tenant, not written out by hand, so the page that explains the score cannot
// drift from the score.
type ScoringResponse struct {
	Product string `json:"product"`
	Version string `json:"version"`
	// Customised is true when the tenant, or the cluster, has set a policy of its own; false when the built-in one runs.
	Customised bool             `json:"customised"`
	Risk       risk.Description `json:"risk"`
	SLA        domain.SLAPolicy `json:"sla"`
	// What an application can say about itself (D140): the screens build their choices from these, so a value added here appears there.
	Environments     []string `json:"environments"`
	ApplicationTypes []string `json:"application_types"`
}

func (a *API) handleScoring(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	var rp *risk.Policy
	sla := domain.DefaultSLAPolicy()
	if a.scorer != nil {
		rp = a.scorer.RiskPolicy(r.Context(), tenantID)
		sla = a.scorer.Policy(r.Context(), tenantID)
	} else {
		rp = scoring.BuiltinPolicy{}.RiskPolicy(r.Context(), tenantID)
	}
	custom := false
	if _, found, err := a.store.GetRiskPolicySpec(r.Context(), tenantID); err == nil && found {
		custom = true
	}
	writeJSON(w, http.StatusOK, ScoringResponse{Product: "Rampart", Version: version.Version, Customised: custom, Risk: rp.Describe(), SLA: sla, Environments: domain.Environments, ApplicationTypes: domain.ApplicationTypes})
}

// handleUpdateApplicationContext answers PATCH /api/v1/applications/{id}: what the score knows about the application.
// A maintainer of the application (or of the tenant) may change it; an application an Application resource manages
// answers 409, because the resource is the truth for it and would undo the change.
func (a *API) handleUpdateApplicationContext(w http.ResponseWriter, r *http.Request) {
	tenantID, _, scope, ok := a.requireAny(w, r, auth.RoleMaintainer)
	if !ok {
		return
	}
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Application not found")
		return
	}
	if !scope.allows(appID, auth.RoleMaintainer) {
		problem(w, http.StatusForbidden, "forbidden", "Your role does not allow this on this application: it needs maintainer")
		return
	}
	wr, ok := a.store.(store.ApplicationContextWriter)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Changing an application needs PostgreSQL")
		return
	}
	var u domain.ApplicationContextUpdate
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&u); err != nil {
		problem(w, http.StatusBadRequest, "validation", "The body is not a valid application update: "+err.Error())
		return
	}
	if err := u.Validate(); err != nil {
		problem(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	app, err := wr.UpdateApplicationContext(r.Context(), tenantID, appID, u)
	switch {
	case errors.Is(err, store.ErrNotFound):
		problem(w, http.StatusNotFound, "not-found", "Application not found")
	case errors.Is(err, store.ErrManagedByResource):
		problem(w, http.StatusConflict, "managed-by-resource", "This application is managed by an Application resource. Change the resource: a change made here would be undone by the next reconcile.")
	case err != nil:
		problem(w, http.StatusInternalServerError, "internal", "Failed to change the application")
	default:
		writeJSON(w, http.StatusOK, app)
	}
}
