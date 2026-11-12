package query

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/store"
	"rampart/internal/workflow"
)

// RiskAcceptanceBody is POST /api/v1/risk-acceptances (docs/06 section 6, docs/16 D39).
type RiskAcceptanceBody struct {
	FindingIDs         []string  `json:"findingIds"`
	Justification      string    `json:"justification"`
	ImpactStatement    string    `json:"impactStatement,omitempty"`
	Owner              string    `json:"owner,omitempty"`
	ExpiresAt          time.Time `json:"expiresAt"`
	OnExpiry           string    `json:"onExpiry,omitempty"`
	RestartSLAOnExpiry bool      `json:"restartSlaOnExpiry,omitempty"`
}

func acceptanceProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrVersionConflict):
		problem(w, http.StatusConflict, "conflict-version", "Someone else decided this risk acceptance first. Reload it.")
	default:
		triageProblem(w, err)
	}
}

func (a *API) handleRequestAcceptance(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	var body RiskAcceptanceBody
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil {
		problem(w, http.StatusBadRequest, "validation", "Invalid JSON payload")
		return
	}
	req := domain.RiskAcceptanceRequest{
		Justification: body.Justification, ImpactStatement: body.ImpactStatement, Owner: body.Owner, ExpiresAt: body.ExpiresAt,
		OnExpiry: body.OnExpiry, RestartSLAOnExpiry: body.RestartSLAOnExpiry,
	}
	for _, s := range body.FindingIDs {
		id, err := uuid.Parse(s)
		if err != nil {
			problem(w, http.StatusBadRequest, "validation", "findingIds holds a value that is not a finding id")
			return
		}
		req.FindingIDs = append(req.FindingIDs, id)
	}
	out, err := workflow.New(a.store).Request(r.Context(), tenantID, actorOf(user), req)
	if err != nil {
		acceptanceProblem(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (a *API) handleListAcceptances(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	status := domain.RiskAcceptanceStatus(r.URL.Query().Get("status"))
	switch status {
	case "", domain.AcceptancePending, domain.AcceptanceApproved, domain.AcceptanceRejected, domain.AcceptanceExpired, domain.AcceptanceRevoked:
	default:
		problem(w, http.StatusBadRequest, "validation", "status must be pending, approved, rejected, expired or revoked")
		return
	}
	limit := 100
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = min(v, 500)
	}
	items, err := a.store.ListRiskAcceptances(r.Context(), tenantID, status, limit)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to list risk acceptances")
		return
	}
	if items == nil {
		items = []*domain.RiskAcceptance{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) handleGetAcceptance(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Risk acceptance not found")
		return
	}
	ra, err := a.store.GetRiskAcceptance(r.Context(), tenantID, id)
	if err != nil {
		acceptanceProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ra)
}

type decisionBody struct {
	Note string `json:"note,omitempty"`
}

// decide runs approve, reject or revoke. Approving and rejecting need an admin (docs/06 says maintainer, a role
// that arrives with scoped access bindings); a requester may withdraw their own request.
func (a *API) decide(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		need := auth.RoleAdmin
		if action == "revoke" {
			need = auth.RoleTriager
		}
		tenantID, user, ok := a.requireRole(w, r, need)
		if !ok {
			return
		}
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			problem(w, http.StatusNotFound, "not-found", "Risk acceptance not found")
			return
		}
		var body decisionBody
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
		svc := workflow.New(a.store)
		actor := actorOf(user)
		switch action {
		case "approve":
			out, err := svc.Approve(r.Context(), tenantID, id, actor)
			if err != nil {
				acceptanceProblem(w, err)
				return
			}
			writeJSON(w, http.StatusOK, out)
		case "reject":
			ra, err := svc.Reject(r.Context(), tenantID, id, actor, body.Note)
			if err != nil {
				acceptanceProblem(w, err)
				return
			}
			writeJSON(w, http.StatusOK, ra)
		case "revoke":
			// A triager may revoke only what they asked for; an admin, anything.
			ra, err := a.store.GetRiskAcceptance(r.Context(), tenantID, id)
			if err != nil {
				acceptanceProblem(w, err)
				return
			}
			if user.Role.Rank() < auth.RoleAdmin.Rank() && ra.Requester != actor && ra.Owner != actor {
				problem(w, http.StatusForbidden, "forbidden", "Only an admin, or the person who asked for it or owns it, can revoke a risk acceptance")
				return
			}
			out, err := svc.Revoke(r.Context(), tenantID, id, actor, body.Note)
			if err != nil {
				acceptanceProblem(w, err)
				return
			}
			writeJSON(w, http.StatusOK, out)
		}
	}
}

// SettingsBody is PATCH /api/v1/settings: only the settings the workflow reads.
type SettingsBody struct {
	RiskAcceptanceApproval *bool `json:"riskAcceptanceApproval,omitempty"`
	RiskAcceptanceMaxDays  *int  `json:"riskAcceptanceMaxDays,omitempty"`
}

func (a *API) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	s, err := a.store.GetTenantSettings(r.Context(), tenantID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the settings")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (a *API) handlePatchSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleAdmin)
	if !ok {
		return
	}
	var body SettingsBody
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body) != nil {
		problem(w, http.StatusBadRequest, "validation", "Invalid JSON payload")
		return
	}
	s, err := a.store.GetTenantSettings(r.Context(), tenantID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the settings")
		return
	}
	if body.RiskAcceptanceApproval != nil {
		s.RiskAcceptanceApproval = *body.RiskAcceptanceApproval
	}
	if body.RiskAcceptanceMaxDays != nil {
		if *body.RiskAcceptanceMaxDays < 1 || *body.RiskAcceptanceMaxDays > domain.MaxAcceptanceMaxDays {
			problem(w, http.StatusBadRequest, "validation", "riskAcceptanceMaxDays must be between 1 and "+strconv.Itoa(domain.MaxAcceptanceMaxDays))
			return
		}
		s.RiskAcceptanceMaxDays = *body.RiskAcceptanceMaxDays
	}
	if err := a.store.SaveTenantSettings(r.Context(), tenantID, s); err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to save the settings")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
