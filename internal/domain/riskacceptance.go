package domain

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RiskAcceptanceStatus is where an acceptance is in its life (docs/06 section 6).
type RiskAcceptanceStatus string

const (
	AcceptancePending  RiskAcceptanceStatus = "pending"
	AcceptanceApproved RiskAcceptanceStatus = "approved"
	AcceptanceRejected RiskAcceptanceStatus = "rejected"
	AcceptanceExpired  RiskAcceptanceStatus = "expired"
	AcceptanceRevoked  RiskAcceptanceStatus = "revoked"
)

// What happens when an approved acceptance runs out.
const (
	OnExpiryReactivate = "reactivate"
	OnExpiryNotifyOnly = "notify_only"
)

// RiskAcceptance is a time-boxed decision to live with a risk: who asked, who owns it, who approved it,
// why, and until when (docs/03, docs/06 section 6, docs/16 D39). Only the decision "accept" exists.
type RiskAcceptance struct {
	ID                 uuid.UUID            `json:"id"`
	TenantID           uuid.UUID            `json:"tenant_id"`
	Decision           string               `json:"decision"`
	Justification      string               `json:"justification"`
	ImpactStatement    string               `json:"impact_statement,omitempty"`
	Owner              string               `json:"owner"`
	Requester          string               `json:"requester"`
	Approver           string               `json:"approver,omitempty"`
	Status             RiskAcceptanceStatus `json:"status"`
	ExpiresAt          time.Time            `json:"expires_at"`
	OnExpiry           string               `json:"on_expiry"`
	RestartSLAOnExpiry bool                 `json:"restart_sla_on_expiry"`
	DecisionNote       string               `json:"decision_note,omitempty"`
	CreatedAt          time.Time            `json:"created_at"`
	DecidedAt          *time.Time           `json:"decided_at,omitempty"`
	FindingIDs         []uuid.UUID          `json:"finding_ids"`
}

// TenantSettings are the per-tenant switches the workflow reads (docs/06 section 6). The zero value is not
// the default: use ParseTenantSettings.
type TenantSettings struct {
	// RiskAcceptanceApproval: a request waits for an approver who is not the requester. Off: auto-approved.
	RiskAcceptanceApproval bool `json:"riskAcceptanceApproval"`
	// RiskAcceptanceMaxDays is the longest an acceptance may run (docs/06: "for example 180 days").
	RiskAcceptanceMaxDays int `json:"riskAcceptanceMaxDays"`
}

// Limits of the settings, and the default maximum.
const (
	DefaultAcceptanceMaxDays = 180
	MaxAcceptanceMaxDays     = 730
	MaxAcceptanceFindings    = 100
)

// ParseTenantSettings reads tenant.settings, filling what is missing with the defaults.
func ParseTenantSettings(raw json.RawMessage) TenantSettings {
	s := TenantSettings{RiskAcceptanceMaxDays: DefaultAcceptanceMaxDays}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &s)
	}
	if s.RiskAcceptanceMaxDays <= 0 || s.RiskAcceptanceMaxDays > MaxAcceptanceMaxDays {
		s.RiskAcceptanceMaxDays = DefaultAcceptanceMaxDays
	}
	return s
}

// RiskAcceptanceRequest is what an analyst asks for.
type RiskAcceptanceRequest struct {
	FindingIDs         []uuid.UUID
	Justification      string
	ImpactStatement    string
	Owner              string // empty: the requester
	ExpiresAt          time.Time
	OnExpiry           string // empty: reactivate
	RestartSLAOnExpiry bool
}

// NewRiskAcceptance checks a request and builds a pending acceptance from it. It does not decide whether
// approval is needed: that is the caller's, from the tenant settings.
func NewRiskAcceptance(req RiskAcceptanceRequest, requester string, settings TenantSettings, now time.Time) (*RiskAcceptance, error) {
	if len(req.FindingIDs) == 0 {
		return nil, &TriageError{Msg: "name at least one finding"}
	}
	if len(req.FindingIDs) > MaxAcceptanceFindings {
		return nil, &TriageError{Msg: fmt.Sprintf("at most %d findings in one risk acceptance", MaxAcceptanceFindings)}
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range req.FindingIDs {
		if id == uuid.Nil || seen[id] {
			return nil, &TriageError{Msg: "the findings must be distinct finding ids"}
		}
		seen[id] = true
	}
	just := strings.TrimSpace(req.Justification)
	if just == "" {
		return nil, &TriageError{Msg: "a risk acceptance needs a justification: why is this risk acceptable?"}
	}
	if len(just) > MaxNote || len(req.ImpactStatement) > MaxNote {
		return nil, &TriageError{Msg: fmt.Sprintf("the justification and the impact statement are at most %d characters", MaxNote)}
	}
	if !req.ExpiresAt.After(now.Add(time.Hour)) {
		return nil, &TriageError{Msg: "the expiry must be at least an hour from now: an acceptance has to end"}
	}
	if max := now.Add(time.Duration(settings.RiskAcceptanceMaxDays) * 24 * time.Hour); req.ExpiresAt.After(max) {
		return nil, &TriageError{Msg: fmt.Sprintf("this tenant allows an acceptance of at most %d days", settings.RiskAcceptanceMaxDays)}
	}
	onExpiry := req.OnExpiry
	if onExpiry == "" {
		onExpiry = OnExpiryReactivate
	}
	if onExpiry != OnExpiryReactivate && onExpiry != OnExpiryNotifyOnly {
		return nil, &TriageError{Msg: "onExpiry must be reactivate or notify_only"}
	}
	owner := strings.TrimSpace(req.Owner)
	if owner == "" {
		owner = requester
	}
	if len(owner) > 255 {
		return nil, &TriageError{Msg: "the owner is at most 255 characters"}
	}
	return &RiskAcceptance{
		ID: NewID(), Decision: "accept", Justification: just, ImpactStatement: strings.TrimSpace(req.ImpactStatement),
		Owner: owner, Requester: requester, Status: AcceptancePending, ExpiresAt: req.ExpiresAt.UTC(), OnExpiry: onExpiry,
		RestartSLAOnExpiry: req.RestartSLAOnExpiry, CreatedAt: now, FindingIDs: append([]uuid.UUID(nil), req.FindingIDs...),
	}, nil
}
