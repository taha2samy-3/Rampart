package query

import (
	"context"
	"sort"
	"time"

	"rampart/internal/compliance"
	"rampart/internal/domain"

	"github.com/google/uuid"
)

// FindingControl is a compliance control an open finding counts against.
type FindingControl struct {
	FrameworkID string `json:"framework_id"`
	Framework   string `json:"framework"`
	Version     string `json:"version"`
	ControlID   string `json:"control_id"`
	Control     string `json:"control"`
	// Due is the finding's deadline (the same for every control it breaks) and Overdue says it has passed: the control is
	// out of compliance until the finding is fixed, decided or accepted.
	Due     *time.Time `json:"due,omitempty"`
	Overdue bool       `json:"overdue"`
}

const maxFindingControls = 50

// findingControls lists the controls an open finding counts against, in the frameworks that read its application. It is
// what makes a deadline mean something on the finding itself: "fix this by the 24th or PCI 6.3.3 is out of compliance".
// A finding that is not open counts against nothing. compliance.Control.Breaks is the rule the compliance page counts by.
func (a *API) findingControls(ctx context.Context, tenantID uuid.UUID, f *domain.Finding, due *time.Time) []FindingControl {
	out := []FindingControl{}
	if f == nil || !f.State.IsActive() {
		return out
	}
	fws, _, err := a.frameworks(ctx, tenantID)
	if err != nil {
		return out
	}
	var scopes []string
	if sl, ok := a.store.(scopeLister); ok {
		if all, err := sl.ApplicationComplianceScopes(ctx, tenantID); err == nil {
			scopes = all[f.ApplicationID]
		}
	}
	facts := compliance.FindingFacts{CWEs: f.CWEs, Category: string(f.Category), ScannerFamily: f.RuleScannerFamily, RuleID: f.RuleID, Band: string(f.RiskBand)}
	overdue := due != nil && due.Before(time.Now())
	for _, fw := range fws {
		if fw.Scope != "" && !containsStr(scopes, fw.Scope) {
			continue
		}
		for _, c := range fw.Controls {
			if c.Breaks(facts) {
				out = append(out, FindingControl{FrameworkID: fw.ID, Framework: fw.Name, Version: fw.Version, ControlID: c.ID, Control: c.Name, Due: due, Overdue: overdue})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		return out[i].ControlID < out[j].ControlID
	})
	if len(out) > maxFindingControls {
		out = out[:maxFindingControls]
	}
	return out
}
