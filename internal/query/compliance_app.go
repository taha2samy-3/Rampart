package query

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"rampart/internal/auth"
	"rampart/internal/store"

	"github.com/google/uuid"
)

// AppFramework is where one application stands against one framework: what the application meets today.
type AppFramework struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Origin   string `json:"origin"`
	Logo     string `json:"logo,omitempty"`
	Verdict  string `json:"verdict"` // meets | at_risk | gaps | partial
	Controls int    `json:"controls"`
	Clear    int    `json:"clear"`        // read, with no open finding
	Open     int    `json:"open"`         // controls with at least one open finding
	AtRisk   int    `json:"at_risk"`      // open findings, none past its deadline: fix them before the first falls due
	Unread   int    `json:"not_assessed"` // no scan of the kind it needs, or a manual control nobody attested
	Findings int    `json:"open_findings"`
	// Overdue is the open findings past their deadline (they are what makes a control out of compliance), and EarliestDue the
	// soonest deadline among the open ones.
	Overdue     int        `json:"overdue_findings"`
	EarliestDue *time.Time `json:"earliest_due,omitempty"`
	Accepted    int        `json:"accepted_findings"`
	Window      int        `json:"window_days"`
}

// AppCompliance is GET /api/v1/applications/{id}/compliance.
type AppCompliance struct {
	Application uuid.UUID      `json:"application"`
	EvaluatedAt time.Time      `json:"evaluated_at"`
	Frameworks  []AppFramework `json:"frameworks"`
	// NotInScope names the frameworks that read only applications whose complianceScope lists their scope, and this
	// application does not.
	NotInScope []string `json:"not_in_scope"`
}

// verdictOf: an application has gaps when a control has a finding past its deadline (out of compliance); it is at risk
// when findings are open but none is past its deadline (compliant today, with a date to meet); it is partial when nothing
// is open but some control cannot be read; and it meets the framework when every control was read and nothing is open.
func verdictOf(open, atRisk, unread int) string {
	switch {
	case open > 0:
		return "gaps"
	case atRisk > 0:
		return "at_risk"
	case unread > 0:
		return "partial"
	default:
		return "meets"
	}
}

// handleApplicationCompliance answers "what does this application meet today": every framework that reads it, with
// the number of controls clear, open and not read. A framework with a scope reads only the applications that list it.
func (a *API) handleApplicationCompliance(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	if _, ok := a.store.(store.ComplianceReader); !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Compliance views need PostgreSQL")
		return
	}
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusBadRequest, "validation", "Not an application id")
		return
	}
	if app, err := a.store.GetApplication(r.Context(), tenantID, appID); err != nil || app == nil {
		problem(w, http.StatusNotFound, "not-found", "No such application")
		return
	}
	fws, _, err := a.frameworks(r.Context(), tenantID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "The frameworks could not be loaded")
		return
	}
	var scopes []string
	if sl, ok := a.store.(scopeLister); ok {
		all, err := sl.ApplicationComplianceScopes(r.Context(), tenantID)
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "The application's scopes could not be read")
			return
		}
		scopes = all[appID]
	}
	now := time.Now().UTC()
	out := AppCompliance{Application: appID, EvaluatedAt: now, Frameworks: []AppFramework{}, NotInScope: []string{}}
	for _, fw := range fws {
		if fw.Scope != "" && !containsStr(scopes, fw.Scope) {
			out.NotInScope = append(out.NotInScope, fw.Name)
			continue
		}
		st, err := a.evaluate(r.Context(), tenantID, fw, &appID, now)
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "A framework could not be evaluated: "+fw.Name)
			return
		}
		row := AppFramework{ID: fw.ID, Name: fw.Name, Version: fw.Version, Origin: fw.Origin, Logo: logoPath(fw.ID, fw.LogoURL), Controls: len(st.Controls), Window: fw.Window()}
		for _, c := range st.Controls {
			switch c.Status {
			case "clear":
				row.Clear++
			case "open", "at_risk":
				if c.Status == "open" {
					row.Open++
				} else {
					row.AtRisk++
				}
				row.Findings += c.Open
				row.Overdue += c.Overdue
				if c.EarliestDue != nil && (row.EarliestDue == nil || c.EarliestDue.Before(*row.EarliestDue)) {
					row.EarliestDue = c.EarliestDue
				}
			default:
				row.Unread++
			}
			row.Accepted += c.Accepted
		}
		row.Verdict = verdictOf(row.Open, row.AtRisk, row.Unread)
		out.Frameworks = append(out.Frameworks, row)
	}
	sort.Slice(out.Frameworks, func(i, j int) bool {
		return strings.ToLower(out.Frameworks[i].Name) < strings.ToLower(out.Frameworks[j].Name)
	})
	sort.Strings(out.NotInScope)
	writeJSON(w, http.StatusOK, out)
}
