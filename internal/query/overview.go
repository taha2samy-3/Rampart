package query

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/query/grammar"
	"rampart/internal/store"
)

// TopFinding is one of the worst findings of an application, as the application page lists it.
type TopFinding struct {
	ID        uuid.UUID  `json:"id"`
	Title     string     `json:"title"`
	Band      string     `json:"band"`
	RiskScore int        `json:"risk_score"`
	State     string     `json:"state"`
	Due       *time.Time `json:"sla_due_date,omitempty"`
}

// ApplicationPage is GET /api/v1/applications/{id}/summary (docs/11): the summary, the SLA standing, the MTTR, the
// coverage, and the worst findings.
type ApplicationPage struct {
	domain.AppDetail
	TopFindings []TopFinding `json:"top_findings"`
}

// aggregator returns the store's aggregates, or answers 501 when it has none (the in-memory store).
func (a *API) aggregator(w http.ResponseWriter) (store.Aggregator, bool) {
	ag, ok := a.store.(store.Aggregator)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Aggregates need PostgreSQL")
		return nil, false
	}
	return ag, true
}

func (a *API) handleListApplications(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	ag, ok := a.aggregator(w)
	if !ok {
		return
	}
	apps, err := ag.ApplicationSummaries(r.Context(), tenantID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to list applications")
		return
	}
	if apps == nil {
		apps = []domain.AppSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": apps})
}

func (a *API) handleApplicationSummary(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	ag, ok := a.aggregator(w)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Application not found")
		return
	}
	detail, err := ag.ApplicationDetail(r.Context(), tenantID, id)
	if err != nil {
		if err == store.ErrNotFound {
			problem(w, http.StatusNotFound, "not-found", "Application not found")
		} else {
			problem(w, http.StatusInternalServerError, "internal", "Failed to read the application")
		}
		return
	}
	page := ApplicationPage{AppDetail: *detail, TopFindings: []TopFinding{}}
	if fq, ok := a.store.(FindingQuerier); ok {
		q, _ := grammar.Parse("app:" + id.String() + " state:open,under_investigation,affected")
		if top, err := fq.QueryFindings(r.Context(), tenantID, &q, "-score", 5, nil); err == nil {
			for _, f := range top {
				page.TopFindings = append(page.TopFindings, TopFinding{ID: f.ID, Title: f.Title, Band: string(f.RiskBand), RiskScore: f.RiskScore, State: string(f.State), Due: f.SLADue})
			}
		}
	}
	writeJSON(w, http.StatusOK, page)
}

func (a *API) handleOverview(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	ag, ok := a.aggregator(w)
	if !ok {
		return
	}
	hours := 24
	if v, err := strconv.Atoi(r.URL.Query().Get("sinceHours")); err == nil && v >= 1 && v <= 168 {
		hours = v
	}
	o, err := ag.Overview(r.Context(), tenantID, time.Now().UTC().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to compute the overview")
		return
	}
	writeJSON(w, http.StatusOK, o)
}

// handleTrend is GET /api/v1/metrics/trend?metric=open|new|closed&days=30 (docs/11), one point per day.
func (a *API) handleTrend(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	ag, ok := a.aggregator(w)
	if !ok {
		return
	}
	metric := r.URL.Query().Get("metric")
	if metric == "" {
		metric = "open"
	}
	if metric != "open" && metric != "new" && metric != "closed" {
		problem(w, http.StatusBadRequest, "validation", "metric must be open, new or closed")
		return
	}
	days := 30
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && v >= 1 && v <= 180 {
		days = v
	}
	pts, err := ag.Trend(r.Context(), tenantID, days)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to compute the trend")
		return
	}
	type point struct {
		Day   string `json:"day"`
		Value int    `json:"value"`
	}
	out := make([]point, 0, len(pts))
	for _, p := range pts {
		v := p.Open
		switch metric {
		case "new":
			v = p.New
		case "closed":
			v = p.Closed
		}
		out = append(out, point{Day: p.Day.UTC().Format("2006-01-02"), Value: v})
	}
	writeJSON(w, http.StatusOK, map[string]any{"metric": metric, "points": out})
}
