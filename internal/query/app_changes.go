package query

import (
	"net/http"
	"time"

	"rampart/internal/auth"
	"rampart/internal/store"

	"github.com/google/uuid"
)

const maxChangeDays = 366

// ChangeSummary is the counts of a range, and the same counts for the range of the same length before it.
type ChangeSummary struct {
	New         int            `json:"new"`
	Closed      int            `json:"closed"`
	Reopened    int            `json:"reopened"`
	OpenAtStart int            `json:"open_at_start"`
	OpenAtEnd   int            `json:"open_at_end"`
	Previous    ChangePrevious `json:"previous"`
}

// ChangePrevious is the range before the one asked for: the same number of days, ending the day before it starts.
type ChangePrevious struct {
	From   string `json:"from"`
	To     string `json:"to"`
	New    int    `json:"new"`
	Closed int    `json:"closed"`
}

// ApplicationChangesResponse is GET /api/v1/applications/{id}/changes.
type ApplicationChangesResponse struct {
	Application uuid.UUID             `json:"application"`
	From        string                `json:"from"` // the first day, YYYY-MM-DD (UTC)
	To          string                `json:"to"`   // the last day, included
	Days        int                   `json:"days"`
	Summary     ChangeSummary         `json:"summary"`
	Daily       []store.ChangeDay     `json:"daily"`
	New         []store.FindingChange `json:"new"`
	Closed      []store.FindingChange `json:"closed"`
	Reopened    []store.FindingChange `json:"reopened"`
	Open        []store.FindingChange `json:"open"` // open when the range ended, worst first
	// Truncated names the lists cut at store.ChangeLimit; the summary counts are exact.
	Truncated []string `json:"truncated"`
}

func parseDay(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02", s)
	return t, err == nil
}

// handleApplicationChanges answers, for one application and a range of days: which findings (CVEs) appeared, which were
// closed and how, which came back, and which were open at the end, with the counts of the range before it to compare.
// Both days are included, in UTC. The default is the last 30 days.
func (a *API) handleApplicationChanges(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	rd, ok := a.store.(store.ChangeReader)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "This view needs PostgreSQL")
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
	today := time.Now().UTC().Truncate(24 * time.Hour)
	to, from := today, today.AddDate(0, 0, -29)
	if r.URL.Query().Has("to") {
		v := r.URL.Query().Get("to")
		if v == "" {
			problem(w, http.StatusBadRequest, "validation", "to is a day, such as 2026-11-20")
			return
		}
		if to, ok = parseDay(v); !ok {
			problem(w, http.StatusBadRequest, "validation", "to is a day, such as 2026-11-20")
			return
		}
		if !r.URL.Query().Has("from") {
			from = to.AddDate(0, 0, -29)
		}
	}
	if r.URL.Query().Has("from") {
		v := r.URL.Query().Get("from")
		if v == "" {
			problem(w, http.StatusBadRequest, "validation", "from is a day, such as 2026-11-01")
			return
		}
		if from, ok = parseDay(v); !ok {
			problem(w, http.StatusBadRequest, "validation", "from is a day, such as 2026-11-01")
			return
		}
	}
	if to.Before(from) {
		problem(w, http.StatusBadRequest, "validation", "from is after to")
		return
	}
	if to.After(today) { // a day that has not come has nothing in it
		to = today
	}
	if to.Before(from) {
		problem(w, http.StatusBadRequest, "validation", "The range starts in the future")
		return
	}
	days := int(to.Sub(from).Hours()/24) + 1
	if days > maxChangeDays {
		problem(w, http.StatusBadRequest, "validation", "A range is at most 366 days")
		return
	}
	ch, err := rd.ApplicationChanges(r.Context(), tenantID, appID, from, to.AddDate(0, 0, 1))
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "The changes could not be read")
		return
	}
	prevTo := from.AddDate(0, 0, -1)
	out := ApplicationChangesResponse{
		Application: appID, From: from.Format("2006-01-02"), To: to.Format("2006-01-02"), Days: days,
		Summary: ChangeSummary{New: ch.Counts.New, Closed: ch.Counts.Closed, Reopened: ch.Counts.Reopened, OpenAtStart: ch.Counts.OpenAtStart, OpenAtEnd: ch.Counts.OpenAtEnd,
			Previous: ChangePrevious{From: prevTo.AddDate(0, 0, -(days - 1)).Format("2006-01-02"), To: prevTo.Format("2006-01-02"), New: ch.Previous.New, Closed: ch.Previous.Closed}},
		Daily: ch.Days, New: ch.New, Closed: ch.Closed, Reopened: ch.Reopened, Open: ch.OpenAtEnd, Truncated: []string{},
	}
	// A list is [], never null: a page calls length and map on it.
	for _, l := range []*[]store.FindingChange{&out.New, &out.Closed, &out.Reopened, &out.Open} {
		if *l == nil {
			*l = []store.FindingChange{}
		}
	}
	if out.Daily == nil {
		out.Daily = []store.ChangeDay{}
	}
	for name, cut := range map[string]bool{"new": ch.NewMore, "closed": ch.ClosedMore, "reopened": ch.ReopenedMore, "open": ch.OpenMore} {
		if cut {
			out.Truncated = append(out.Truncated, name)
		}
	}
	writeJSON(w, http.StatusOK, out)
}
