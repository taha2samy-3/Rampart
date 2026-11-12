package query

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/compliance"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// TaxonomyInfo is a framework in the list.
type TaxonomyInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Source   string `json:"source"`
	Kind     string `json:"kind"`
	Note     string `json:"note,omitempty"`
	Controls int    `json:"controls"`
}

func (a *API) handleListTaxonomies(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.requireRole(w, r, auth.RoleViewer); !ok {
		return
	}
	fs, err := compliance.All()
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "The frameworks could not be loaded")
		return
	}
	out := make([]TaxonomyInfo, 0, len(fs))
	for _, f := range fs {
		out = append(out, TaxonomyInfo{ID: f.ID, Name: f.Name, Version: f.Version, Source: f.Source, Kind: f.Kind, Note: f.Note, Controls: len(f.Controls)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// ControlStatus is one control's reading, with what it rests on.
type ControlStatus struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Status   string         `json:"status"`
	Open     int            `json:"open"`
	Bands    map[string]int `json:"bands"`
	Query    string         `json:"query"`              // the findings filter that lists them
	Evidence []string       `json:"evidence,omitempty"` // scanners that ran lately and could evidence it
	Rank     int            `json:"rank,omitempty"`
}

// TaxonomyStatus is GET /api/v1/taxonomies/{id}/status.
type TaxonomyStatus struct {
	TaxonomyInfo
	Application *uuid.UUID      `json:"application,omitempty"`
	EvaluatedAt time.Time       `json:"evaluated_at"`
	WindowDays  int             `json:"window_days"`
	Controls    []ControlStatus `json:"status"`
}

const evidenceWindow = 30 * 24 * time.Hour

// handleTaxonomyStatus is GET /api/v1/taxonomies/{id}/status?application=&format=csv. Per control: open findings
// by band, and whether a scan that could evidence it ran in the last 30 days. "Clear" means assessed and nothing
// open; it is not a certification.
func (a *API) handleTaxonomyStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	rd, ok := a.store.(store.ComplianceReader)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Compliance views need PostgreSQL")
		return
	}
	fw, found := compliance.Get(r.PathValue("id"))
	if !found {
		problem(w, http.StatusNotFound, "not-found", "No such framework")
		return
	}
	var app *uuid.UUID
	if s := r.URL.Query().Get("application"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			problem(w, http.StatusBadRequest, "validation", "application is not an application id")
			return
		}
		app = &id
	}
	format := r.URL.Query().Get("format")
	if format != "" && format != "json" && format != "csv" {
		problem(w, http.StatusBadRequest, "validation", "format is json or csv")
		return
	}
	now := time.Now().UTC()
	matches := make([]store.ControlMatch, 0, len(fw.Controls))
	for _, c := range fw.Controls {
		matches = append(matches, store.ControlMatch{ID: c.ID, CWEs: c.CWEs, Categories: c.Categories})
	}
	counts, err := rd.ControlCounts(r.Context(), tenantID, app, matches)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to evaluate the framework")
		return
	}
	scans, err := rd.RecentScans(r.Context(), tenantID, app, now.Add(-evidenceWindow))
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the recent scans")
		return
	}
	scanned := map[string]bool{}
	byCat := map[string][]string{}
	for _, s := range scans {
		for _, cat := range compliance.FamilyCategories[s.Family] {
			scanned[cat] = true
			byCat[cat] = append(byCat[cat], s.Family)
		}
	}
	res := TaxonomyStatus{
		TaxonomyInfo: TaxonomyInfo{ID: fw.ID, Name: fw.Name, Version: fw.Version, Source: fw.Source, Kind: fw.Kind, Note: fw.Note, Controls: len(fw.Controls)},
		Application:  app, EvaluatedAt: now, WindowDays: int(evidenceWindow / (24 * time.Hour)),
		Controls: make([]ControlStatus, 0, len(fw.Controls)),
	}
	for _, c := range fw.Controls {
		bands := map[string]int{}
		for _, b := range domain.Bands {
			bands[b] = counts[c.ID][b]
		}
		open := 0
		for _, n := range counts[c.ID] {
			open += n
		}
		cs := ControlStatus{ID: c.ID, Name: c.Name, Open: open, Bands: bands, Query: c.Query(), Rank: c.Rank}
		switch {
		case open > 0:
			cs.Status = string(compliance.StatusOpen)
		case c.Assessed(scanned):
			cs.Status = string(compliance.StatusClear)
		default:
			cs.Status = string(compliance.StatusNotAssessed)
		}
		seen := map[string]bool{}
		for _, cat := range append(append([]string{}, c.Categories...), []string{"sast", "dast", "sca", "container"}[:map[bool]int{true: 4, false: 0}[len(c.Categories) == 0]]...) {
			for _, fam := range byCat[cat] {
				if !seen[fam] {
					seen[fam] = true
					cs.Evidence = append(cs.Evidence, fam)
				}
			}
		}
		res.Controls = append(res.Controls, cs)
	}
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fw.ID+`.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"framework", "version", "application", "control", "name", "status", "open", "critical", "high", "medium", "low", "evidence", "evaluated_at"})
		appCell := ""
		if app != nil {
			appCell = app.String()
		}
		for _, c := range res.Controls {
			_ = cw.Write([]string{fw.Name, fw.Version, appCell, c.ID, c.Name, c.Status, strconv.Itoa(c.Open),
				strconv.Itoa(c.Bands["critical"]), strconv.Itoa(c.Bands["high"]), strconv.Itoa(c.Bands["medium"]), strconv.Itoa(c.Bands["low"]),
				strings.Join(c.Evidence, " "), now.Format(time.RFC3339)})
		}
		cw.Flush()
		return
	}
	writeJSON(w, http.StatusOK, res)
}
