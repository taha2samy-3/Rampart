package query

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/store"
	"rampart/internal/vex"
)

// handleExportVEX is GET /api/v1/applications/{id}/vex and /assets/{id}/vex (docs/05 section 7): the current
// decisions on the vulnerabilities of an application or an asset, as OpenVEX or CycloneDX.
func (a *API) handleExportVEX(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "No such application or asset")
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "openvex"
	}
	if format != "openvex" && format != "cyclonedx" {
		msg := "format is openvex or cyclonedx"
		if format == "csaf" {
			msg = "CSAF export is not built; use openvex or cyclonedx"
		}
		problem(w, http.StatusBadRequest, "validation", msg)
		return
	}
	findings, err := a.store.ListFindings(r.Context(), tenantID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to list findings")
		return
	}
	byApp := strings.Contains(r.URL.Path, "/applications/")
	var items []vex.Item
	for _, f := range findings {
		if (byApp && f.ApplicationID != id) || (!byApp && f.AssetID != id) {
			continue
		}
		if f.VulnerabilityID == nil || f.Location.Package == nil || f.Location.Package.Purl == "" {
			continue // only a vulnerability in a package is a VEX subject
		}
		items = append(items, vex.Item{
			Vuln: *f.VulnerabilityID, Purl: f.Location.Package.Purl, State: f.State, Justification: f.Justification,
			Impact: f.ImpactStatement, Action: f.StateReason, At: f.UpdatedAt,
		})
	}
	meta := vex.Meta{ID: fmt.Sprintf("https://rampart.aspm.dev/vex/%s/%s", tenantID, id), Author: "Rampart (" + actorOf(user) + ")", At: time.Now().UTC()}
	var doc map[string]any
	if format == "cyclonedx" {
		doc = vex.CycloneDX(meta, items)
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	} else {
		doc = vex.OpenVEX(meta, items)
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

// VEXImportReport says what an import did, statement by statement.
type VEXImportReport struct {
	Format     string         `json:"format"`
	DryRun     bool           `json:"dry_run"`
	Statements int            `json:"statements"`
	Matched    int            `json:"matched"`   // findings a statement was about
	Applied    int            `json:"applied"`   // findings decided
	Unchanged  int            `json:"unchanged"` // already in the state the statement says
	Stale      int            `json:"stale"`     // a person decided after the statement's time: the person wins
	Rejected   []VEXRejection `json:"rejected"`
	Unmatched  []VEXRejection `json:"unmatched"`
	Failed     []BulkFailure  `json:"failed"`
}

// VEXRejection names a statement and why it was not used.
type VEXRejection struct {
	Vulnerability string   `json:"vulnerability"`
	Packages      []string `json:"packages,omitempty"`
	Reason        string   `json:"reason"`
}

// purlVersion is the version of a package URL, or "".
func purlVersion(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndex(p, "@"); i >= 0 {
		return p[i+1:]
	}
	return ""
}

// humanDecisionAfter says whether a person decided about the finding after t: such a decision outranks a
// statement older than it (docs/05 section 7: later overrides earlier, and a person is later than a document
// written before them).
func (a *API) humanDecisionAfter(r *http.Request, tenantID, id uuid.UUID, t time.Time) bool {
	if t.IsZero() {
		return false
	}
	evs, err := a.store.GetFindingEvents(r.Context(), tenantID, id)
	if err != nil {
		return false
	}
	for _, e := range evs {
		if strings.HasPrefix(e.Actor, "user:") && e.At.After(t) && (e.Type == "state_changed") {
			return true
		}
	}
	return false
}

// handleImportVEX is POST /api/v1/vex?application=&dryRun=: OpenVEX or CycloneDX VEX decides findings. A
// statement that matches nothing creates nothing; it is reported.
func (a *API) handleImportVEX(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	m, ok := a.store.(store.VEXMatcher)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "VEX import needs PostgreSQL")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, vex.MaxDocument+1))
	if err != nil || len(data) == 0 {
		problem(w, http.StatusBadRequest, "validation", "The body is empty")
		return
	}
	if len(data) > vex.MaxDocument {
		problem(w, http.StatusRequestEntityTooLarge, "payload-too-large", "The document is larger than 16 MiB")
		return
	}
	var appID *uuid.UUID
	if s := r.URL.Query().Get("application"); s != "" {
		id, perr := uuid.Parse(s)
		if perr != nil {
			problem(w, http.StatusBadRequest, "validation", "application is not an application id")
			return
		}
		appID = &id
	}
	doc, err := vex.Parse(data)
	if err != nil {
		problem(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	dry := r.URL.Query().Get("dryRun") == "true"
	rep := VEXImportReport{Format: doc.Format, DryRun: dry, Statements: len(doc.Statements), Rejected: []VEXRejection{}, Unmatched: []VEXRejection{}, Failed: []BulkFailure{}}
	author := strings.TrimSpace(doc.Author)
	if author == "" {
		author = "import"
	}
	actor := "vex:" + author

	// Oldest first, so that where two statements are about the same finding the later one is applied last.
	stmts := append([]vex.Statement(nil), doc.Statements...)
	sort.SliceStable(stmts, func(i, j int) bool { return stmts[i].At.Before(stmts[j].At) })

	for _, st := range stmts {
		rej := VEXRejection{Vulnerability: strings.Join(st.Vulns, ", "), Packages: st.Purls}
		switch {
		case st.Problem != "":
			rej.Reason = st.Problem
		case len(st.Vulns) == 0:
			rej.Reason = "the statement names no vulnerability"
		case len(st.Purls) == 0:
			rej.Reason = "the statement names no package, and a decision for a whole product is not applied"
		}
		if rej.Reason != "" {
			rep.Rejected = append(rep.Rejected, rej)
			continue
		}
		var bases []string
		for _, p := range st.Purls {
			if _, base, perr := normalize.CanonicalPURL(p); perr == nil && base != "" {
				bases = append(bases, base)
			}
		}
		cands, err := m.FindFindingsForVEX(r.Context(), tenantID, st.Vulns, bases, appID)
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "Failed to look up findings")
			return
		}
		matched := 0
		for _, f := range cands {
			if !statementCovers(st, f) {
				continue
			}
			matched++
			rep.Matched++
			if f.State == st.State && (st.State != domain.StateNotAffected || f.Justification == st.Justification) {
				rep.Unchanged++
				continue
			}
			if a.humanDecisionAfter(r, tenantID, f.ID, st.At) {
				rep.Stale++
				continue
			}
			note := fmt.Sprintf("VEX (%s) from %s, imported by %s", doc.Format, author, actorOf(user))
			if st.Action != "" {
				note += ". Action: " + st.Action
			}
			patch := PatchFindingRequest{State: string(st.State), Justification: st.Justification, ImpactStatement: st.Impact, Note: note}
			if dry { // the same rules, on a copy
				req, _ := patch.toTriage()
				cp := *f
				if _, terr := domain.ApplyTriage(&cp, req, actor, time.Now().UTC()); terr != nil {
					rep.Failed = append(rep.Failed, BulkFailure{ID: f.ID.String(), Error: terr.Error()})
					continue
				}
				rep.Applied++
				continue
			}
			_, _, terr := a.triageOne(r.Context(), tenantID, f.ID, patch, nil, actor)
			var te *domain.TriageError
			switch {
			case terr == nil:
				rep.Applied++
			case errors.As(terr, &te), errors.Is(terr, store.ErrVersionConflict):
				rep.Failed = append(rep.Failed, BulkFailure{ID: f.ID.String(), Error: terr.Error()})
			default:
				problem(w, http.StatusInternalServerError, "internal", "Failed to save a decision")
				return
			}
		}
		if matched == 0 {
			rej.Reason = "no finding matches this vulnerability and package"
			rep.Unmatched = append(rep.Unmatched, rej)
		}
	}
	writeJSON(w, http.StatusOK, rep)
}

// statementCovers says whether a statement is about this finding's package: the same package, and the same
// version when the statement names one.
func statementCovers(st vex.Statement, f *domain.Finding) bool {
	if f.Location.Package == nil {
		return false
	}
	fv := purlVersion(f.Location.Package.Purl)
	if fv == "" {
		fv = f.Location.Package.InstalledVersion
	}
	fb := f.Location.Package.PurlBase
	if fb == "" {
		_, fb, _ = normalize.CanonicalPURL(f.Location.Package.Purl)
	}
	for _, p := range st.Purls {
		_, base, _ := normalize.CanonicalPURL(p)
		if base == "" || base != fb {
			continue
		}
		if v := purlVersion(p); v == "" || fv == "" || v == fv {
			return true
		}
	}
	return false
}
