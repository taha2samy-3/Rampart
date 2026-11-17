package query

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/compliance"
	"rampart/internal/domain"
	"rampart/internal/store"
	"rampart/internal/telemetry"
)

// TaxonomyInfo is a framework in the list.
type TaxonomyInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Source     string `json:"source"`
	Kind       string `json:"kind"`
	Logo       string `json:"logo,omitempty"` // the mark, on this server (GET /taxonomies/{id}/logo); empty: the screen draws one
	Note       string `json:"note,omitempty"`
	Origin     string `json:"origin"`          // builtin | cluster | tenant
	Scope      string `json:"scope,omitempty"` // only applications whose complianceScope lists it
	WindowDays int    `json:"window_days"`
	Controls   int    `json:"controls"`
	Error      string `json:"error,omitempty"` // a resource that does not validate: shown, not used
}

func infoOf(f compliance.Framework) TaxonomyInfo {
	return TaxonomyInfo{ID: f.ID, Name: f.Name, Version: f.Version, Source: f.Source, Kind: f.Kind, Logo: logoPath(f.ID, f.LogoURL), Note: f.Note, Origin: f.Origin,
		Scope: f.Scope, WindowDays: f.Window(), Controls: len(f.Controls)}
}

type frameworkLister interface {
	ListComplianceFrameworks(ctx context.Context, tenantID uuid.UUID) ([]store.StoredFramework, error)
}

type scopeLister interface {
	ApplicationComplianceScopes(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID][]string, error)
}

// frameworks are the built-in frameworks, then those the platform and the tenant installed (D102). A tenant's
// framework with the name of a platform one replaces it for that tenant. broken lists the resources that do not
// validate, so the screen can say why they are missing.
func (a *API) frameworks(ctx context.Context, tenantID uuid.UUID) (fws []compliance.Framework, broken []TaxonomyInfo, err error) {
	builtin, err := compliance.All()
	if err != nil {
		return nil, nil, err
	}
	fws = append(fws, builtin...)
	lister, ok := a.store.(frameworkLister)
	if !ok {
		return fws, nil, nil
	}
	stored, err := lister.ListComplianceFrameworks(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	byName := map[string]compliance.Framework{}
	for _, s := range stored {
		if s.Spec == nil {
			broken = append(broken, TaxonomyInfo{ID: s.Name, Name: s.Name, Origin: s.Origin, Error: s.Error})
			continue
		}
		spec, perr := compliance.ParseFrameworkSpec(s.Spec)
		if perr != nil {
			broken = append(broken, TaxonomyInfo{ID: s.Name, Name: s.Name, Origin: s.Origin, Error: perr.Error()})
			continue
		}
		if prev, ok := byName[s.Name]; ok && prev.Origin == "tenant" {
			continue
		}
		f := spec.Framework(s.Name, s.Origin)
		if s.Error != "" { // the last valid spec is in force; the newer one is not
			f.Note = strings.TrimSpace(f.Note + " The latest change is not applied: " + s.Error)
		}
		byName[s.Name] = f
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fws = append(fws, byName[n])
	}
	return fws, broken, nil
}

func (a *API) framework(ctx context.Context, tenantID uuid.UUID, id string) (*compliance.Framework, error) {
	fws, _, err := a.frameworks(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for i := range fws {
		if fws[i].ID == id {
			return &fws[i], nil
		}
	}
	return nil, nil
}

func (a *API) handleListTaxonomies(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	fws, broken, err := a.frameworks(r.Context(), tenantID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "The frameworks could not be loaded")
		return
	}
	out := make([]TaxonomyInfo, 0, len(fws)+len(broken))
	for _, f := range fws {
		out = append(out, infoOf(f))
	}
	out = append(out, broken...)
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// ControlStatus is one control's reading, with what it rests on and a sentence that says why.
type ControlStatus struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Status      string         `json:"status"` // open | clear | not_assessed
	Reason      string         `json:"reason"` // the status in one sentence a reader can act on
	Open        int            `json:"open"`
	Bands       map[string]int `json:"bands"`
	Accepted    int            `json:"accepted"` // risk-accepted findings: approved exceptions, not counted as open
	Query       string         `json:"query,omitempty"`
	QueryExact  bool           `json:"query_exact"`
	// Overdue is how many of the open findings are past their SLA due date, and EarliestDue the soonest due date of them all:
	// a control is out of compliance when one is overdue, and at risk while they are only open (docs/28 §13).
	Overdue     int        `json:"overdue,omitempty"`
	EarliestDue *time.Time `json:"earliest_due,omitempty"`
	noDeadline  int        // of the open findings, how many have no SLA due date (D120)
	deadlines   bool       // the store could tell the deadlines; without it an open finding breaks the control, as before // false: the link lists part of what is counted
	Evidence    []string   `json:"evidence,omitempty"`
	Needs       []string   `json:"needs,omitempty"` // the kinds of scan that read it
	// Tenant-wide, a control is assessed only where its scans ran: in how many of the applications in scope.
	AssessedApps int                `json:"assessed_apps"`
	TotalApps    int                `json:"total_apps"`
	Manual       bool               `json:"manual,omitempty"`
	Attestation  *store.Attestation `json:"attestation,omitempty"`
	Rank         int                `json:"rank,omitempty"`
}

// TaxonomyStatus is GET /api/v1/taxonomies/{id}/status.
type TaxonomyStatus struct {
	TaxonomyInfo
	Application *uuid.UUID      `json:"application,omitempty"`
	EvaluatedAt time.Time       `json:"evaluated_at"`
	Historical  bool            `json:"historical,omitempty"` // read from the day's kept reading, not now
	Controls    []ControlStatus `json:"status"`
	// Model names the rule the statuses were read by. A kept reading carries the one it was written with; one with none was
	// written before D120, when any open finding made a control "open" and "at_risk" did not exist.
	Model string `json:"model,omitempty"`
	// totals counts the findings that break any control once each (not once per control); nil when the store cannot.
	totals *store.FindingTotals
}

// categoryWords names scan kinds in a sentence.
var categoryWords = map[string]string{"sast": "SAST", "sca": "dependency (SCA)", "secret": "secret", "iac": "IaC", "container": "image",
	"dast": "DAST", "cspm": "cloud", "compliance": "benchmark", "license": "licence", "supply_chain": "supply-chain"}

func kindsText(cats []string) string {
	w := make([]string, 0, len(cats))
	for _, c := range cats {
		if v, ok := categoryWords[c]; ok {
			w = append(w, v)
		} else {
			w = append(w, c)
		}
	}
	switch len(w) {
	case 0:
		return "a matching"
	case 1:
		return w[0]
	}
	return strings.Join(w[:len(w)-1], ", ") + " or " + w[len(w)-1]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// evaluate reads a framework now, for one application or for every application in its scope.
func (a *API) evaluate(ctx context.Context, tenantID uuid.UUID, fw compliance.Framework, app *uuid.UUID, now time.Time) (*TaxonomyStatus, error) {
	rd, ok := a.store.(store.ComplianceReader)
	if !ok {
		return nil, errUnsupported
	}
	// The applications in scope: the one asked for; else those whose complianceScope lists the framework's scope;
	// else all. nil means "all" to the store when the store cannot list them.
	var apps []uuid.UUID
	switch {
	case app != nil:
		apps = []uuid.UUID{*app}
	default:
		if sl, ok := a.store.(scopeLister); ok {
			scopes, err := sl.ApplicationComplianceScopes(ctx, tenantID)
			if err != nil {
				return nil, err
			}
			apps = []uuid.UUID{}
			for id, sc := range scopes {
				if fw.Scope == "" || containsStr(sc, fw.Scope) {
					apps = append(apps, id)
				}
			}
		}
	}
	matches := make([]store.ControlMatch, 0, len(fw.Controls))
	for _, c := range fw.Controls {
		if c.Manual {
			continue
		}
		m := store.ControlMatch{ID: c.ID, CWEs: c.CWEs, Categories: c.Categories, MinSeverity: c.MinSeverity}
		for _, rm := range c.Rules {
			m.Rules = append(m.Rules, store.RuleMatch{ScannerFamily: rm.ScannerFamily, RuleID: rm.RuleID})
		}
		matches = append(matches, m)
	}
	counts, err := rd.ControlCounts(ctx, tenantID, apps, matches)
	if err != nil {
		return nil, err
	}
	var deadlines map[string]store.ControlDeadline
	var totals *store.FindingTotals
	if dl, ok := a.store.(store.ComplianceDeadlines); ok {
		if deadlines, err = dl.ControlDeadlines(ctx, tenantID, apps, matches); err != nil {
			return nil, err
		}
		if deadlines == nil {
			deadlines = map[string]store.ControlDeadline{}
		}
		if t, terr := dl.DistinctFindings(ctx, tenantID, apps, matches); terr != nil {
			return nil, terr
		} else {
			totals = &t
		}
	}
	window := fw.Window()
	scans, err := rd.RecentScans(ctx, tenantID, apps, now.AddDate(0, 0, -window))
	if err != nil {
		return nil, err
	}
	fromFindings, err := rd.FamilyFindingCategories(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	extra := a.familyCategories(ctx, tenantID, fromFindings)
	scanned := map[uuid.UUID]map[string]bool{} // app -> category
	families := map[uuid.UUID]map[string]bool{}
	byCat := map[string][]string{}
	for _, s := range scans {
		if scanned[s.App] == nil {
			scanned[s.App], families[s.App] = map[string]bool{}, map[string]bool{}
		}
		families[s.App][s.Family] = true
		for _, cat := range compliance.CategoriesOf(s.Family, extra) {
			scanned[s.App][cat] = true
			if !containsStr(byCat[cat], s.Family) {
				byCat[cat] = append(byCat[cat], s.Family)
			}
		}
	}
	appSet := apps
	if appSet == nil { // the store cannot list applications: read the ones that were scanned
		for id := range scanned {
			appSet = append(appSet, id)
		}
	}
	var atts []store.Attestation
	if hasManual(fw) {
		if atts, err = rd.Attestations(ctx, tenantID, fw.ID); err != nil {
			return nil, err
		}
	}

	res := &TaxonomyStatus{TaxonomyInfo: infoOf(fw), Application: app, EvaluatedAt: now, Controls: make([]ControlStatus, 0, len(fw.Controls)), totals: totals, Model: complianceModel}
	for _, c := range fw.Controls {
		cs := ControlStatus{ID: c.ID, Name: c.Name, Description: c.Description, Rank: c.Rank, Manual: c.Manual, Bands: map[string]int{}, TotalApps: len(appSet)}
		if c.Manual {
			cs.Attestation = attestationFor(atts, c.ID, app, time.Now())
			readManual(&cs, now)
			res.Controls = append(res.Controls, cs)
			continue
		}
		cc := counts[c.ID]
		for _, b := range domain.Bands {
			cs.Bands[b] = cc.Open[b]
			cs.Open += cc.Open[b]
		}
		cs.Accepted = cc.Accepted
		if deadlines != nil {
			cs.deadlines = true
			cs.Overdue, cs.EarliestDue, cs.noDeadline = deadlines[c.ID].Overdue, deadlines[c.ID].Earliest, deadlines[c.ID].NoDeadline
		}
		cs.Query, cs.QueryExact = c.Query()
		cs.Needs = c.EvidenceCategories()
		for _, cat := range cs.Needs {
			for _, fam := range byCat[cat] {
				if !containsStr(cs.Evidence, fam) {
					cs.Evidence = append(cs.Evidence, fam)
				}
			}
		}
		for _, rm := range c.Rules {
			for _, f := range families {
				if f[rm.ScannerFamily] && !containsStr(cs.Evidence, rm.ScannerFamily) {
					cs.Evidence = append(cs.Evidence, rm.ScannerFamily)
				}
			}
		}
		sort.Strings(cs.Evidence)
		for _, id := range appSet {
			if c.Assessed(scanned[id], families[id]) {
				cs.AssessedApps++
			}
		}
		readMatched(&cs, c, window, app != nil)
		res.Controls = append(res.Controls, cs)
	}
	return res, nil
}

// complianceModel is the rule a reading's statuses are made by. Raise it when the meaning of a status changes, so a kept
// reading says which rule it was made with and the history can be read across the change.
const complianceModel = "d120-deadlines"

var errUnsupported = errors.New("compliance views need PostgreSQL")

func hasManual(fw compliance.Framework) bool {
	for _, c := range fw.Controls {
		if c.Manual {
			return true
		}
	}
	return false
}

// attestationFor is the attestation that reads a control. One made for the application asked about is more specific
// and wins over one made for the whole tenant, but only while it is in force: an expired one must not hide a
// tenant-wide attestation that still holds (D123). When none is in force, the newest that applies is returned, so
// the reading says "expired on ..." rather than "nobody has yet". Tenant-wide, only a whole-tenant attestation counts.
func attestationFor(atts []store.Attestation, controlID string, app *uuid.UUID, now time.Time) *store.Attestation {
	var specific, wide *store.Attestation
	for i := range atts { // newest first
		a := &atts[i]
		if a.ControlID != controlID {
			continue
		}
		if app != nil && a.ApplicationID != nil && *a.ApplicationID == *app {
			if specific == nil {
				specific = a
			}
		} else if a.ApplicationID == nil && wide == nil {
			wide = a
		}
	}
	inForce := func(a *store.Attestation) bool { return a != nil && a.ExpiresAt.After(now) }
	switch {
	case inForce(specific):
		return specific
	case inForce(wide):
		return wide
	case specific != nil:
		return specific
	}
	return wide
}

func readManual(cs *ControlStatus, now time.Time) {
	a := cs.Attestation
	who := ""
	if a != nil {
		who = strings.TrimPrefix(a.AttestedBy, "user:") // the person, as a reader names them
	}
	switch {
	case a == nil:
		cs.Status = string(compliance.StatusNotAssessed)
		cs.Reason = "A person attests this control, and nobody has yet."
	case !a.ExpiresAt.After(now):
		cs.Status = string(compliance.StatusNotAssessed)
		cs.Reason = fmt.Sprintf("The last attestation, by %s, expired on %s. Attest it again.", who, a.ExpiresAt.Format("2 Jan 2006"))
	case a.Status == "failed":
		cs.Status = string(compliance.StatusOpen)
		cs.Reason = fmt.Sprintf("%s attested on %s that it is not met.", who, a.AttestedAt.Format("2 Jan 2006"))
	default:
		cs.Status = string(compliance.StatusClear)
		cs.Reason = fmt.Sprintf("%s attested on %s that it is met; in force until %s.", who, a.AttestedAt.Format("2 Jan 2006"), a.ExpiresAt.Format("2 Jan 2006"))
	}
}

// readMatched decides a matched control's status and says why. Clear needs evidence everywhere it applies: one
// application's scan does not clear a control for another that was never scanned.
func readMatched(cs *ControlStatus, c compliance.Control, window int, oneApp bool) {
	needs := kindsText(cs.Needs)
	if len(c.Rules) > 0 && len(cs.Needs) == 0 {
		fams := []string{}
		for _, r := range c.Rules {
			if !containsStr(fams, r.ScannerFamily) {
				fams = append(fams, r.ScannerFamily)
			}
		}
		needs = strings.Join(fams, " or ")
	}
	exceptions := ""
	if cs.Accepted > 0 {
		exceptions = " " + plural(cs.Accepted, "finding is", "findings are") + " risk-accepted: approved exceptions, not counted as open."
	}
	switch {
	case cs.Open > 0 && cs.deadlines && cs.Overdue == 0 && cs.EarliestDue != nil && cs.noDeadline == 0:
		// Open, but none is past its deadline: the control still holds. (With no deadline at all there is no clock to wait
		// on, so the control is not met, as before.) PCI DSS 6.3.3 gives a month for a critical patch,
		// Vanta and Drata count an item overdue only past its SLA. It is at risk, and the first date is what to meet.
		cs.Status = string(compliance.StatusAtRisk)
		cs.Reason = plural(cs.Open, "open finding counts", "open findings count") + " against it, none past its deadline."
		if cs.EarliestDue != nil {
			cs.Reason += " The first falls due " + cs.EarliestDue.UTC().Format("2 Jan 2006") + "."
		}
	case cs.Open > 0:
		cs.Status = string(compliance.StatusOpen)
		cs.Reason = plural(cs.Open, "open finding breaks", "open findings break") + " it."
		if cs.deadlines && cs.Overdue == 0 && cs.noDeadline > 0 {
			// A finding with no deadline has no clock to wait on, so it counts now (D120), even beside findings that have one.
			late := "they are"
			if cs.noDeadline == 1 {
				late = "it is"
			}
			cs.Reason = plural(cs.noDeadline, "open finding has", "open findings have") + " no deadline, so nothing says when " + late + " late, and the control is not met (" + fmt.Sprintf("%d open in all", cs.Open) + ")."
		}
		if cs.deadlines && cs.Overdue > 0 {
			cs.Reason = plural(cs.Overdue, "finding is", "findings are") + " past the deadline, so the control is out of compliance (" + fmt.Sprintf("%d open in all", cs.Open) + ")."
		}
	case cs.TotalApps == 0:
		cs.Status = string(compliance.StatusNotAssessed)
		cs.Reason = "No application is in this framework's scope."
	case cs.AssessedApps == 0:
		cs.Status = string(compliance.StatusNotAssessed)
		cs.Reason = fmt.Sprintf("No %s scan ran in the last %d days, so nothing can be said.", needs, window)
	case cs.AssessedApps < cs.TotalApps:
		cs.Status = string(compliance.StatusNotAssessed)
		rest := "The other one"
		if n := cs.TotalApps - cs.AssessedApps; n > 1 {
			rest = fmt.Sprintf("The other %d", n)
		}
		cs.Reason = fmt.Sprintf("Assessed in %d of %d applications. %s had no %s scan in the last %d days.",
			cs.AssessedApps, cs.TotalApps, rest, needs, window)
	default:
		cs.Status = string(compliance.StatusClear)
		where := ""
		if !oneApp && cs.TotalApps > 1 {
			where = fmt.Sprintf(" in all %d applications", cs.TotalApps)
		}
		cs.Reason = fmt.Sprintf("Nothing that bears on it is open, and a %s scan ran%s in the last %d days.", needs, where, window)
	}
	cs.Reason += exceptions // an approved exception is said whatever the status: an auditor reads it
}

// handleTaxonomyStatus is GET /api/v1/taxonomies/{id}/status?application=&format=csv&at=YYYY-MM-DD. "Clear" means
// assessed and nothing open; it is evidence for an auditor, not a certification.
func (a *API) handleTaxonomyStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	rd, ok := a.store.(store.ComplianceReader)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Compliance views need PostgreSQL")
		return
	}
	fw, err := a.framework(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "The frameworks could not be loaded")
		return
	}
	if fw == nil {
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
		if fw.Scope != "" { // a scoped framework reads only the applications that list its scope (D102)
			if sl, ok := a.store.(scopeLister); ok {
				all, err := sl.ApplicationComplianceScopes(r.Context(), tenantID)
				if err != nil {
					problem(w, http.StatusInternalServerError, "internal", "The application's scopes could not be read")
					return
				}
				if !containsStr(all[id], fw.Scope) {
					problem(w, http.StatusNotFound, "not-found", "This framework does not apply to that application: it does not list the complianceScope "+fw.Scope)
					return
				}
			}
		}
	}
	format := r.URL.Query().Get("format")
	if format != "" && format != "json" && format != "csv" {
		problem(w, http.StatusBadRequest, "validation", "format is json or csv")
		return
	}
	var res *TaxonomyStatus
	if at := r.URL.Query().Get("at"); at != "" {
		day, err := time.Parse("2006-01-02", at)
		if err != nil {
			problem(w, http.StatusBadRequest, "validation", "at is a day, such as 2026-06-30")
			return
		}
		if app != nil {
			problem(w, http.StatusBadRequest, "validation", "The daily reading is kept for the whole tenant; leave out application")
			return
		}
		raw, err := rd.ComplianceSnapshot(r.Context(), tenantID, fw.ID, day)
		if errors.Is(err, store.ErrNoSnapshot) {
			problem(w, http.StatusNotFound, "not-found", "No reading of this framework was kept for "+at)
			return
		}
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "The kept reading could not be read")
			return
		}
		res = &TaxonomyStatus{}
		if err := json.Unmarshal(raw, res); err != nil {
			problem(w, http.StatusInternalServerError, "internal", "The kept reading could not be read")
			return
		}
		res.Historical = true
		if res.Model != complianceModel {
			res.Note = strings.TrimSpace(res.Note + " This reading was kept before controls were read by deadline (D120): then any open finding made a control not met, and \"at risk\" did not exist. Compare it with later days with that in mind.")
		}
	} else {
		res, err = a.evaluate(r.Context(), tenantID, *fw, app, time.Now().UTC())
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "Failed to evaluate the framework")
			return
		}
	}
	if format != "csv" {
		writeJSON(w, http.StatusOK, res)
		return
	}
	// A compliance report leaves the system: who took it, and of what, is audit evidence too.
	_ = a.store.RecordAudit(r.Context(), auth.AuditEvent{
		TenantID: tenantID, Actor: actorOf(user), Action: "GET /api/v1/taxonomies/{id}/status?format=csv",
		ResourceType: "compliance-frameworks", ResourceID: fw.ID,
		Detail: map[string]any{"version": fw.Version, "application": app, "at": r.URL.Query().Get("at")}, RequestID: telemetry.RequestID(r.Context()),
	})
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fw.ID+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"framework", "version", "application", "control", "name", "status", "reason", "open", "critical", "high", "medium", "low",
		"accepted", "assessed_applications", "applications", "evidence", "attested_by", "attested_at", "attestation_expires", "evaluated_at", "overdue", "earliest_due", "attestation_owner"})
	// open is every finding that counts against the control; only "overdue" of them are past their deadline, and a control
	// with open > 0 and overdue = 0 reads at_risk (D120). The last three columns were added after the first release.
	appCell := ""
	if app != nil {
		appCell = app.String()
	}
	for _, c := range res.Controls {
		by, at, exp, owner := "", "", "", ""
		if c.Attestation != nil {
			by, at, exp = c.Attestation.AttestedBy, c.Attestation.AttestedAt.Format(time.RFC3339), c.Attestation.ExpiresAt.Format(time.RFC3339)
			owner = csvCell(c.Attestation.Owner)
		}
		due := ""
		if c.EarliestDue != nil {
			due = c.EarliestDue.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{res.Name, res.Version, appCell, c.ID, csvCell(c.Name), c.Status, csvCell(c.Reason), strconv.Itoa(c.Open),
			strconv.Itoa(c.Bands["critical"]), strconv.Itoa(c.Bands["high"]), strconv.Itoa(c.Bands["medium"]), strconv.Itoa(c.Bands["low"]),
			strconv.Itoa(c.Accepted), strconv.Itoa(c.AssessedApps), strconv.Itoa(c.TotalApps), strings.Join(c.Evidence, " "),
			csvCell(by), at, exp, res.EvaluatedAt.Format(time.RFC3339), strconv.Itoa(c.Overdue), due, owner})
	}
	cw.Flush()
}

// csvCell defuses a cell a spreadsheet would run as a formula (D84).
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// handleTaxonomyHistory is GET /api/v1/taxonomies/{id}/history: the days a reading was kept, newest first.
func (a *API) handleTaxonomyHistory(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	rd, ok := a.store.(store.ComplianceReader)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Compliance views need PostgreSQL")
		return
	}
	days, err := rd.ComplianceSnapshotDays(r.Context(), tenantID, r.PathValue("id"), 400)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "The kept readings could not be listed")
		return
	}
	out := make([]string, 0, len(days))
	for _, d := range days {
		out = append(out, d.Format("2006-01-02"))
	}
	writeJSON(w, http.StatusOK, map[string]any{"days": out})
}

// AttestRequest is the body of POST /api/v1/taxonomies/{id}/controls/{control}/attestations.
type AttestRequest struct {
	Status        string     `json:"status"` // passed | failed
	Note          string     `json:"note"`
	EvidenceURL   string     `json:"evidence_url,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"` // default a year; at most three
	ApplicationID *uuid.UUID `json:"application_id,omitempty"`
	Owner         string     `json:"owner,omitempty"` // who renews it; default the person attesting
}

// handleAttest records a person's reading of a manual control (D102). Only a maintainer or above may attest:
// the same people who approve risk acceptances (docs/07).
func (a *API) handleAttest(w http.ResponseWriter, r *http.Request) {
	// The door is the highest role the caller holds anywhere (D48); the decision is checked below against the
	// application the attestation is for, or against the tenant role when it is for the whole tenant.
	tenantID, user, scope, ok := a.requireAny(w, r, auth.RoleMaintainer)
	if !ok {
		return
	}
	rd, ok := a.store.(store.ComplianceReader)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Compliance views need PostgreSQL")
		return
	}
	fw, err := a.framework(r.Context(), tenantID, r.PathValue("id"))
	if err != nil || fw == nil {
		problem(w, http.StatusNotFound, "not-found", "No such framework")
		return
	}
	var ctl *compliance.Control
	for i := range fw.Controls {
		if fw.Controls[i].ID == r.PathValue("control") {
			ctl = &fw.Controls[i]
		}
	}
	if ctl == nil {
		problem(w, http.StatusNotFound, "not-found", "No such control in this framework")
		return
	}
	if !ctl.Manual {
		problem(w, http.StatusConflict, "conflict", "This control is read from findings and scans; only a manual control is attested")
		return
	}
	var req AttestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "validation", "The body is not valid JSON")
		return
	}
	now := time.Now().UTC()
	req.Note = strings.TrimSpace(req.Note)
	switch {
	case req.Status != "passed" && req.Status != "failed":
		problem(w, http.StatusBadRequest, "validation", "status is passed or failed")
		return
	case req.Note == "" || len(req.Note) > 4000:
		problem(w, http.StatusBadRequest, "validation", "note says what was checked and how; it is required, at most 4000 characters")
		return
	}
	if req.EvidenceURL != "" {
		u, err := url.Parse(req.EvidenceURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			problem(w, http.StatusBadRequest, "validation", "evidence_url is an https link to where the evidence is kept")
			return
		}
	}
	expires := now.AddDate(1, 0, 0)
	if req.ExpiresAt != nil {
		expires = req.ExpiresAt.UTC()
		if !expires.After(now) || expires.After(now.AddDate(3, 0, 0)) {
			problem(w, http.StatusBadRequest, "validation", "expires_at is in the future and at most three years away")
			return
		}
	}
	if req.ApplicationID != nil {
		if app, err := a.store.GetApplication(r.Context(), tenantID, *req.ApplicationID); err != nil || app == nil {
			problem(w, http.StatusBadRequest, "validation", "application_id is not an application of this tenant")
			return
		}
		if !scope.allows(*req.ApplicationID, auth.RoleMaintainer) {
			problem(w, http.StatusForbidden, "forbidden", "Attesting needs the maintainer role on this application")
			return
		}
	} else if scope.tenant.Rank() < auth.RoleMaintainer.Rank() {
		problem(w, http.StatusForbidden, "forbidden", "An attestation for the whole tenant needs the maintainer role on the tenant, not only on an application")
		return
	}
	req.Owner = strings.TrimSpace(req.Owner)
	if len(req.Owner) > 200 || strings.ContainsFunc(req.Owner, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		problem(w, http.StatusBadRequest, "validation", "owner is at most 200 characters, on one line (it is written into notifications and tickets)")
		return
	}
	att := store.Attestation{ID: uuid.New(), FrameworkID: fw.ID, ControlID: ctl.ID, ApplicationID: req.ApplicationID, Status: req.Status,
		Note: req.Note, EvidenceURL: req.EvidenceURL, AttestedBy: actorOf(user), Owner: req.Owner, AttestedAt: now, ExpiresAt: expires}
	if err := rd.AddAttestation(r.Context(), tenantID, att); err != nil {
		problem(w, http.StatusInternalServerError, "internal", "The attestation could not be recorded")
		return
	}
	_ = a.store.RecordAudit(r.Context(), auth.AuditEvent{
		TenantID: tenantID, Actor: actorOf(user), Action: "POST /api/v1/taxonomies/{id}/controls/{control}/attestations",
		ResourceType: "compliance-frameworks", ResourceID: fw.ID,
		Detail: map[string]any{"control": ctl.ID, "status": req.Status, "application": req.ApplicationID, "expires_at": expires}, RequestID: telemetry.RequestID(r.Context()),
	})
	writeJSON(w, http.StatusCreated, att)
}

// handleTaxonomyLogo is GET /api/v1/taxonomies/{id}/logo: the mark the framework's resource names, read once by the
// server and served from here, so the page's security policy stays closed to other hosts and the viewer's address
// is not sent to a third party.
func (a *API) handleTaxonomyLogo(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	fw, err := a.framework(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "The frameworks could not be loaded")
		return
	}
	if fw == nil || fw.LogoURL == "" {
		problem(w, http.StatusNotFound, "not-found", "This framework has no logo")
		return
	}
	body, ctype, err := a.logos.get(r.Context(), fw.LogoURL)
	if err != nil {
		problem(w, http.StatusBadGateway, "logo-unavailable", "The logo could not be read: "+err.Error())
		return
	}
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cache-Control", "private, max-age=86400")
	_, _ = w.Write(body)
}
