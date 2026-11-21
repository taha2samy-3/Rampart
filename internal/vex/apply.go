package vex

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/normalize"
)

// MatcherStore provides access to finding lookup and triage storage for VEX application.
type MatcherStore interface {
	FindFindingsForVEX(ctx context.Context, tenantID uuid.UUID, vulnIDs, purlBases []string, appID *uuid.UUID) ([]*domain.Finding, error)
	GetFindingEvents(ctx context.Context, tenantID, findingID uuid.UUID) ([]*domain.FindingEvent, error)
	UpdateFindingTriage(ctx context.Context, tenantID uuid.UUID, f *domain.Finding, expectedVersion int, events []*domain.FindingEvent) error
}

// Scorer optionally re-scores findings upon triage changes.
type Scorer interface {
	ScoreBatch(ctx context.Context, tenantID, appID uuid.UUID, findings []*domain.Finding) error
}

// ApplyOptions configures how a VEX document is applied to findings.
type ApplyOptions struct {
	DryRun   bool
	Actor    string
	Author   string
	Importer string
	AppID    *uuid.UUID
	Scorer   Scorer
	AllowApp func(appID uuid.UUID) bool
}

// Report details the outcome of applying a VEX document statement by statement.
type Report struct {
	Format     string      `json:"format"`
	DryRun     bool        `json:"dry_run"`
	Statements int         `json:"statements"`
	Matched    int         `json:"matched"`   // findings a statement was about
	Applied    int         `json:"applied"`   // findings decided
	Unchanged  int         `json:"unchanged"` // already in the state the statement says
	Stale      int         `json:"stale"`     // a person decided after the statement's time: human decision preserved
	Rejected   []Rejection `json:"rejected"`
	Unmatched  []Rejection `json:"unmatched"`
	Failed     []Failure   `json:"failed"`
}

// Rejection names a statement and why it was not used.
type Rejection struct {
	Vulnerability string   `json:"vulnerability"`
	Packages      []string `json:"packages,omitempty"`
	Reason        string   `json:"reason"`
}

// Failure describes an error applying a decision to a specific finding.
type Failure struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

// PurlVersion extracts the version component of a package URL, or "".
func PurlVersion(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndex(p, "@"); i >= 0 {
		return p[i+1:]
	}
	return ""
}

// StatementCovers reports whether st speaks for f: the vulnerability and package must match.
func StatementCovers(st Statement, f *domain.Finding) bool {
	if f.Location.Package == nil {
		return false
	}
	fv := PurlVersion(f.Location.Package.Purl)
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
		if v := PurlVersion(p); v == "" || fv == "" || v == fv {
			return true
		}
	}
	return false
}

// HumanDecisionAfter reports whether a human decided about the finding after t.
func HumanDecisionAfter(ctx context.Context, s MatcherStore, tenantID, id uuid.UUID, t time.Time) bool {
	if t.IsZero() {
		return false
	}
	evs, err := s.GetFindingEvents(ctx, tenantID, id)
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

// Apply executes a parsed VEX document against the findings of a tenant.
func Apply(ctx context.Context, s MatcherStore, doc *Document, tenantID uuid.UUID, opts ApplyOptions) (*Report, error) {
	rep := &Report{
		Format:     doc.Format,
		DryRun:     opts.DryRun,
		Statements: len(doc.Statements),
		Rejected:   []Rejection{},
		Unmatched:  []Rejection{},
		Failed:     []Failure{},
	}

	author := strings.TrimSpace(opts.Author)
	if author == "" {
		author = strings.TrimSpace(doc.Author)
	}
	if author == "" {
		author = "import"
	}

	actor := opts.Actor
	if actor == "" {
		actor = "vex:" + author
	}

	importer := opts.Importer
	if importer == "" {
		importer = author
	}

	// Oldest first, so that where two statements are about the same finding the later one is applied last.
	stmts := append([]Statement(nil), doc.Statements...)
	sort.SliceStable(stmts, func(i, j int) bool { return stmts[i].At.Before(stmts[j].At) })

	for _, st := range stmts {
		rej := Rejection{Vulnerability: strings.Join(st.Vulns, ", "), Packages: st.Purls}
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

		cands, err := s.FindFindingsForVEX(ctx, tenantID, st.Vulns, bases, opts.AppID)
		if err != nil {
			return nil, fmt.Errorf("vex: find findings: %w", err)
		}

		matched := 0
		for _, f := range cands {
			if !StatementCovers(st, f) {
				continue
			}
			matched++
			rep.Matched++

			if f.State == st.State && (st.State != domain.StateNotAffected || f.Justification == st.Justification) {
				rep.Unchanged++
				continue
			}

			if HumanDecisionAfter(ctx, s, tenantID, f.ID, st.At) {
				rep.Stale++
				continue
			}

			if opts.AllowApp != nil && !opts.AllowApp(f.ApplicationID) {
				rep.Failed = append(rep.Failed, Failure{ID: f.ID.String(), Error: "forbidden: role not permitted on application"})
				continue
			}

			note := fmt.Sprintf("VEX (%s) from %s, imported by %s", doc.Format, author, importer)
			if st.Action != "" {
				note += ". Action: " + st.Action
			}

			req := domain.TriageRequest{
				State:           st.State,
				Justification:   st.Justification,
				ImpactStatement: st.Impact,
				Note:            note,
			}

			if opts.DryRun {
				cp := *f
				if _, terr := domain.ApplyTriage(&cp, req, actor, time.Now().UTC()); terr != nil {
					rep.Failed = append(rep.Failed, Failure{ID: f.ID.String(), Error: terr.Error()})
					continue
				}
				rep.Applied++
				continue
			}

			events, terr := domain.ApplyTriage(f, req, actor, time.Now().UTC())
			if terr != nil {
				var te *domain.TriageError
				if errors.As(terr, &te) {
					rep.Failed = append(rep.Failed, Failure{ID: f.ID.String(), Error: te.Msg})
					continue
				}
				rep.Failed = append(rep.Failed, Failure{ID: f.ID.String(), Error: terr.Error()})
				continue
			}

			if !isNil(opts.Scorer) {
				if err := opts.Scorer.ScoreBatch(ctx, tenantID, f.ApplicationID, []*domain.Finding{f}); err != nil {
					rep.Failed = append(rep.Failed, Failure{ID: f.ID.String(), Error: err.Error()})
					continue
				}
			}

			if err := s.UpdateFindingTriage(ctx, tenantID, f, f.Version, events); err != nil {
				rep.Failed = append(rep.Failed, Failure{ID: f.ID.String(), Error: err.Error()})
				continue
			}
			rep.Applied++
		}

		if matched == 0 {
			rej.Reason = "no finding matches this vulnerability and package"
			rep.Unmatched = append(rep.Unmatched, rej)
		}
	}

	return rep, nil
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface) && rv.IsNil()
}
