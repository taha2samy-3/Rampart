package domain_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

func openFinding() *domain.Finding {
	return &domain.Finding{ID: uuid.New(), State: domain.StateOpen, Severity: domain.SeverityHigh, Detection: domain.DetectionPresent}
}

var now = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func TestApplyTriage_RulesOfD18(t *testing.T) {
	other := uuid.New()
	long := strings.Repeat("x", domain.MaxTagLength+1)
	cases := []struct {
		name    string
		from    domain.FindingState
		req     domain.TriageRequest
		wantErr string // substring; empty means it must succeed
	}{
		{"a risk cannot be accepted by a plain decision", domain.StateAffected, domain.TriageRequest{State: domain.StateRiskAccepted}, "risk acceptance"},
		{"open to under investigation", domain.StateOpen, domain.TriageRequest{State: domain.StateUnderInvestigation}, ""},
		{"fixed cannot become affected directly", domain.StateFixed, domain.TriageRequest{State: domain.StateAffected}, "cannot transition"},
		{"unknown state", domain.StateOpen, domain.TriageRequest{State: "banana"}, "unknown state"},
		{"not_affected needs a justification", domain.StateOpen, domain.TriageRequest{State: domain.StateNotAffected}, "OpenVEX justifications"},
		{"not_affected refuses an invented justification", domain.StateOpen, domain.TriageRequest{State: domain.StateNotAffected, Justification: "i just know"}, "OpenVEX justifications"},
		{"not_affected with a justification", domain.StateOpen, domain.TriageRequest{State: domain.StateNotAffected, Justification: "vulnerable_code_not_in_execute_path", ImpactStatement: "never called"}, ""},
		{"a justification outside not_affected", domain.StateOpen, domain.TriageRequest{State: domain.StateFixed, Justification: "component_not_present"}, "belongs to a not_affected"},
		{"duplicate needs its original", domain.StateOpen, domain.TriageRequest{State: domain.StateDuplicate}, "needs the id"},
		{"duplicate cannot be itself", domain.StateOpen, domain.TriageRequest{State: domain.StateDuplicate, DuplicateOf: &uuid.Nil}, ""}, // replaced below
		{"duplicate of another finding", domain.StateOpen, domain.TriageRequest{State: domain.StateDuplicate, DuplicateOf: &other}, ""},
		{"duplicateOf outside a duplicate", domain.StateOpen, domain.TriageRequest{State: domain.StateFixed, DuplicateOf: &other}, "belongs to a duplicate"},
		{"severity override needs a reason", domain.StateOpen, domain.TriageRequest{Severity: "low"}, "needs a reason"},
		{"severity override with a reason", domain.StateOpen, domain.TriageRequest{Severity: "low", SeverityReason: "internal tool, no data"}, ""},
		{"unknown severity", domain.StateOpen, domain.TriageRequest{Severity: "spicy", SeverityReason: "x"}, "severity must be"},
		{"a tag too long", domain.StateOpen, domain.TriageRequest{Tags: &[]string{long}}, "longer than"},
		{"a note alone", domain.StateOpen, domain.TriageRequest{Note: "talked to the owner"}, ""},
		{"an empty request", domain.StateOpen, domain.TriageRequest{}, "nothing to change"},
		{"the same state again", domain.StateOpen, domain.TriageRequest{State: domain.StateOpen}, "nothing to change"},
		{"a note that is too long", domain.StateOpen, domain.TriageRequest{Note: strings.Repeat("n", domain.MaxNote+1)}, "longer than"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := openFinding()
			f.State = c.from
			if c.name == "duplicate cannot be itself" {
				c.req.DuplicateOf = &f.ID
				c.wantErr = "cannot be itself"
			}
			before := *f
			events, err := domain.ApplyTriage(f, c.req, "user:sara", now)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want an error containing %q, got %v", c.wantErr, err)
				}
				if !domain.IsTriageError(err) {
					t.Fatal("a refused request must be a TriageError (400)")
				}
				if !reflect.DeepEqual(*f, before) {
					t.Fatal("a refused request must leave the finding untouched")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(events) == 0 {
				t.Fatal("a change must leave an event on the timeline")
			}
			for _, ev := range events {
				if ev.Actor != "user:sara" || !ev.At.Equal(now) || ev.FindingID != f.ID {
					t.Fatalf("event %+v", ev)
				}
			}
		})
	}
}

func TestApplyTriage_StateEffects(t *testing.T) {
	f := openFinding()
	f.Tags = []string{"a"}

	// Open to risk_accepted remembers where it came from (D18: expiry returns there).
	f.State = domain.StateAffected
	if _, err := domain.ApplyTriage(f, domain.TriageRequest{State: domain.StateRiskAccepted, Note: "approved by CISO", ViaRiskAcceptance: true}, "u", now); err != nil {
		t.Fatal(err)
	}
	if f.PreviousState != domain.StateAffected || f.State != domain.StateRiskAccepted || f.StateReason != "approved by CISO" {
		t.Fatalf("risk accepted: %+v", f)
	}
	if f.Resolution == nil || *f.Resolution != domain.ResolutionRiskAccepted || f.ResolvedAt == nil {
		t.Fatalf("resolution: %+v", f.Resolution)
	}

	// Back to an active state clears the resolution and the memory.
	if _, err := domain.ApplyTriage(f, domain.TriageRequest{State: domain.StateOpen}, "u", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if f.PreviousState != "" || f.Resolution != nil || f.ResolvedAt != nil {
		t.Fatalf("reopened: %+v", f)
	}

	// not_affected keeps its justification, and loses it when the finding goes back.
	if _, err := domain.ApplyTriage(f, domain.TriageRequest{State: domain.StateNotAffected, Justification: "component_not_present", ImpactStatement: "not shipped"}, "u", now); err != nil {
		t.Fatal(err)
	}
	if f.Justification != "component_not_present" || f.ImpactStatement != "not shipped" {
		t.Fatalf("justification: %+v", f)
	}
	if _, err := domain.ApplyTriage(f, domain.TriageRequest{State: domain.StateUnderInvestigation}, "u", now); err != nil {
		t.Fatal(err)
	}
	if f.Justification != "" || f.ImpactStatement != "" {
		t.Fatal("leaving not_affected must clear its justification")
	}

	// A duplicate points at its original, and stops pointing when it is reopened.
	orig := uuid.New()
	g := openFinding()
	if _, err := domain.ApplyTriage(g, domain.TriageRequest{State: domain.StateDuplicate, DuplicateOf: &orig}, "u", now); err != nil {
		t.Fatal(err)
	}
	if g.DuplicateOfID == nil || *g.DuplicateOfID != orig {
		t.Fatal("duplicate_of not set")
	}
	if _, err := domain.ApplyTriage(g, domain.TriageRequest{State: domain.StateOpen}, "u", now); err != nil {
		t.Fatal(err)
	}
	if g.DuplicateOfID != nil {
		t.Fatal("duplicate_of must clear on reopen")
	}

	// Reopening a fixed finding counts as a reopening.
	h := openFinding()
	h.State = domain.StateFixed
	if _, err := domain.ApplyTriage(h, domain.TriageRequest{State: domain.StateOpen}, "u", now); err != nil {
		t.Fatal(err)
	}
	if h.ReopenedCount != 1 {
		t.Fatalf("reopened_count %d", h.ReopenedCount)
	}
}

func TestApplyTriage_SeverityAndTags(t *testing.T) {
	f := openFinding()
	evs, err := domain.ApplyTriage(f, domain.TriageRequest{Severity: "low", SeverityReason: "dev only", Tags: &[]string{" pci ", "pci", "", "alpha"}, Note: "see ticket"}, "u", now)
	if err != nil {
		t.Fatal(err)
	}
	if f.Severity != domain.SeverityLow || f.SeverityOverrideReason == nil || *f.SeverityOverrideReason != "dev only" {
		t.Fatalf("severity: %+v", f)
	}
	if !reflect.DeepEqual(f.Tags, []string{"alpha", "pci"}) { // trimmed, deduplicated, sorted
		t.Fatalf("tags %v", f.Tags)
	}
	types := map[string]bool{}
	for _, e := range evs {
		types[e.Type] = true
	}
	if !types["severity_changed"] || !types["tags_changed"] || !types["note_added"] || len(evs) != 3 {
		t.Fatalf("events %v", types)
	}
	// Setting the same tags again is not a change.
	if _, err := domain.ApplyTriage(f, domain.TriageRequest{Tags: &[]string{"pci", "alpha"}}, "u", now); err == nil {
		t.Fatal("the same tags again must be nothing to change")
	}
	// An empty list clears them.
	if _, err := domain.ApplyTriage(f, domain.TriageRequest{Tags: &[]string{}}, "u", now); err != nil || len(f.Tags) != 0 {
		t.Fatalf("clear tags: %v %v", err, f.Tags)
	}
}
