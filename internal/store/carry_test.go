package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/domain"
)

func semgrepWith(rule, path, message string) string {
	return fmt.Sprintf(`{"check_id":%q,"path":%q,"start":{"line":3,"col":1},"end":{"line":3,"col":9},"extra":{"message":%q,"severity":"ERROR","lines":"x := q(r)","metadata":{"cwe":"CWE-89"}}}`, rule, path, message)
}

func findingOnTrack(t *testing.T, h *uploadHarness, rule, track string) *domain.Finding {
	t.Helper()
	list, err := h.app.ListFindings(context.Background(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		if f.RuleID == rule && f.Track == track {
			return f
		}
	}
	t.Fatalf("no %s finding on %s", rule, track)
	return nil
}

// A decision follows the issue to the asset's other tracks (01 C6, D57): a not_affected made on main reaches the
// same issue when release/1.x first reports it, with its justification and a timeline entry, and does not block
// the gate there. It does not carry when the evidence differs, a risk acceptance does not carry, and nothing that
// already exists is changed.
func TestDecisionsCarryAcrossTracks(t *testing.T) {
	ctx := context.Background()
	h := newUploadHarness(t)
	h.formatHint = "semgrep"
	triager := h.tokenFor(auth.RoleTriager, "sara@acme.example")
	onBranch := func(branch, commit string, results ...string) {
		t.Helper()
		h.waitRun(h.uploadAndComplete(semgrepReport(results...), domain.UploadContext{Repository: "github.com/acme/shop", Branch: branch, Commit: commit}))
	}

	// release/1.x already has rule.old open before anything is decided.
	onBranch("release/1.x", "r0", semgrepWith("rule.old", "old.go", "a flaw"))
	onBranch("main", "m1",
		semgrepWith("rule.fp", "a.go", "a flaw"), semgrepWith("rule.changed", "b.go", "a flaw"),
		semgrepWith("rule.accepted", "c.go", "a flaw"), semgrepWith("rule.old", "old.go", "a flaw"))

	decide := func(rule string) {
		t.Helper()
		f := findingOnTrack(t, h, rule, "main")
		code, body := h.callAs(triager, "PATCH", "/api/v1/findings/"+f.ID.String(),
			map[string]any{"state": "not_affected", "justification": "vulnerable_code_not_in_execute_path", "impactStatement": "only test data reaches it"}, nil)
		if code != http.StatusOK {
			t.Fatalf("PATCH %s: %d %s", rule, code, body)
		}
	}
	decide("rule.fp")
	decide("rule.changed")
	decide("rule.old")
	mustExec(t, h.pool, `UPDATE finding SET state = 'risk_accepted', previous_state = 'open' WHERE tenant_id = $1 AND rule_id = 'rule.accepted' AND track = 'main'`, h.tenant)

	// release/1.x reports the same issues; rule.changed has a different message there (different evidence).
	h.waitRun(h.uploadAndComplete(semgrepReport(
		semgrepWith("rule.fp", "a.go", "a flaw"), semgrepWith("rule.changed", "b.go", "another description of it"),
		semgrepWith("rule.accepted", "c.go", "a flaw"), semgrepWith("rule.old", "old.go", "a flaw")),
		domain.UploadContext{Repository: "github.com/acme/shop", Branch: "release/1.x", Commit: "r1"}))

	carried := findingOnTrack(t, h, "rule.fp", "release/1.x")
	if carried.State != domain.StateNotAffected || carried.Justification != "vulnerable_code_not_in_execute_path" || carried.ImpactStatement != "only test data reaches it" {
		t.Fatalf("the decision was not carried: %s %q %q", carried.State, carried.Justification, carried.ImpactStatement)
	}
	events, err := h.store.GetFindingEvents(ctx, h.tenant, carried.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Type == "decision_carried" {
			found = true
		}
	}
	if !found {
		t.Fatal("the timeline does not say where the decision came from")
	}
	if f := findingOnTrack(t, h, "rule.changed", "release/1.x"); f.State != domain.StateOpen {
		t.Fatalf("a decision carried onto different evidence: %s", f.State)
	}
	if f := findingOnTrack(t, h, "rule.accepted", "release/1.x"); f.State != domain.StateOpen {
		t.Fatalf("a risk acceptance carried to another track: %s", f.State)
	}
	if f := findingOnTrack(t, h, "rule.old", "release/1.x"); f.State != domain.StateOpen {
		t.Fatalf("an existing finding was changed retroactively: %s", f.State)
	}

	// The gate on the release commit: the carried finding is not new work; the two undecided new ones are.
	code, body := h.call("POST", "/api/v1/gate", map[string]any{"context": map[string]any{"commit": "r1"}, "expect": []string{"semgrep"}, "failOn": "high"}, nil)
	var g struct {
		Blocking []struct{ Path string } `json:"blocking"`
	}
	_ = json.Unmarshal(body, &g)
	if code != http.StatusOK || len(g.Blocking) != 2 {
		t.Fatalf("gate: %d %s", code, body)
	}
	for _, b := range g.Blocking {
		if b.Path == "a.go" {
			t.Fatal("a finding that arrived already decided blocked the gate")
		}
	}
}
