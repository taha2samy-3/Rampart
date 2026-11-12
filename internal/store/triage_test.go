package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/query"
)

// tokenFor issues an API token with a role, for the tenant of the harness.
func (h *uploadHarness) tokenFor(role auth.Role, subject string) string {
	h.t.Helper()
	raw, rec, err := auth.GenerateToken(h.tenant, role, subject, []string{"*"}, time.Hour)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.store.SaveToken(context.Background(), rec); err != nil {
		h.t.Fatal(err)
	}
	return raw
}

func (h *uploadHarness) callAs(token, method, path string, body any, headers map[string]string) (int, []byte) {
	h.t.Helper()
	saved := h.token
	h.token = token
	defer func() { h.token = saved }()
	return h.call(method, path, body, headers)
}

func ingestRules(t *testing.T, h *uploadHarness, rules map[string]string, branch string) {
	t.Helper()
	rep := miniSARIF(rules)
	run := h.waitRun(h.uploadAndComplete(rep, domain.UploadContext{Repository: "github.com/acme/up-test", Branch: branch, Commit: "c-" + uuid.NewString()[:6]}))
	if run.Status != domain.RunCompleted {
		t.Fatalf("ingest: %s %s", run.Status, run.Error)
	}
}

func findingIDs(t *testing.T, h *uploadHarness) map[string]uuid.UUID { // rule id -> finding id
	t.Helper()
	all, err := h.app.ListFindings(context.Background(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]uuid.UUID{}
	for _, f := range all {
		out[f.RuleID] = f.ID
	}
	return out
}

func TestTriage_EndToEnd(t *testing.T) {
	h := newUploadHarness(t)
	ingestRules(t, h, map[string]string{"rule.a": "9.5", "rule.b": "7.5", "rule.c": "5.5"}, "main")
	ids := findingIDs(t, h)
	if len(ids) != 3 {
		t.Fatalf("%d findings", len(ids))
	}
	a := ids["rule.a"].String()
	viewer := h.tokenFor(auth.RoleViewer, "viewer@acme.example")
	triager := h.tokenFor(auth.RoleTriager, "sara@acme.example")

	// A viewer reads but cannot decide.
	if code, _ := h.callAs(viewer, "PATCH", "/api/v1/findings/"+a, map[string]any{"state": "under_investigation"}, nil); code != http.StatusForbidden {
		t.Fatalf("viewer PATCH: want 403, got %d", code)
	}
	if code, _ := h.callAs(viewer, "POST", "/api/v1/findings/bulk", map[string]any{"ids": []string{a}, "patch": map[string]any{"state": "under_investigation"}}, nil); code != http.StatusForbidden {
		t.Fatalf("viewer bulk: want 403, got %d", code)
	}
	if code, _ := h.callAs(viewer, "GET", "/api/v1/findings/"+a+"/events", nil, nil); code != http.StatusOK {
		t.Fatalf("viewer may read the timeline: %d", code)
	}
	if code, _ := h.callAs("not-a-token", "PATCH", "/api/v1/findings/"+a, map[string]any{"state": "fixed"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("bad token: want 401, got %d", code)
	}

	// The rules answer 400 with the reason.
	for name, body := range map[string]map[string]any{
		"not_affected without a justification": {"state": "not_affected"},
		"an invented justification":            {"state": "not_affected", "justification": "trust me"},
		"fixed to affected is not a move":      {"state": "fixed"}, // first make it fixed below
	} {
		if name == "fixed to affected is not a move" {
			continue
		}
		if code, _ := h.callAs(triager, "PATCH", "/api/v1/findings/"+a, body, nil); code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", name, code)
		}
	}
	if code, _ := h.callAs(triager, "PATCH", "/api/v1/findings/"+a, map[string]any{}, nil); code != http.StatusBadRequest {
		t.Fatalf("an empty decision: want 400, got %d", code)
	}

	// A real decision: not_affected with its VEX justification, a severity override with its reason, tags and a note.
	code, body := h.callAs(triager, "PATCH", "/api/v1/findings/"+a, map[string]any{
		"state": "not_affected", "justification": "vulnerable_code_not_in_execute_path", "impactStatement": "the handler is never routed",
		"severity": "low", "severityReason": "internal tool", "tags": []string{"pci", "triaged"}, "note": "checked with the service owner",
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("decision: %d %s", code, body)
	}
	var res query.FindingResponse
	_ = json.Unmarshal(body, &res)
	if res.Finding.State != domain.StateNotAffected || res.Finding.Version != 2 {
		t.Fatalf("after the decision: state %s version %d", res.Finding.State, res.Finding.Version)
	}

	// It is stored, not only returned (the old PATCH lost the severity override on PostgreSQL).
	stored, _, err := h.store.GetFinding(context.Background(), h.tenant, ids["rule.a"])
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != domain.StateNotAffected || stored.Justification != "vulnerable_code_not_in_execute_path" || stored.ImpactStatement != "the handler is never routed" ||
		stored.Severity != domain.SeverityLow || stored.SeverityOverrideReason == nil || *stored.SeverityOverrideReason != "internal tool" ||
		len(stored.Tags) != 2 || stored.Resolution == nil || *stored.Resolution != domain.ResolutionNotAffected || stored.PreviousState != domain.StateOpen {
		t.Fatalf("stored finding: %+v", stored)
	}

	// The timeline says who did what.
	_, evBody := h.callAs(viewer, "GET", "/api/v1/findings/"+a+"/events", nil, nil)
	var evs query.EventsResponse
	_ = json.Unmarshal(evBody, &evs)
	types := map[string]string{}
	for _, e := range evs.Items {
		if e.Actor == "user:sara@acme.example" {
			types[e.Type] = e.Note
		}
	}
	_, hasTags := types["tags_changed"]
	if types["state_changed"] != "checked with the service owner" || types["severity_changed"] != "internal tool" || !hasTags || len(types) != 3 {
		// the note rides on the state event, so there is no separate note_added
		t.Fatalf("timeline by sara: %v (all: %+v)", types, evs.Items)
	}

	// A new scan of the same code does not undo the decision, nor the severity override.
	ingestRules(t, h, map[string]string{"rule.a": "9.5", "rule.b": "7.5", "rule.c": "5.5"}, "main")
	after, _, _ := h.store.GetFinding(context.Background(), h.tenant, ids["rule.a"])
	if after.State != domain.StateNotAffected || after.Justification == "" || after.Severity != domain.SeverityLow {
		t.Fatalf("a rescan changed a human decision: %+v", after)
	}

	// Optimistic locking: a stale If-Match is a 409, the right one applies.
	if code, _ := h.callAs(triager, "PATCH", "/api/v1/findings/"+a, map[string]any{"tags": []string{"x"}}, map[string]string{"If-Match": `"1"`}); code != http.StatusConflict {
		t.Fatalf("stale version: want 409, got %d", code)
	}
	if code, _ := h.callAs(triager, "PATCH", "/api/v1/findings/"+a, map[string]any{"tags": []string{"x"}}, map[string]string{"If-Match": `"2"`}); code != http.StatusOK {
		t.Fatalf("current version: want 200, got %d", code)
	}

	// Two people deciding on the same version at once: exactly one wins.
	b := ids["rule.b"].String()
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], _ = h.callAs(triager, "PATCH", "/api/v1/findings/"+b, map[string]any{"state": "under_investigation", "note": "me"}, map[string]string{"If-Match": `"1"`})
		}()
	}
	wg.Wait()
	oneWins := (codes[0] == 200 && codes[1] == 409) || (codes[0] == 409 && codes[1] == 200)
	if !oneWins {
		t.Fatalf("two simultaneous decisions on version 1: got %v, want one 200 and one 409", codes)
	}

	// Bulk by id: one is already there, one has a rule that refuses, the rest change.
	c := ids["rule.c"].String()
	code, body = h.callAs(triager, "POST", "/api/v1/findings/bulk", map[string]any{
		"ids": []string{a, b, c}, "patch": map[string]any{"state": "under_investigation"},
	}, nil)
	var bulk query.BulkResponse
	_ = json.Unmarshal(body, &bulk)
	// a: not_affected -> under_investigation is allowed (updated); b is already there (unchanged); c: open -> updated.
	if code != http.StatusOK || bulk.Matched != 3 || bulk.Updated != 2 || bulk.Unchanged != 1 || len(bulk.Failed) != 0 {
		t.Fatalf("bulk by id: %d %+v", code, bulk)
	}
	// Bulk with a decision that is wrong for some of them: they are listed, the others still go through.
	code, body = h.callAs(triager, "POST", "/api/v1/findings/bulk", map[string]any{
		"ids": []string{a, c}, "patch": map[string]any{"state": "fixed"},
	}, nil)
	_ = json.Unmarshal(body, &bulk)
	if code != http.StatusOK || bulk.Updated != 2 {
		t.Fatalf("bulk fixed: %d %+v", code, bulk)
	}
	code, body = h.callAs(triager, "POST", "/api/v1/findings/bulk", map[string]any{
		"ids": []string{a, c}, "patch": map[string]any{"state": "affected"}, // fixed -> affected is not a move
	}, nil)
	_ = json.Unmarshal(body, &bulk)
	if code != http.StatusOK || bulk.Updated != 0 || len(bulk.Failed) != 2 || !strings.Contains(bulk.Failed[0].Error, "cannot transition") {
		t.Fatalf("bulk refused: %d %+v", code, bulk)
	}
	// Bulk by filter, and the malformed shapes.
	code, body = h.callAs(triager, "POST", "/api/v1/findings/bulk", map[string]any{"q": "state:fixed", "patch": map[string]any{"tags": []string{"closed-batch"}}}, nil)
	_ = json.Unmarshal(body, &bulk)
	if code != http.StatusOK || bulk.Matched != 2 || bulk.Updated != 2 {
		t.Fatalf("bulk by filter: %d %+v", code, bulk)
	}
	for name, req := range map[string]map[string]any{
		"neither ids nor q": {"patch": map[string]any{"state": "fixed"}},
		"both ids and q":    {"ids": []string{a}, "q": "state:open", "patch": map[string]any{"state": "fixed"}},
		"a bad id":          {"ids": []string{"nope"}, "patch": map[string]any{"state": "fixed"}},
		"an invalid patch":  {"ids": []string{a}, "patch": map[string]any{"state": "banana"}},
	} {
		code, _ := h.callAs(triager, "POST", "/api/v1/findings/bulk", req, nil)
		if name == "an invalid patch" {
			// per-finding refusal, reported, not a 400 for the whole request
			if code != http.StatusOK {
				t.Fatalf("%s: %d", name, code)
			}
			continue
		}
		if code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", name, code)
		}
	}

	// Another tenant cannot decide on these findings, and cannot read their timeline.
	other := newUploadHarness(t)
	otherTriager := other.tokenFor(auth.RoleTriager, "eve@other.example")
	if code, _ := other.callAs(otherTriager, "PATCH", "/api/v1/findings/"+a, map[string]any{"state": "fixed"}, nil); code != http.StatusNotFound {
		t.Fatalf("SECURITY VIOLATION: another tenant reached a finding: %d", code)
	}
	if code, _ := other.callAs(otherTriager, "GET", "/api/v1/findings/"+a+"/events", nil, nil); code != http.StatusNotFound {
		t.Fatalf("SECURITY VIOLATION: another tenant read a timeline: %d", code)
	}
	if code, body := other.callAs(otherTriager, "POST", "/api/v1/findings/bulk", map[string]any{"ids": []string{a}, "patch": map[string]any{"state": "fixed"}}, nil); code != http.StatusOK || !strings.Contains(string(body), `"updated":0`) {
		t.Fatalf("SECURITY VIOLATION: another tenant's bulk touched findings: %d %s", code, body)
	}
}
