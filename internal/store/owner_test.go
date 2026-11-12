package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/query"
)

// Owners (01 C9, D59): a finding is assigned to a member of the tenant, singly or in bulk; the timeline says so;
// owner:<e-mail>, owner:none and owner:me find them. A non-member is refused, and an unknown filter field is
// refused instead of being dropped (which made a bulk change by filter reach every finding).
func TestOwners(t *testing.T) {
	ctx := context.Background()
	h := newUploadHarness(t)
	h.formatHint = "semgrep"
	h.waitRun(h.uploadAndComplete(semgrepReport(semgrepResult("rule.a", "a.go", 3), semgrepResult("rule.b", "b.go", 4), semgrepResult("rule.c", "c.go", 5)),
		domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main"}))
	uid, err := h.sys.UpsertUser(ctx, auth.User{Issuer: "https://idp.example", Subject: "mona-1", Email: "Mona@Acme.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.sys.UpsertMember(ctx, h.tenant, uid, auth.RoleTriager); err != nil {
		t.Fatal(err)
	}
	sara := h.tokenFor(auth.RoleTriager, "sara@acme.example")
	a := findingByRule(t, h, "rule.a")

	// A non-member is refused; a member (any case) is set, lower-cased, and on the timeline.
	if code, body := h.callAs(sara, "PATCH", "/api/v1/findings/"+a.ID.String(), map[string]any{"owner": "stranger@elsewhere.example"}, nil); code != http.StatusBadRequest {
		t.Fatalf("a non-member owner: %d %s", code, body)
	}
	if code, body := h.callAs(sara, "PATCH", "/api/v1/findings/"+a.ID.String(), map[string]any{"owner": "mona@acme.EXAMPLE"}, nil); code != http.StatusOK {
		t.Fatalf("assign: %d %s", code, body)
	}
	if got := findingByRule(t, h, "rule.a").Owner; got != "mona@acme.example" {
		t.Fatalf("owner: %q", got)
	}
	events, _ := h.store.GetFindingEvents(ctx, h.tenant, a.ID)
	if last := events[len(events)-1]; last.Type != "owner_changed" || last.Actor != "user:sara@acme.example" {
		t.Fatalf("timeline: %+v", last)
	}

	// Bulk by filter: everything unassigned goes to mona. owner:none matched b and c only.
	code, body := h.callAs(sara, "POST", "/api/v1/findings/bulk", map[string]any{"q": "owner:none", "patch": map[string]any{"owner": "mona@acme.example"}}, nil)
	var bulk query.BulkResponse
	_ = json.Unmarshal(body, &bulk)
	if code != http.StatusOK || bulk.Matched != 2 || bulk.Updated != 2 {
		t.Fatalf("bulk: %d %s", code, body)
	}
	list := func(token, q string) int {
		t.Helper()
		code, body := h.callAs(token, "GET", "/api/v1/findings?q="+q, nil, nil)
		var res struct{ Items []json.RawMessage }
		_ = json.Unmarshal(body, &res)
		if code != http.StatusOK {
			t.Fatalf("list %s: %d %s", q, code, body)
		}
		return len(res.Items)
	}
	if n := list(sara, "owner:mona@acme.example"); n != 3 {
		t.Fatalf("owner:mona: %d", n)
	}
	mona := h.tokenFor(auth.RoleTriager, "mona@acme.example")
	if n := list(mona, "owner:me"); n != 3 {
		t.Fatalf("owner:me for mona: %d", n)
	}
	if n := list(sara, "owner:me"); n != 0 {
		t.Fatalf("owner:me for sara: %d", n)
	}

	// Clearing.
	if code, _ := h.callAs(sara, "PATCH", "/api/v1/findings/"+a.ID.String(), map[string]any{"owner": ""}, nil); code != http.StatusOK {
		t.Fatal("clear")
	}
	if n := list(sara, "owner:none"); n != 1 {
		t.Fatalf("owner:none after clearing: %d", n)
	}

	// Tags in bulk are added and removed, never replaced: each finding keeps its own.
	if code, body := h.callAs(sara, "PATCH", "/api/v1/findings/"+a.ID.String(), map[string]any{"tags": []string{"keep-me"}}, nil); code != http.StatusOK {
		t.Fatalf("tags: %d %s", code, body)
	}
	if code, body := h.callAs(sara, "POST", "/api/v1/findings/bulk", map[string]any{"q": "", "ids": []string{a.ID.String(), findingByRule(t, h, "rule.b").ID.String()},
		"patch": map[string]any{"addTags": []string{"sprint-12"}}}, nil); code != http.StatusOK {
		t.Fatalf("bulk add tags: %d %s", code, body)
	}
	if got := findingByRule(t, h, "rule.a").Tags; len(got) != 2 || got[0] != "keep-me" || got[1] != "sprint-12" {
		t.Fatalf("a finding lost its own tags in a bulk add: %v", got)
	}
	if code, _ := h.callAs(sara, "PATCH", "/api/v1/findings/"+a.ID.String(), map[string]any{"removeTags": []string{"keep-me"}}, nil); code != http.StatusOK {
		t.Fatal("remove tag")
	}
	if got := findingByRule(t, h, "rule.a").Tags; len(got) != 1 || got[0] != "sprint-12" {
		t.Fatalf("remove: %v", got)
	}
	if code, _ := h.callAs(sara, "PATCH", "/api/v1/findings/"+a.ID.String(), map[string]any{"tags": []string{"x"}, "addTags": []string{"y"}}, nil); code != http.StatusBadRequest {
		t.Fatal("tags and addTags together must be refused")
	}

	// An unknown field is refused, not dropped: before, a bulk change by "ownr:none" reached every finding.
	if code, body := h.callAs(sara, "POST", "/api/v1/findings/bulk", map[string]any{"q": "ownr:none", "patch": map[string]any{"state": "under_investigation"}}, nil); code != http.StatusBadRequest {
		t.Fatalf("unknown field in bulk: %d %s", code, body)
	}
	if n := list(sara, "state:under_investigation"); n != 0 {
		t.Fatalf("the refused bulk changed %d findings", n)
	}
	// A value that cannot be read matches nothing.
	if n := list(sara, "cwe:abc"); n != 0 {
		t.Fatalf("cwe:abc matched %d", n)
	}
}
