package store_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/enrich"
	"rampart/internal/query"
)

func TestAuditLog_RecordsMutationsAndIsAppendOnly(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	ingestRules(t, h, map[string]string{"rule.a": "9.5"}, "main")
	ids := findingIDs(t, h)
	sara := h.tokenFor(auth.RoleTriager, "sara@acme.example")
	viewer := h.tokenFor(auth.RoleViewer, "viewer@acme.example")
	boss := h.tokenFor(auth.RoleAdmin, "boss@acme.example")

	authn := auth.NewAuthenticatorWithStore(h.store)
	api := query.NewAPIWithAuth(h.store, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	srv := httptest.NewServer(api.Audited(mux))
	defer srv.Close()
	do := func(token, method, path string, body string) (int, string, http.Header) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b), res.Header
	}
	type page struct {
		Items []struct {
			Actor, Action string
			ResourceType  string `json:"resource_type"`
			ResourceID    string `json:"resource_id"`
			Detail        struct{ Status int }
		}
		NextCursor string `json:"next_cursor"`
	}
	read := func(path string) page {
		code, body, _ := do(boss, "GET", path, "")
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, code, body)
		}
		var p page
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if code, body, _ := do(sara, "PATCH", "/api/v1/findings/"+ids["rule.a"].String(), `{"state":"under_investigation"}`); code != http.StatusOK {
		t.Fatalf("triage: %d %s", code, body)
	}
	// A refused call is recorded too, with its status; an unauthenticated one has no tenant and is not.
	do(viewer, "PATCH", "/api/v1/findings/"+ids["rule.a"].String(), `{"state":"fixed"}`)
	do("", "PATCH", "/api/v1/findings/"+ids["rule.a"].String(), `{"state":"fixed"}`)
	do(sara, "GET", "/api/v1/findings", "") // a read is not an audit event

	p := read("/api/v1/audit")
	if len(p.Items) != 2 {
		t.Fatalf("want the two authenticated mutations, got %+v", p.Items)
	}
	newest, oldest := p.Items[0], p.Items[1]
	if oldest.Actor != "user:sara@acme.example" || oldest.Action != "PATCH /api/v1/findings/{id}" || oldest.ResourceType != "findings" || oldest.ResourceID != ids["rule.a"].String() || oldest.Detail.Status != 200 {
		t.Fatalf("the triage call: %+v", oldest)
	}
	if newest.Actor != "user:viewer@acme.example" || newest.Detail.Status != http.StatusForbidden {
		t.Fatalf("the refused call: %+v", newest)
	}

	// Only an administrator reads it.
	for _, tok := range []string{viewer, sara} {
		if code, _, _ := do(tok, "GET", "/api/v1/audit", ""); code != http.StatusForbidden {
			t.Fatalf("a non-admin read the audit log: %d", code)
		}
	}
	if code, _, _ := do("", "GET", "/api/v1/audit", ""); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", code)
	}

	// Filters, paging and export.
	if f := read("/api/v1/audit?actor=user:sara@acme.example"); len(f.Items) != 1 {
		t.Fatalf("filter by actor: %+v", f.Items)
	}
	if f := read("/api/v1/audit?action=PATCH"); len(f.Items) != 2 {
		t.Fatalf("filter by action: %+v", f.Items)
	}
	first := read("/api/v1/audit?limit=1")
	if len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first page: %+v", first)
	}
	second := read("/api/v1/audit?limit=1&cursor=" + first.NextCursor)
	if len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].Actor != oldest.Actor {
		t.Fatalf("second page: %+v", second)
	}
	if code, _, _ := do(boss, "GET", "/api/v1/audit?cursor=garbage", ""); code != http.StatusBadRequest {
		t.Fatalf("a bad cursor: %d", code)
	}
	code, body, hdr := do(boss, "GET", "/api/v1/audit?format=csv", "")
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/csv") || !strings.HasPrefix(body, "at,actor,action,") || !strings.Contains(body, "user:sara@acme.example") {
		t.Fatalf("csv: %d %q", code, body)
	}
	if code, body, _ := do(boss, "GET", "/api/v1/audit?format=ndjson", ""); code != http.StatusOK || len(strings.Split(strings.TrimSpace(body), "\n")) != 2 {
		t.Fatalf("ndjson: %d %q", code, body)
	}

	// Append-only: neither the application role nor the system role can change or remove a row.
	for name, exec := range map[string]func(sql string) error{
		"app":    func(sql string) error { _, err := h.store.Pool().Exec(ctx, sql); return err },
		"system": func(sql string) error { _, err := h.pool.Exec(ctx, sql); return err },
	} {
		for _, sql := range []string{`UPDATE audit_event SET action = 'x'`, `DELETE FROM audit_event`, `TRUNCATE audit_event`} {
			err := exec(sql)
			if err == nil || !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("%s role ran %q: err = %v", name, sql, err)
			}
		}
	}
}
