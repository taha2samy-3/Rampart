package query_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/ingest"
	"rampart/internal/query"

	"github.com/google/uuid"
)

// A NUL in a filter, a note or a tag reached PostgreSQL, which cannot store it: the API answered HTTP 500 for
// what is a bad request. It answers 400 before any handler runs.
func TestAPI_NULIsABadRequestNotAServerError(t *testing.T) {
	store := ingest.NewMemoryStore()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(store)
	token := authn.DefaultAdminToken(tenantID)
	mux := http.NewServeMux()
	query.NewAPIWithAuth(store, nil, authn).RegisterRoutes(mux)

	cases := []struct{ name, method, url, body string }{
		{"query %00", "GET", "/api/v1/findings?q=a%00b", ""},
		{"query key %00", "GET", "/api/v1/findings?a%00=1", ""},
		{"note \\u0000", "PATCH", "/api/v1/findings/" + uuid.NewString(), `{"note":"a\u0000b"}`},
		{"tag raw NUL", "PATCH", "/api/v1/findings/" + uuid.NewString(), "{\"tags\":[\"a\x00\"]}"},
		{"bulk \\u0000", "POST", "/api/v1/findings/bulk", `{"q":"x\u0000","addTags":["t"]}`},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.url, strings.NewReader(c.body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", c.name, rec.Code, rec.Body.String())
		}
	}

	// A body without a NUL is passed on whole (the handler reads what the middleware read).
	req := httptest.NewRequest("POST", "/api/v1/findings/bulk", strings.NewReader(`{"ids":[],"addTags":["t"]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "ids or q") {
		t.Errorf("a clean body must reach the handler (want its own 400 about ids or q): %d %s", rec.Code, rec.Body.String())
	}
}

// format=sarif (or any name the API does not write) returned the JSON export; an empty page was "items":null.
func TestAPI_ExportFormatAndEmptyPage(t *testing.T) {
	store := ingest.NewMemoryStore()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(store)
	token := authn.DefaultAdminToken(tenantID)
	mux := http.NewServeMux()
	query.NewAPIWithAuth(store, nil, authn).RegisterRoutes(mux)
	get := func(url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	for _, f := range []string{"sarif", "bogus", "xml"} {
		if rec := get("/api/v1/findings/export?format=" + f); rec.Code != http.StatusBadRequest {
			t.Errorf("format=%s: want 400, got %d", f, rec.Code)
		}
	}
	for _, f := range []string{"", "json", "csv", "ocsf", "CSV"} {
		// The in-memory store cannot run the query (501); what matters is that the name is accepted.
		if rec := get("/api/v1/findings/export?format=" + f); rec.Code == http.StatusBadRequest {
			t.Errorf("format=%q must be accepted, got 400: %s", f, rec.Body.String())
		}
	}
	if rec := get("/api/v1/findings?q=severity:critical"); !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Errorf("an empty page must list [], got %s", rec.Body.String())
	}
}
