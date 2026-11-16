package query_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/query"
)

// D80: a CI ingest token reaches only the gate on the query API. Before, most read routes checked only the tenant,
// so a 15-minute federated token could read every finding of the tenant.
func TestIngestTokenReachesOnlyTheGate(t *testing.T) {
	st := ingest.NewMemoryStore()
	authn := auth.NewAuthenticatorWithStore(st)
	tenantID := domain.NewID()
	ci := auth.FormatToken(tenantID, "ci_ingest_token_for_guard_test_1")
	authn.RegisterToken(ci, &auth.TokenRecord{ID: domain.NewID(), TenantID: tenantID, Subject: "github:acme/shop", Role: auth.RoleIngest, CreatedAt: time.Now().UTC()})
	viewer := auth.FormatToken(tenantID, "viewer_token_for_guard_test_123")
	authn.RegisterToken(viewer, &auth.TokenRecord{ID: domain.NewID(), TenantID: tenantID, Subject: "reader", Role: auth.RoleViewer, CreatedAt: time.Now().UTC()})

	mux := http.NewServeMux()
	query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn).RegisterRoutes(mux)
	call := func(tok, method, path, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}

	for _, path := range []string{"/api/v1/findings", "/api/v1/applications", "/api/v1/risk-acceptances", "/api/v1/runs", "/api/v1/findings/export?format=csv"} {
		if code := call(ci, http.MethodGet, path, ""); code != http.StatusForbidden {
			t.Errorf("GET %s with an ingest token: want 403, got %d", path, code)
		}
	}
	if code := call(ci, http.MethodPost, "/api/v1/gate", `{"context":{"commit":"abc"},"expect":["semgrep"]}`); code == http.StatusForbidden {
		t.Error("the gate must stay open to the CI token that uploaded")
	}
	if code := call(viewer, http.MethodGet, "/api/v1/findings", ""); code != http.StatusOK {
		t.Errorf("a viewer must still read findings, got %d", code)
	}
}
