package query_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/parsertest"
	"rampart/internal/query"
)

func TestParsersAPI_List(t *testing.T) {
	tenantID := uuid.New()
	st := ingest.NewMemoryStore()
	// The server knows no parser: with nothing installed the list is empty, and what the control plane stores is what is listed.
	for _, m := range parsertest.Manifests(t) {
		st.SaveClusterParser(m.Name, m.Stored)
	}
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)

	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// 1. Authorized GET /api/v1/parsers
	req := httptest.NewRequest(http.MethodGet, "/api/v1/parsers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var res struct {
		Parsers []map[string]any `json:"parsers"`
		Total   int              `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Total != 20 {
		t.Errorf("expected the 17 report parsers and 3 SBOM readers that were installed, got %d", res.Total)
	}
	ids := map[string]bool{}
	for _, p := range res.Parsers {
		ids[p["id"].(string)] = true
	}
	for _, want := range []string{"builtin:trivy", "builtin:sarif", "builtin:genericjson", "builtin:sbom-spdx", "builtin:sbom-cyclonedx", "builtin:sbom-syft"} {
		if !ids[want] {
			t.Errorf("%s is installed and must be listed with the id the runs and the compliance report use: %v", want, ids)
		}
	}

	// 2. Unauthorized request returns 401
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/v1/parsers", nil)
	unauthW := httptest.NewRecorder()
	mux.ServeHTTP(unauthW, unauthReq)
	if unauthW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthW.Code)
	}
}

// A server that was given no parser has none to list: nothing is compiled in.
func TestParsersAPI_ListIsEmptyWhenNothingIsInstalled(t *testing.T) {
	tenantID := uuid.New()
	st := ingest.NewMemoryStore()
	authn := auth.NewAuthenticatorWithStore(st)
	mux := http.NewServeMux()
	query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn).RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/parsers", nil)
	req.Header.Set("Authorization", "Bearer "+authn.DefaultAdminToken(tenantID))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var res struct {
		Parsers []any `json:"parsers"`
		Total   int   `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if res.Total != 0 || res.Parsers == nil || len(res.Parsers) != 0 {
		t.Fatalf("an empty server lists an empty list (never null): %s", w.Body.String())
	}
}
