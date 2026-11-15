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
	"rampart/internal/query"
)

func TestParsersAPI_List(t *testing.T) {
	tenantID := uuid.New()
	st := ingest.NewMemoryStore()
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
	if res.Total < 19 {
		t.Errorf("expected at least 19 parsers, got %d", res.Total)
	}

	// 2. Unauthorized request returns 401
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/v1/parsers", nil)
	unauthW := httptest.NewRecorder()
	mux.ServeHTTP(unauthW, unauthReq)
	if unauthW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthW.Code)
	}
}
