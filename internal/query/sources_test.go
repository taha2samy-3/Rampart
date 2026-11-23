package query_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/query"
)

func TestApplicationSourcesAPI(t *testing.T) {
	ctx := context.Background()
	tenantA := uuid.MustParse("01931f6a-0000-7000-8000-000000000001")
	tenantB := uuid.MustParse("01931f6a-0000-7000-8000-000000000002")

	appA := uuid.New()
	appB := uuid.New()
	otherAppA := uuid.New()

	st := ingest.NewMemoryStore()
	_ = st.CreateApplication(ctx, &domain.Application{ID: appA, TenantID: tenantA, Name: "checkout", Slug: "checkout"})
	_ = st.CreateApplication(ctx, &domain.Application{ID: otherAppA, TenantID: tenantA, Name: "payments", Slug: "payments"})
	_ = st.CreateApplication(ctx, &domain.Application{ID: appB, TenantID: tenantB, Name: "billing", Slug: "billing"})

	authn := auth.NewAuthenticatorWithStore(st)
	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	viewerA, vrecA, _ := auth.GenerateToken(tenantA, auth.RoleViewer, "viewer-a", []string{"*"}, time.Hour)
	_ = st.SaveToken(ctx, vrecA)

	get := func(token, path string) (int, query.ApplicationScanSourcesResponse) {
		r := httptest.NewRequest("GET", path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var resp query.ApplicationScanSourcesResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp
	}

	// 1. Unauthenticated -> 401
	if code, _ := get("", "/api/v1/applications/"+appA.String()+"/sources"); code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized, got %d", code)
	}

	// 2. Tenant isolation: viewer from Tenant A tries to read Tenant B's application -> 404
	if code, _ := get(viewerA, "/api/v1/applications/"+appB.String()+"/sources"); code != http.StatusNotFound {
		t.Fatalf("expected 404 not found for tenant isolation, got %d", code)
	}

	// 3. Application not found -> 404
	if code, _ := get(viewerA, "/api/v1/applications/"+uuid.New().String()+"/sources"); code != http.StatusNotFound {
		t.Fatalf("expected 404 not found, got %d", code)
	}

	// 4. Application with no sources -> 200 with empty list
	code, resp := get(viewerA, "/api/v1/applications/"+appA.String()+"/sources")
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if len(resp.Sources) != 0 || resp.Total != 0 {
		t.Fatalf("expected 0 sources, got %d", resp.Total)
	}

	// 5. Add sources:
	// Source 1: bound to appA, multi-auth, categories sast + sca
	src1ID := uuid.New()
	st.SetScanSource(&domain.ScanSource{
		ID:            src1ID,
		TenantID:      tenantA,
		Name:          "checkout-ci",
		Type:          "upload",
		ScannerFamily: "semgrep",
		ApplicationID: appA,
		Categories:    []string{"sast", "sca"},
		Auth: domain.AuthSpec{
			TokenSecretRef: &domain.SecretRef{Name: "sec", Key: "tok"},
			Federation: &domain.FederationSpec{
				Issuer:      "https://token.actions.githubusercontent.com",
				BoundClaims: map[string]string{"repository": "org/checkout"},
			},
		},
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})

	// Add an ingest run for src1
	runID := uuid.New()
	_ = st.CreateIngestRun(ctx, &domain.IngestRun{
		ID:           runID,
		TenantID:     tenantA,
		ScanSourceID: src1ID,
		CreatedAt:    time.Now().Add(-1 * time.Hour),
	})

	// Source 2: bound to otherAppA (should not appear in appA query)
	st.SetScanSource(&domain.ScanSource{
		ID:            uuid.New(),
		TenantID:      tenantA,
		Name:          "payments-ci",
		ApplicationID: otherAppA,
		Categories:    []string{"all"},
		CreatedAt:     time.Now().Add(-1 * time.Hour),
	})

	// Source 3: bound to appA, disabled
	disabledAt := time.Now().Add(-10 * time.Minute)
	st.SetScanSource(&domain.ScanSource{
		ID:            uuid.New(),
		TenantID:      tenantA,
		Name:          "checkout-nightly",
		Type:          "apiPull",
		ApplicationID: appA,
		Categories:    []string{"dast"},
		DisabledAt:    &disabledAt,
		CreatedAt:     time.Now().Add(-24 * time.Hour),
	})

	// Query appA sources
	code, resp = get(viewerA, "/api/v1/applications/"+appA.String()+"/sources")
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if resp.Total != 2 || len(resp.Sources) != 2 {
		t.Fatalf("expected 2 sources for appA, got %d", resp.Total)
	}

	// First source should be checkout-ci (sorted by name)
	s1 := resp.Sources[0]
	if s1.Name != "checkout-ci" {
		t.Errorf("expected first source name checkout-ci, got %s", s1.Name)
	}
	if s1.AuthType != "multi" {
		t.Errorf("expected authType multi, got %s", s1.AuthType)
	}
	if !s1.Active {
		t.Errorf("expected checkout-ci to be active")
	}
	if s1.TotalRuns != 1 {
		t.Errorf("expected 1 total run, got %d", s1.TotalRuns)
	}
	if s1.LastScanAt == nil {
		t.Errorf("expected last scan at to be set")
	}

	// Second source should be checkout-nightly (disabled)
	s2 := resp.Sources[1]
	if s2.Name != "checkout-nightly" {
		t.Errorf("expected second source name checkout-nightly, got %s", s2.Name)
	}
	if s2.Active {
		t.Errorf("expected checkout-nightly to be inactive/disabled")
	}
	if s2.Type != "apiPull" {
		t.Errorf("expected type apiPull, got %s", s2.Type)
	}
}
