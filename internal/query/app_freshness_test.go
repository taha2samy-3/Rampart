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

func TestApplicationFreshness(t *testing.T) {
	ctx := context.Background()
	tenantA := uuid.MustParse("01931f6a-0000-7000-8000-000000000001")
	tenantB := uuid.MustParse("01931f6a-0000-7000-8000-000000000002")

	appA := uuid.New()
	appB := uuid.New()
	assetA := uuid.New()

	st := ingest.NewMemoryStore()
	_ = st.CreateApplication(ctx, &domain.Application{ID: appA, TenantID: tenantA, Name: "checkout", Slug: "checkout"})
	_ = st.CreateApplication(ctx, &domain.Application{ID: appB, TenantID: tenantB, Name: "billing", Slug: "billing"})

	_ = st.CreateAsset(ctx, &domain.Asset{
		ID:            assetA,
		TenantID:      tenantA,
		ApplicationID: &appA,
		Type:          domain.AssetRepository,
		Key:           "checkout-repo",
		DisplayName:   "checkout-service",
	})

	authn := auth.NewAuthenticatorWithStore(st)
	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	viewerA, vrecA, _ := auth.GenerateToken(tenantA, auth.RoleViewer, "viewer-a", []string{"*"}, time.Hour)
	_ = st.SaveToken(ctx, vrecA)

	get := func(token, path string) (int, query.ApplicationFreshnessResponse) {
		r := httptest.NewRequest("GET", path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var resp query.ApplicationFreshnessResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp
	}

	// 1. Unauthenticated -> 401
	if code, _ := get("", "/api/v1/applications/"+appA.String()+"/freshness"); code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized, got %d", code)
	}

	// 2. Tenant isolation: viewer from Tenant A tries to read Tenant B's application -> 404
	if code, _ := get(viewerA, "/api/v1/applications/"+appB.String()+"/freshness"); code != http.StatusNotFound {
		t.Fatalf("expected 404 not found for tenant isolation, got %d", code)
	}

	// 3. Non-existent app or invalid UUID -> 404
	if code, _ := get(viewerA, "/api/v1/applications/"+uuid.New().String()+"/freshness"); code != http.StatusNotFound {
		t.Fatalf("expected 404 for random app, got %d", code)
	}
	if code, _ := get(viewerA, "/api/v1/applications/not-a-uuid/freshness"); code != http.StatusNotFound {
		t.Fatalf("expected 404 for bad id, got %d", code)
	}

	// 4. App with no SBOM yet
	code, resp := get(viewerA, "/api/v1/applications/"+appA.String()+"/freshness")
	if code != http.StatusOK {
		t.Fatalf("expected 200 for app without sbom, got %d", code)
	}
	if resp.SBOM != nil {
		t.Fatalf("expected nil SBOM, got %+v", resp.SBOM)
	}
	if len(resp.Analyzers) != 0 {
		t.Fatalf("expected 0 analyzers without SBOM, got %d", len(resp.Analyzers))
	}
	if len(resp.Feeds) == 0 {
		t.Fatalf("expected feeds list to be populated")
	}

	// 5. App with SBOM and active/completed/failed analyzers
	sbomID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	sbom := &domain.SBOM{
		ID:             sbomID,
		TenantID:       tenantA,
		AssetID:        assetA,
		Format:         "cyclonedx",
		ComponentCount: 5,
		Track:          "main",
		CreatedAt:      now.Add(-2 * time.Hour),
	}
	components := []domain.SBOMComponent{
		{TenantID: tenantA, SBOMID: sbomID, Ref: "pkg:npm/react@18.2.0", Name: "react", Version: "18.2.0"},
		{TenantID: tenantA, SBOMID: sbomID, Ref: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21"},
	}
	if err := st.SaveSBOM(ctx, sbom, components); err != nil {
		t.Fatalf("SaveSBOM failed: %v", err)
	}

	finishedAt := now.Add(-30 * time.Minute)
	startedAt := now.Add(-5 * time.Minute)

	// Save a completed analysis
	_ = st.SaveSBOMAnalysis(ctx, domain.SBOMAnalysis{
		TenantID:   tenantA,
		SBOMID:     sbomID,
		Analyzer:   domain.AnalyzerRef{Kind: "sbom", Scope: "cluster", Name: "built-in-matcher"},
		State:      domain.AnalysisCompleted,
		Trigger:    domain.TriggerUpload,
		Findings:   4,
		Created:    4,
		Closed:     0,
		FinishedAt: &finishedAt,
		CreatedAt:  now.Add(-35 * time.Minute),
		UpdatedAt:  finishedAt,
	})

	// Save an in-flight analysis
	_ = st.SaveSBOMAnalysis(ctx, domain.SBOMAnalysis{
		TenantID:  tenantA,
		SBOMID:    sbomID,
		Analyzer:  domain.AnalyzerRef{Kind: "external", Scope: "cluster", Name: "sonatype-oss-index"},
		State:     domain.AnalysisRunning,
		Trigger:   domain.TriggerManual,
		StartedAt: &startedAt,
		CreatedAt: startedAt,
		UpdatedAt: startedAt,
	})

	// Save a failed analysis
	_ = st.SaveSBOMAnalysis(ctx, domain.SBOMAnalysis{
		TenantID:   tenantA,
		SBOMID:     sbomID,
		Analyzer:   domain.AnalyzerRef{Kind: "external", Scope: "tenant", Name: "custom-analyzer"},
		State:      domain.AnalysisFailed,
		Trigger:    domain.TriggerScheduled,
		Error:      "dial tcp 10.0.0.5:50051: connect: connection refused",
		Findings:   1,
		FinishedAt: &finishedAt,
		CreatedAt:  now.Add(-40 * time.Minute),
		UpdatedAt:  finishedAt,
	})

	code, resp = get(viewerA, "/api/v1/applications/"+appA.String()+"/freshness")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if resp.SBOM == nil {
		t.Fatalf("expected non-nil SBOM")
	}
	if resp.SBOM.Components != 5 {
		t.Fatalf("expected 5 components, got %d", resp.SBOM.Components)
	}
	if len(resp.Analyzers) != 3 {
		t.Fatalf("expected 3 analyzers, got %d", len(resp.Analyzers))
	}

	// Verify each analyzer
	var completed, running, failed *query.FreshnessAnalyzer
	for i := range resp.Analyzers {
		a := &resp.Analyzers[i]
		switch a.Name {
		case "built-in-matcher":
			completed = a
		case "sonatype-oss-index":
			running = a
		case "custom-analyzer":
			failed = a
		}
	}

	if completed == nil || completed.State != "completed" || completed.Findings != 4 || completed.LastAnalysedAt == nil || completed.InProgressSince != nil {
		t.Fatalf("unexpected completed analyzer state: %+v", completed)
	}

	if running == nil || running.State != "running" || running.InProgressSince == nil || running.LastAnalysedAt != nil {
		t.Fatalf("unexpected running analyzer state: %+v", running)
	}

	if failed == nil || failed.State != "failed" || failed.Error == "" || failed.Findings != 1 {
		t.Fatalf("unexpected failed analyzer state: %+v", failed)
	}
}
