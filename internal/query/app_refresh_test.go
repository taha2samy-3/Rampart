package query_test

import (
	"context"
	"encoding/json"
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

	"github.com/google/uuid"
)

type refreshMockDispatcher struct {
	hasSBOM bool
	n       int
	err     error
}

func (d *refreshMockDispatcher) DispatchAnalyzer(_ context.Context, _ uuid.UUID, _ domain.AnalyzerRef, _ domain.AnalysisTrigger) (int, error) {
	return 0, nil
}

func (d *refreshMockDispatcher) DispatchAsset(_ context.Context, _, _ uuid.UUID, _ domain.AnalysisTrigger) (int, error) {
	if !d.hasSBOM {
		return 0, nil
	}
	return d.n, d.err
}

// "Scan this application" triggers native vulnerability matching.
func TestRefreshVulnerabilities(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	appA, appB := uuid.New(), uuid.New()
	st := ingest.NewMemoryStore()
	_ = st.CreateApplication(ctx, &domain.Application{ID: appA, TenantID: tenantID, Name: "payments", Slug: "payments"})
	_ = st.CreateApplication(ctx, &domain.Application{ID: appB, TenantID: tenantID, Name: "search", Slug: "search"})
	authn := auth.NewAuthenticatorWithStore(st)
	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// a triager on payments only
	tri, rec, _ := auth.GenerateToken(tenantID, auth.RoleViewer, "pay-tri", []string{"*"}, time.Hour)
	_ = st.SaveToken(ctx, rec)
	_ = st.UpsertAccessBinding(ctx, tenantID, &domain.AccessBinding{ID: uuid.New(), Subject: "pay-tri", Role: "triager", ApplicationID: appA})
	viewer, vrec, _ := auth.GenerateToken(tenantID, auth.RoleViewer, "plain", []string{"*"}, time.Hour)
	_ = st.SaveToken(ctx, vrec)

	post := func(token, path, body string) (int, query.RefreshResponse) {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var resp query.RefreshResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp
	}

	if c, _ := post(viewer, "/api/v1/applications/"+appA.String()+"/refresh-vulnerabilities", ""); c != http.StatusForbidden {
		t.Fatalf("a viewer: %d", c)
	}
	if c, _ := post(tri, "/api/v1/applications/"+appB.String()+"/refresh-vulnerabilities", ""); c != http.StatusForbidden {
		t.Fatalf("a triager on payments cannot refresh search: %d", c)
	}
	// With analysis dispatcher nil: answers 202 with analysis disabled message
	if c, resp := post(tri, "/api/v1/applications/"+appA.String()+"/refresh-vulnerabilities", ""); c != http.StatusAccepted || resp.Status != "idle" {
		t.Fatalf("expected accepted idle when analysis nil: %d %v", c, resp)
	}
	if c, _ := post(authn.DefaultAdminToken(tenantID), "/api/v1/applications/"+uuid.New().String()+"/refresh-vulnerabilities", ""); c != http.StatusNotFound {
		t.Fatalf("an application that does not exist: %d", c)
	}
	if c, _ := post(authn.DefaultAdminToken(tenantID), "/api/v1/applications/not-an-id/refresh-vulnerabilities", ""); c != http.StatusBadRequest {
		t.Fatalf("a bad id: %d", c)
	}

	// Now with dispatcher and an SBOM
	disp := &refreshMockDispatcher{hasSBOM: false, n: 2}
	api.SetAnalysisDispatcher(disp)

	// App with no SBOM
	if c, resp := post(tri, "/api/v1/applications/"+appA.String()+"/refresh-vulnerabilities", ""); c != http.StatusAccepted || resp.Status != "idle" || resp.Message != "Nothing to check: no SBOM" {
		t.Fatalf("expected idle no sbom: %d %v", c, resp)
	}

	// Store an SBOM for appA
	disp.hasSBOM = true
	_ = st.SaveSBOM(ctx, &domain.SBOM{ID: uuid.New(), TenantID: tenantID, AssetID: appA, Format: "cyclonedx"}, nil)

	// Dispatcher queues 2 analyses
	if c, resp := post(tri, "/api/v1/applications/"+appA.String()+"/refresh-vulnerabilities", ""); c != http.StatusAccepted || resp.Status != "started" || resp.Queued != 2 {
		t.Fatalf("expected started with 2 queued: %d %v", c, resp)
	}

	// Dispatcher queues 0 (already running)
	disp.n = 0
	if c, resp := post(tri, "/api/v1/applications/"+appA.String()+"/refresh-vulnerabilities", ""); c != http.StatusAccepted || resp.Status != "in_progress" || resp.Queued != 0 {
		t.Fatalf("expected in_progress when already running: %d %v", c, resp)
	}

	// Test Cooldown (docs/39 Slice D.2)
	now := time.Now()
	twoMinAgo := now.Add(-2 * time.Minute)
	sbomA := uuid.New()
	_ = st.SaveSBOM(ctx, &domain.SBOM{ID: sbomA, TenantID: tenantID, AssetID: appA, Format: "cyclonedx"}, nil)
	_ = st.SaveSBOMAnalysis(ctx, domain.SBOMAnalysis{
		TenantID:   tenantID,
		SBOMID:     sbomA,
		Analyzer:   domain.AnalyzerRef{Kind: "sbom", Name: "osv"},
		State:      domain.AnalysisCompleted,
		Trigger:    domain.TriggerManual,
		FinishedAt: &twoMinAgo,
	})

	api.SetAnalysisLimits(50, 5*time.Minute)
	if c, resp := post(tri, "/api/v1/applications/"+appA.String()+"/refresh-vulnerabilities", ""); c != http.StatusAccepted || resp.Status != "cooldown" || resp.CooldownUntil == "" {
		t.Fatalf("expected cooldown response: code=%d resp=%v", c, resp)
	}

	// Test In-Flight Limit (docs/39 Slice D.3): cap manual work across the platform with 429 Retry-After
	api.SetAnalysisLimits(1, time.Nanosecond) // cooldown immediately elapsed, but in-flight limit = 1
	// Claim one analysis in flight
	_, _ = st.ClaimSBOMAnalysis(ctx, domain.SBOMAnalysis{
		TenantID: tenantID,
		SBOMID:   sbomA,
		Analyzer: domain.AnalyzerRef{Kind: "external", Name: "sonatype-oss-index"},
		Trigger:  domain.TriggerUpload,
	}, time.Hour)

	r := httptest.NewRequest("POST", "/api/v1/applications/"+appA.String()+"/refresh-vulnerabilities", nil)
	r.Header.Set("Authorization", "Bearer "+tri)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when maxInFlight reached, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Retry-After") != "30" {
		t.Fatalf("expected Retry-After 30, got %q", w.Header().Get("Retry-After"))
	}

	// Reset limits
	api.SetAnalysisLimits(50, time.Nanosecond)

	// the per-package button needs triage rights too
	if c, _ := post(viewer, "/api/v1/inventory/components/scan", `{"purl":"pkg:npm/lodash@4"}`); c != http.StatusForbidden {
		t.Fatalf("a viewer cannot re-score the tenant: %d", c)
	}
}
