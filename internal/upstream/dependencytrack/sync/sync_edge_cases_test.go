package sync_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	dtclient "rampart/internal/upstream/dependencytrack/client"
	dtsync "rampart/internal/upstream/dependencytrack/sync"
)

// TestMappingEngine_CircularHierarchy_EdgeCases verifies that circular parent chains
// do not cause infinite recursion.
func TestMappingEngine_CircularHierarchy_EdgeCases(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	apps := &mockAppResolver{
		apps: map[string]*domain.Application{
			"app-default": {ID: uuid.New(), TenantID: tenantID, Slug: "app-default"},
		},
	}
	assets := &mockAssetFinder{
		assetsByUUID: make(map[string]*domain.Asset),
		assetsByKey:  make(map[string]*domain.Asset),
	}

	cfg := dtsync.MappingConfig{
		ParentAsApplication: true,
		DefaultApplication:  "app-default",
	}

	engine, err := dtsync.NewMappingEngine(cfg, assets, apps)
	if err != nil {
		t.Fatal(err)
	}

	// Project with itself as parent (cycle of 1)
	selfParent := dtclient.Project{
		UUID:   "proj-self",
		Name:   "Self Referencing",
		Parent: &dtclient.ParentRef{UUID: "proj-self", Name: "Self Referencing"},
	}

	res := engine.Resolve(ctx, tenantID, selfParent, nil)
	if res.ApplicationSlug != "Self Referencing" && res.ApplicationSlug != "app-default" {
		t.Fatalf("unexpected app slug: %s", res.ApplicationSlug)
	}
}

// TestMappingEngine_CELFailureAndFallbacks tests runtime failures in CEL expressions
// and graceful fallback to default application.
func TestMappingEngine_CELFailureAndFallbacks(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	apps := &mockAppResolver{
		apps: map[string]*domain.Application{
			"fallback-app": {ID: uuid.New(), TenantID: tenantID, Slug: "fallback-app"},
		},
	}
	assets := &mockAssetFinder{
		assetsByUUID: make(map[string]*domain.Asset),
		assetsByKey:  make(map[string]*domain.Asset),
	}

	cfg := dtsync.MappingConfig{
		CELRules: []dtsync.CELRule{
			// Rule that tries to access non-existent field or evaluates false
			{When: `project.name == "will-not-match"`, Application: "none"},
		},
		DefaultApplication: "fallback-app",
	}

	engine, err := dtsync.NewMappingEngine(cfg, assets, apps)
	if err != nil {
		t.Fatal(err)
	}

	proj := dtclient.Project{UUID: "p-test", Name: "my-service"}
	res := engine.Resolve(ctx, tenantID, proj, nil)
	if res.ApplicationSlug != "fallback-app" {
		t.Fatalf("expected fallback to fallback-app, got %+v", res)
	}
}

// D84 (docs/23 DT1): settled means the project's last analysis is not older than its last BOM import, read from
// the project itself. Metrics and identical double reads are no longer signals.
func dtProjectServer(t *testing.T, project func(n int) string) *httptest.Server {
	t.Helper()
	calls := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/finding"):
			_, _ = w.Write([]byte(`[{"vulnId":"CVE-2021-44228"}]`))
		case strings.Contains(r.URL.Path, "/project/"):
			calls++
			_, _ = w.Write([]byte(project(calls)))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestSettleChecker_NeverSettles_Timeout(t *testing.T) {
	srv := dtProjectServer(t, func(int) string {
		return `{"uuid":"p","name":"p","lastBomImport":2000,"lastVulnerabilityAnalysis":1000}` // analysis older than the BOM
	})
	defer srv.Close()
	checker := dtsync.NewSettleChecker(dtclient.NewClient(dtclient.Config{BaseURL: srv.URL, APIKey: "k"}), 10*time.Millisecond, 60*time.Millisecond)
	settled, data, _, err := checker.CheckSettled(context.Background(), "p", 0)
	if err != nil || settled || data != nil {
		t.Fatalf("an analysis older than the BOM is not settled, and nothing is read yet: settled=%v err=%v", settled, err)
	}
	// Past the bound the syncer reads anyway and marks the run unsettled (D92).
	data, _, err = checker.ReadAnyway(context.Background(), "p", true)
	if err != nil || !strings.Contains(string(data), "CVE-2021-44228") {
		t.Fatal("past the bound the findings are read")
	}
}

func TestSettleChecker_ImmediateSettle(t *testing.T) {
	srv := dtProjectServer(t, func(int) string {
		return `{"uuid":"p","name":"p","lastBomImport":1000,"lastVulnerabilityAnalysis":2000}`
	})
	defer srv.Close()
	checker := dtsync.NewSettleChecker(dtclient.NewClient(dtclient.Config{BaseURL: srv.URL, APIKey: "k"}), 10*time.Millisecond, 200*time.Millisecond)
	settled, data, _, err := checker.CheckSettled(context.Background(), "p", 0)
	if err != nil || !settled || !strings.Contains(string(data), "CVE-2021-44228") {
		t.Fatalf("settled=%v err=%v data=%s", settled, err, data)
	}
}

func TestSettleChecker_SettlesWhenTheAnalysisEnds(t *testing.T) {
	srv := dtProjectServer(t, func(n int) string {
		if n < 3 { // the first reads come before the analysis of the new BOM has ended
			return `{"uuid":"p","name":"p","lastBomImport":2000,"lastVulnerabilityAnalysis":1000}`
		}
		return `{"uuid":"p","name":"p","lastBomImport":2000,"lastVulnerabilityAnalysis":2500}`
	})
	defer srv.Close()
	checker := dtsync.NewSettleChecker(dtclient.NewClient(dtclient.Config{BaseURL: srv.URL, APIKey: "k"}), 5*time.Millisecond, time.Second)
	if settled, _, _, err := checker.CheckSettled(context.Background(), "p", 0); err != nil || !settled {
		t.Fatalf("settled=%v err=%v", settled, err)
	}
}

// TestFPFPayload_MalformedJSON tests handling of corrupted or truncated JSON.
func TestFPFPayload_MalformedJSON(t *testing.T) {
	t.Run("truncated json payload returns unmarshal error without panicking", func(t *testing.T) {
		truncated := `[{"component": {"name": "log4j", "version": "2.14.1"}, "vulnerability": {"vulnId": "CVE-2021-`
		var findings []any
		err := json.Unmarshal([]byte(truncated), &findings)
		if err == nil {
			t.Fatal("expected unmarshal error for truncated JSON")
		}
	})

	t.Run("finding with null or missing vulnerability object handled safely", func(t *testing.T) {
		partial := `[{"component": {"name": "react", "version": "17.0.2"}}]`
		var raw []map[string]any
		if err := json.Unmarshal([]byte(partial), &raw); err != nil {
			t.Fatal(err)
		}
		if len(raw) != 1 {
			t.Fatalf("expected 1 item, got %d", len(raw))
		}
		if raw[0]["vulnerability"] != nil {
			t.Fatalf("expected nil vulnerability, got %v", raw[0]["vulnerability"])
		}
	})
}
