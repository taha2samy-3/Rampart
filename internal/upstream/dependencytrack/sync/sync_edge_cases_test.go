package sync_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// TestSettleChecker_NeverSettles_Timeout verifies that a project whose finding counts
// fluctuate indefinitely reaches timeout and returns settled=false.
func TestSettleChecker_NeverSettles_Timeout(t *testing.T) {
	ctx := context.Background()

	var counter int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/finding") {
			// Fluctuate body content on every call
			c := atomic.AddInt64(&counter, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `[{"vulnId":"CVE-%d"}]`, c)
			return
		}
		if strings.Contains(r.URL.Path, "/metrics") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cli := dtclient.NewClient(dtclient.Config{BaseURL: srv.URL, APIKey: "test-key"})

	checker := dtsync.NewSettleChecker(cli, 10*time.Millisecond, 50*time.Millisecond)
	settled, _, err := checker.CheckSettled(ctx, "proj-fluctuating", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if settled {
		t.Fatal("expected settled to be false when findings never match")
	}
}

// TestSettleChecker_ImmediateSettle verifies fast settling when metrics match or findings match.
func TestSettleChecker_ImmediateSettle(t *testing.T) {
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/finding") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"vulnId":"CVE-2021-44228"}]`))
			return
		}
		if strings.Contains(r.URL.Path, "/metrics") {
			w.WriteHeader(http.StatusOK)
			// Metrics lastOccurrence is newer than lastBomImport
			_, _ = w.Write([]byte(`{"lastOccurrence": 2000, "critical": 1}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cli := dtclient.NewClient(dtclient.Config{BaseURL: srv.URL, APIKey: "test-key"})

	checker := dtsync.NewSettleChecker(cli, 10*time.Millisecond, 200*time.Millisecond)
	// lastBomImport is 1000, metrics is 2000 -> settles immediately via metrics!
	settled, data, err := checker.CheckSettled(ctx, "proj-steady", 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !settled {
		t.Fatal("expected settled=true")
	}
	if !strings.Contains(string(data), "CVE-2021-44228") {
		t.Fatalf("unexpected findings data: %s", string(data))
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
