package query_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/query"
)

// TestCrossTenantLeakIsolation satisfies Phase 0/1 exit criterion (docs/09 line 45, docs/16 line 334).
// Asserts that Tenant A can NEVER read, query, or mutate Tenant B's data across any endpoint.
func TestCrossTenantLeakIsolation(t *testing.T) {
	store := ingest.NewMemoryStore()
	api := query.NewAPI(store, nil)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	tenantA := domain.NewID()
	tenantB := domain.NewID()

	assetA := domain.NewID()
	assetB := domain.NewID()

	// 1. Seed Tenant A finding
	findingA := &domain.Finding{
		ID:                domain.NewID(),
		TenantID:          tenantA,
		AssetID:           assetA,
		FindingKey:        "key-tenant-a",
		Title:             "Tenant A Secret Exposed",
		Severity:          domain.SeverityCritical,
		State:             domain.StateOpen,
		RuleScannerFamily: "gitleaks",
		FirstSeen:         time.Now(),
		LastSeen:          time.Now(),
	}

	// 2. Seed Tenant B finding
	findingB := &domain.Finding{
		ID:                domain.NewID(),
		TenantID:          tenantB,
		AssetID:           assetB,
		FindingKey:        "key-tenant-b",
		Title:             "Tenant B Proprietary Vuln",
		Severity:          domain.SeverityHigh,
		State:             domain.StateOpen,
		RuleScannerFamily: "semgrep",
		FirstSeen:         time.Now(),
		LastSeen:          time.Now(),
	}

	_ = store.UpsertFindings(context.Background(), tenantA, []*domain.Finding{findingA})
	_ = store.UpsertFindings(context.Background(), tenantB, []*domain.Finding{findingB})

	// 3. Seed Tenant B SBOM
	sbomB := &domain.SBOM{
		ID:             domain.NewID(),
		TenantID:       tenantB,
		AssetID:        assetB,
		ComponentCount: 1,
	}
	compsB := []domain.SBOMComponent{
		{
			TenantID: tenantB,
			Name:     "internal-proprietary-lib",
			Version:  "1.0.0",
		},
	}
	_ = store.SaveSBOM(context.Background(), sbomB, compsB)

	// =========================================================================
	// Assertion 1: Tenant A lists findings -> must return ONLY Tenant A data
	// =========================================================================
	reqListA := httptest.NewRequest("GET", "/api/v1/findings", nil)
	reqListA.Header.Set("X-Tenant-ID", tenantA.String())
	recListA := httptest.NewRecorder()
	mux.ServeHTTP(recListA, reqListA)

	if recListA.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recListA.Code)
	}

	var resListA query.ListFindingsResponse
	_ = json.NewDecoder(recListA.Body).Decode(&resListA)
	if resListA.Total != 1 {
		t.Fatalf("expected 1 finding for Tenant A, got %d", resListA.Total)
	}
	if resListA.Items[0].Finding.ID != findingA.ID {
		t.Errorf("tenant A received unexpected finding: %v", resListA.Items[0].Finding.ID)
	}

	// =========================================================================
	// Assertion 2: Tenant A attempts to GET Tenant B's finding -> 404 Not Found
	// =========================================================================
	reqGetB := httptest.NewRequest("GET", "/api/v1/findings/"+findingB.ID.String(), nil)
	reqGetB.Header.Set("X-Tenant-ID", tenantA.String())
	recGetB := httptest.NewRecorder()
	mux.ServeHTTP(recGetB, reqGetB)

	if recGetB.Code != http.StatusNotFound {
		t.Errorf("LEAK DETECTED! Tenant A could access Tenant B finding: expected 404, got %d", recGetB.Code)
	}

	// =========================================================================
	// Assertion 3: Tenant A attempts to GET Tenant B's SBOM -> 404 Not Found
	// =========================================================================
	reqSbomB := httptest.NewRequest("GET", "/api/v1/assets/"+assetB.String()+"/sbom", nil)
	reqSbomB.Header.Set("X-Tenant-ID", tenantA.String())
	recSbomB := httptest.NewRecorder()
	mux.ServeHTTP(recSbomB, reqSbomB)

	if recSbomB.Code != http.StatusNotFound {
		t.Errorf("LEAK DETECTED! Tenant A could access Tenant B SBOM: expected 404, got %d", recSbomB.Code)
	}

	// =========================================================================
	// Assertion 4: Tenant A attempts to GET Tenant B's VEX -> empty statements
	// =========================================================================
	reqVexB := httptest.NewRequest("GET", "/api/v1/assets/"+assetB.String()+"/vex", nil)
	reqVexB.Header.Set("X-Tenant-ID", tenantA.String())
	recVexB := httptest.NewRecorder()
	mux.ServeHTTP(recVexB, reqVexB)

	var vexDoc struct {
		Statements []any `json:"statements"`
	}
	_ = json.NewDecoder(recVexB.Body).Decode(&vexDoc)
	if len(vexDoc.Statements) != 0 {
		t.Errorf("LEAK DETECTED! Tenant A received Tenant B VEX statements: %d", len(vexDoc.Statements))
	}

	// =========================================================================
	// Assertion 5: Tenant A attempts to PATCH Tenant B's finding -> 404 Not Found
	// =========================================================================
	reqPatchB := httptest.NewRequest("PATCH", "/api/v1/findings/"+findingB.ID.String(), strings.NewReader(`{"state":"not_affected"}`))
	reqPatchB.Header.Set("X-Tenant-ID", tenantA.String())
	recPatchB := httptest.NewRecorder()
	mux.ServeHTTP(recPatchB, reqPatchB)

	if recPatchB.Code != http.StatusNotFound {
		t.Errorf("LEAK DETECTED! Tenant A could patch Tenant B finding: expected 404, got %d", recPatchB.Code)
	}
}
