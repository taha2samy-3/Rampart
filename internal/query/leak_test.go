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
	"rampart/internal/ingest"
	"rampart/internal/query"
)

// TestCrossTenantLeakIsolation satisfies Phase 0/1 exit criterion (docs/09 line 45, docs/16 line 334).
// Asserts that Tenant A can NEVER read, query, or mutate Tenant B's data across any endpoint,
// and proves that blind trust of X-Tenant-ID is completely eliminated (Security A).
func TestCrossTenantLeakIsolation(t *testing.T) {
	store := ingest.NewMemoryStore()
	authn := auth.NewAuthenticatorWithStore(store)
	api := query.NewAPIWithAuth(store, nil, authn)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	tenantA := domain.NewID()
	tenantB := domain.NewID()

	tokenA := authn.DefaultAdminToken(tenantA)
	tokenB := authn.DefaultAdminToken(tenantB)

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
	// Even if Tenant A injects "X-Tenant-ID: <tenantB>", it is ignored!
	// =========================================================================
	reqListA := httptest.NewRequest("GET", "/api/v1/findings", nil)
	reqListA.Header.Set("Authorization", "Bearer "+tokenA)
	reqListA.Header.Set("X-Tenant-ID", tenantB.String()) // Malicious spoof attempt
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
	// Assertion 2: Tenant A requests Tenant B's finding ID directly -> 404
	// =========================================================================
	reqGetB := httptest.NewRequest("GET", "/api/v1/findings/"+findingB.ID.String(), nil)
	reqGetB.Header.Set("Authorization", "Bearer "+tokenA)
	recGetB := httptest.NewRecorder()
	mux.ServeHTTP(recGetB, reqGetB)

	if recGetB.Code != http.StatusNotFound {
		t.Fatalf("LEAK DETECTED! Tenant A could view Tenant B's finding: status %d", recGetB.Code)
	}

	// =========================================================================
	// Assertion 3: Tenant A requests Tenant B's SBOM -> 404
	// =========================================================================
	reqSBOM := httptest.NewRequest("GET", "/api/v1/assets/"+assetB.String()+"/sbom", nil)
	reqSBOM.Header.Set("Authorization", "Bearer "+tokenA)
	recSBOM := httptest.NewRecorder()
	mux.ServeHTTP(recSBOM, reqSBOM)

	if recSBOM.Code != http.StatusNotFound {
		t.Fatalf("LEAK DETECTED! Tenant A could view Tenant B's SBOM: status %d", recSBOM.Code)
	}

	// =========================================================================
	// Assertion 4: Tenant A tries to PATCH Tenant B's finding -> 404
	// =========================================================================
	patchPayload := `{"state":"not_affected","justification":"tampered"}`
	reqPatch := httptest.NewRequest("PATCH", "/api/v1/findings/"+findingB.ID.String(), strings.NewReader(patchPayload))
	reqPatch.Header.Set("Authorization", "Bearer "+tokenA)
	recPatch := httptest.NewRecorder()
	mux.ServeHTTP(recPatch, reqPatch)

	if recPatch.Code != http.StatusNotFound {
		t.Fatalf("LEAK DETECTED! Tenant A could mutate Tenant B's finding: status %d", recPatch.Code)
	}

	// Verify Tenant B's finding was untouched
	storedB, _, _ := store.GetFinding(context.Background(), tenantB, findingB.ID)
	if storedB.State != domain.StateOpen {
		t.Fatalf("tampering succeeded on Tenant B's finding! State: %v", storedB.State)
	}

	// =========================================================================
	// Assertion 5: Tenant B can successfully access its own finding with tokenB
	// =========================================================================
	reqValidB := httptest.NewRequest("GET", "/api/v1/findings/"+findingB.ID.String(), nil)
	reqValidB.Header.Set("Authorization", "Bearer "+tokenB)
	recValidB := httptest.NewRecorder()
	mux.ServeHTTP(recValidB, reqValidB)

	if recValidB.Code != http.StatusOK {
		t.Fatalf("expected Tenant B to access its own finding: got %d", recValidB.Code)
	}
}
