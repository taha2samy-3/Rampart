package query_test

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
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/query"
)

func TestQueryAPIFindings(t *testing.T) {
	store := ingest.NewMemoryStore()
	feeds := enrich.NewFeedStore()
	api := query.NewAPI(store, feeds)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	cveStr := "CVE-2021-44228"

	// Seed 3 findings
	f1ID := domain.NewID()
	f1 := &domain.Finding{
		ID:                f1ID,
		TenantID:          tenantID,
		FindingKey:        "key-1",
		RuleID:            "log4shell",
		Title:             "Log4Shell RCE",
		Severity:          domain.SeverityCritical,
		State:             domain.StateOpen,
		RiskScore:         900,
		VulnerabilityID:   &cveStr,
		RuleScannerFamily: "trivy",
		FirstSeen:         time.Now().Add(-10 * 24 * time.Hour),
		LastSeen:          time.Now(),
	}

	f2ID := domain.NewID()
	f2 := &domain.Finding{
		ID:                f2ID,
		TenantID:          tenantID,
		FindingKey:        "key-2",
		RuleID:            "hardcoded-secret",
		Title:             "AWS Secret Key",
		Severity:          domain.SeverityHigh,
		State:             domain.StateFixed,
		RiskScore:         650,
		RuleScannerFamily: "gitleaks",
		FirstSeen:         time.Now().Add(-5 * 24 * time.Hour),
		LastSeen:          time.Now(),
	}

	f3ID := domain.NewID()
	f3 := &domain.Finding{
		ID:                f3ID,
		TenantID:          tenantID,
		FindingKey:        "key-3",
		RuleID:            "missing-header",
		Title:             "X-Content-Type-Options missing",
		Severity:          domain.SeverityLow,
		State:             domain.StateOpen,
		RiskScore:         80,
		RuleScannerFamily: "zap",
		FirstSeen:         time.Now().Add(-1 * 24 * time.Hour),
		LastSeen:          time.Now(),
	}

	_ = store.UpsertFindings(context.Background(), tenantID, []*domain.Finding{f1, f2, f3})

	// 1. Test List all
	reqAll := httptest.NewRequest("GET", "/api/v1/findings", nil)
	recAll := httptest.NewRecorder()
	mux.ServeHTTP(recAll, reqAll)

	if recAll.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recAll.Code)
	}

	var resAll query.ListFindingsResponse
	_ = json.NewDecoder(recAll.Body).Decode(&resAll)
	if resAll.Total != 3 {
		t.Errorf("expected 3 findings total, got %d", resAll.Total)
	}

	// 2. Test Filter: ?q=severity:critical,high
	reqFilter := httptest.NewRequest("GET", "/api/v1/findings?q=severity:critical,high", nil)
	recFilter := httptest.NewRecorder()
	mux.ServeHTTP(recFilter, reqFilter)

	var resFilter query.ListFindingsResponse
	_ = json.NewDecoder(recFilter.Body).Decode(&resFilter)
	if resFilter.Total != 2 {
		t.Errorf("expected 2 findings for severity:critical,high, got %d", resFilter.Total)
	}

	// 3. Test Filter Negation: ?q=-state:fixed
	reqNeg := httptest.NewRequest("GET", "/api/v1/findings?q=-state:fixed", nil)
	recNeg := httptest.NewRecorder()
	mux.ServeHTTP(recNeg, reqNeg)

	var resNeg query.ListFindingsResponse
	_ = json.NewDecoder(recNeg.Body).Decode(&resNeg)
	if resNeg.Total != 2 {
		t.Errorf("expected 2 findings for -state:fixed, got %d", resNeg.Total)
	}

	// 4. Test Wildcard: ?q=cve:CVE-2021-*
	reqWC := httptest.NewRequest("GET", "/api/v1/findings?q=cve:CVE-2021-*", nil)
	recWC := httptest.NewRecorder()
	mux.ServeHTTP(recWC, reqWC)

	var resWC query.ListFindingsResponse
	_ = json.NewDecoder(recWC.Body).Decode(&resWC)
	if resWC.Total != 1 || resWC.Items[0].Finding.ID != f1ID {
		t.Errorf("expected 1 finding for wildcard cve:CVE-2021-*, got %d", resWC.Total)
	}

	// 5. Test Get Finding Detail
	reqDetail := httptest.NewRequest("GET", "/api/v1/findings/"+f1ID.String(), nil)
	recDetail := httptest.NewRecorder()
	mux.ServeHTTP(recDetail, reqDetail)

	if recDetail.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for detail, got %d", recDetail.Code)
	}

	var resDetail query.FindingResponse
	_ = json.NewDecoder(recDetail.Body).Decode(&resDetail)
	if resDetail.Finding.ID != f1ID {
		t.Errorf("expected finding ID %s, got %s", f1ID, resDetail.Finding.ID)
	}
	if resDetail.SLADueDate == nil {
		t.Errorf("expected SLA due date to be calculated")
	}
}

func TestQueryAPISBOM(t *testing.T) {
	store := ingest.NewMemoryStore()
	api := query.NewAPI(store, nil)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	assetID := domain.NewID()

	sbom := &domain.SBOM{
		ID:             domain.NewID(),
		TenantID:       tenantID,
		AssetID:        assetID,
		Format:         "cyclonedx",
		RootComponent:  "pkg:npm/my-app@1.0.0",
		ComponentCount: 3,
		Dependencies: []domain.DependencyEdge{
			{FromRef: "pkg:npm/my-app@1.0.0", ToRef: "pkg:npm/express@4.18.2"},
			{FromRef: "pkg:npm/express@4.18.2", ToRef: "pkg:npm/debug@2.6.9"},
		},
	}

	comps := []domain.SBOMComponent{
		{
			TenantID: tenantID,
			Purl:     "pkg:npm/my-app@1.0.0",
			Name:     "my-app",
			Version:  "1.0.0",
		},
		{
			TenantID: tenantID,
			Purl:     "pkg:npm/express@4.18.2",
			Name:     "express",
			Version:  "4.18.2",
		},
		{
			TenantID: tenantID,
			Purl:     "pkg:npm/debug@2.6.9",
			Name:     "debug",
			Version:  "2.6.9",
		},
	}

	_ = store.SaveSBOM(context.Background(), sbom, comps)

	req := httptest.NewRequest("GET", "/api/v1/assets/"+assetID.String()+"/sbom", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on get SBOM, got %d: %s", rec.Code, rec.Body.String())
	}

	var res struct {
		SBOM       *domain.SBOM           `json:"sbom"`
		Components []domain.SBOMComponent `json:"components"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&res)
	if res.SBOM == nil || len(res.Components) != 3 {
		t.Errorf("expected 3 components, got %v", res.Components)
	}

	// Test GET /sbom/graph
	reqGraph := httptest.NewRequest("GET", "/api/v1/assets/"+assetID.String()+"/sbom/graph", nil)
	recGraph := httptest.NewRecorder()
	mux.ServeHTTP(recGraph, reqGraph)

	if recGraph.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on get SBOM graph, got %d: %s", recGraph.Code, recGraph.Body.String())
	}

	var resGraph struct {
		Root                 string `json:"root"`
		TotalComponents      int    `json:"total_components"`
		DirectComponents     int    `json:"direct_components"`
		TransitiveComponents int    `json:"transitive_components"`
		Mermaid              string `json:"mermaid"`
		Tree                 string `json:"tree"`
	}
	_ = json.NewDecoder(recGraph.Body).Decode(&resGraph)
	if resGraph.Root != "pkg:npm/my-app@1.0.0" {
		t.Errorf("expected root 'pkg:npm/my-app@1.0.0', got %q", resGraph.Root)
	}
	if resGraph.DirectComponents != 1 || resGraph.TransitiveComponents != 2 {
		t.Errorf("expected 1 direct and 2 transitive components, got direct=%d transitive=%d", resGraph.DirectComponents, resGraph.TransitiveComponents)
	}
	if !strings.Contains(resGraph.Mermaid, "flowchart TD") {
		t.Errorf("expected Mermaid flowchart output, got %s", resGraph.Mermaid)
	}

	// Test GET /sbom/path
	reqPath := httptest.NewRequest("GET", "/api/v1/assets/"+assetID.String()+"/sbom/path?target=pkg:npm/debug@2.6.9", nil)
	recPath := httptest.NewRecorder()
	mux.ServeHTTP(recPath, reqPath)

	if recPath.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on get SBOM path, got %d: %s", recPath.Code, recPath.Body.String())
	}

	var resPath struct {
		Target string   `json:"target"`
		Path   []string `json:"path"`
		Depth  int      `json:"depth"`
	}
	_ = json.NewDecoder(recPath.Body).Decode(&resPath)
	if len(resPath.Path) != 3 || resPath.Depth != 2 {
		t.Errorf("expected path length 3 and depth 2, got depth=%d path=%v", resPath.Depth, resPath.Path)
	}
}

func TestQueryAPIPatchAndVEX(t *testing.T) {
	store := ingest.NewMemoryStore()
	api := query.NewAPI(store, nil)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	assetID := domain.NewID()
	findingID := domain.NewID()

	f := &domain.Finding{
		ID:         findingID,
		TenantID:   tenantID,
		AssetID:    assetID,
		FindingKey: "patch-test-key",
		RuleID:     "CVE-2021-44228",
		Title:      "Log4Shell",
		Severity:   domain.SeverityCritical,
		State:      domain.StateOpen,
		Location: domain.Location{
			Package: &domain.PackageLocation{
				Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			},
		},
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}

	_ = store.UpsertFindings(context.Background(), tenantID, []*domain.Finding{f})

	// 1. PATCH state to not_affected with justification
	patchBody := `{"state":"not_affected","justification":"vulnerable_code_not_present","severity":"medium"}`
	reqPatch := httptest.NewRequest("PATCH", "/api/v1/findings/"+findingID.String(), strings.NewReader(patchBody))
	recPatch := httptest.NewRecorder()
	mux.ServeHTTP(recPatch, reqPatch)

	if recPatch.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on PATCH, got %d: %s", recPatch.Code, recPatch.Body.String())
	}

	var resPatch query.FindingResponse
	_ = json.NewDecoder(recPatch.Body).Decode(&resPatch)
	if resPatch.Finding.State != domain.StateNotAffected {
		t.Errorf("expected state 'not_affected', got %s", resPatch.Finding.State)
	}
	if resPatch.Finding.Severity != domain.SeverityMedium {
		t.Errorf("expected severity 'medium', got %s", resPatch.Finding.Severity)
	}

	// 2. Export VEX for the asset
	reqVEX := httptest.NewRequest("GET", "/api/v1/assets/"+assetID.String()+"/vex", nil)
	recVEX := httptest.NewRecorder()
	mux.ServeHTTP(recVEX, reqVEX)

	if recVEX.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on VEX export, got %d", recVEX.Code)
	}

	var vexDoc struct {
		Context    string `json:"@context"`
		Statements []struct {
			Status        string `json:"status"`
			Justification string `json:"justification"`
		} `json:"statements"`
	}
	_ = json.NewDecoder(recVEX.Body).Decode(&vexDoc)
	if len(vexDoc.Statements) != 1 {
		t.Fatalf("expected 1 VEX statement, got %d", len(vexDoc.Statements))
	}
	if vexDoc.Statements[0].Status != "not_affected" {
		t.Errorf("expected VEX status 'not_affected', got %s", vexDoc.Statements[0].Status)
	}
	if vexDoc.Statements[0].Justification != "vulnerable_code_not_present" {
		t.Errorf("expected justification 'vulnerable_code_not_present', got %s", vexDoc.Statements[0].Justification)
	}
}
