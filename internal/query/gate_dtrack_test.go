package query_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/query"
)

type mockGateStore struct {
	*ingest.MemoryStore
	runs    []*domain.IngestRun
	results map[uuid.UUID][]*domain.IngestRunResult
}

func newMockGateStore() *mockGateStore {
	return &mockGateStore{
		MemoryStore: ingest.NewMemoryStore(),
		results:     make(map[uuid.UUID][]*domain.IngestRunResult),
	}
}

func (m *mockGateStore) ListRunsForGate(ctx context.Context, tenantID, sourceID uuid.UUID, commit, digest string) ([]*domain.IngestRun, error) {
	var out []*domain.IngestRun
	for _, r := range m.runs {
		if r.TenantID == tenantID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *mockGateStore) ListRunResults(ctx context.Context, tenantID, runID uuid.UUID) ([]*domain.IngestRunResult, error) {
	return m.results[runID], nil
}

func (m *mockGateStore) ListRunScopes(ctx context.Context, tenantID, runID uuid.UUID) ([]string, error) {
	return nil, nil
}

func TestGate_WaitsForLinkedDependencyTrackSync(t *testing.T) {
	st := newMockGateStore()
	tenantID := uuid.New()
	sourceID := uuid.New()

	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, nil, authn)

	st.EnsureScanSource(context.Background(), tenantID, "ci")

	// 1. Terminal SBOM run
	sbomRunID := uuid.New()
	sbomRun := &domain.IngestRun{
		ID:            sbomRunID,
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: "cyclonedx",
		Format:        "cyclonedx",
		Status:        domain.RunCompleted,
		Context:       domain.UploadContext{Commit: "c123456"},
		CreatedAt:     time.Now().Add(-2 * time.Minute),
	}

	// 2. In-progress linked Dependency-Track sync run
	dtRunID := uuid.New()
	dtRun := &domain.IngestRun{
		ID:            dtRunID,
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: "dependency-track",
		Format:        "dependency-track/api",
		Status:        domain.RunParsing, // Not terminal yet!
		Context:       domain.UploadContext{Commit: "c123456"},
		CreatedAt:     time.Now().Add(-1 * time.Minute),
	}

	st.runs = []*domain.IngestRun{sbomRun, dtRun}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	gateReq := query.GateRequest{
		Source: sourceID.String(),
		Context: struct {
			Commit      string `json:"commit,omitempty"`
			ImageDigest string `json:"imageDigest,omitempty"`
		}{
			Commit: "c123456",
		},
		Expect: []string{"sbom"},
		Wait:   false,
	}

	bodyBytes, _ := json.Marshal(gateReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gate", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("gate returned status %d: %s", w.Code, w.Body.String())
	}

	var resp query.GateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding gate response: %v", err)
	}

	// Because the linked Dependency-Track run is still parsing, gate must NOT pass and reason must say waiting
	if resp.Pass {
		t.Error("gate should not pass while linked dependency-track run is parsing")
	}

	var foundWaitingDT bool
	for _, r := range resp.Reasons {
		if r == "waiting for dependency-track: the linked sync run is parsing" {
			foundWaitingDT = true
			break
		}
	}
	if !foundWaitingDT {
		t.Errorf("expected reason waiting for dependency-track, got reasons: %v", resp.Reasons)
	}

	// 3. Complete Dependency-Track run with a new Critical finding
	dtRun.Status = domain.RunCompleted
	st.results[dtRunID] = []*domain.IngestRunResult{
		{
			TenantID:    tenantID,
			IngestRunID: dtRunID,
			FindingKey:  "key-crit",
			Severity:    domain.SeverityCritical,
			IsNew:       true,
		},
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/gate", bytes.NewReader(bodyBytes))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")

	mux.ServeHTTP(w2, req2)

	var resp2 query.GateResponse
	_ = json.Unmarshal(w2.Body.Bytes(), &resp2)

	if resp2.Pass {
		t.Error("gate should fail when completed dependency-track run has new critical finding")
	}
	if resp2.Summary.New != 1 {
		t.Errorf("summary new = %d, want 1", resp2.Summary.New)
	}

	// Verify both runs are listed
	var foundSBOMRun, foundDTRun bool
	for _, rid := range resp2.Runs {
		if rid == sbomRunID.String() {
			foundSBOMRun = true
		}
		if rid == dtRunID.String() {
			foundDTRun = true
		}
	}
	if !foundSBOMRun || !foundDTRun {
		t.Errorf("runs = %v, expected both %s and %s", resp2.Runs, sbomRunID, dtRunID)
	}
}
