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

func TestGate_NativeSBOMRun(t *testing.T) {
	st := newMockGateStore()
	tenantID := uuid.New()
	sourceID := uuid.New()

	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, nil, authn)

	_, _ = st.EnsureScanSource(context.Background(), tenantID, "ci")

	// 1. In-progress SBOM run
	sbomRunID := uuid.New()
	sbomRun := &domain.IngestRun{
		ID:           sbomRunID,
		TenantID:     tenantID,
		ScanSourceID: sourceID,
		Format:       "sbom-cyclonedx",
		Status:       domain.RunParsing, // in progress
		Context:      domain.UploadContext{Commit: "c123456"},
		CreatedAt:    time.Now().Add(-1 * time.Minute),
	}

	st.runs = []*domain.IngestRun{sbomRun}

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

	// While parsing, gate must NOT pass and reason must say waiting
	if resp.Pass {
		t.Error("gate should not pass while sbom run is parsing")
	}

	var foundWaiting bool
	for _, r := range resp.Reasons {
		if r == "waiting for sbom: the run is parsing" {
			foundWaiting = true
			break
		}
	}
	if !foundWaiting {
		t.Errorf("expected reason waiting for sbom, got reasons: %v", resp.Reasons)
	}

	// 2. Complete SBOM run with a new Critical finding
	sbomRun.Status = domain.RunCompleted
	st.results[sbomRunID] = []*domain.IngestRunResult{
		{
			TenantID:    tenantID,
			IngestRunID: sbomRunID,
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
		t.Error("gate should fail when completed sbom run has new critical finding")
	}
	if resp2.Summary.New != 1 {
		t.Errorf("summary new = %d, want 1", resp2.Summary.New)
	}
	if len(resp2.Runs) == 0 || resp2.Runs[0] != sbomRunID.String() {
		t.Errorf("expected run %s in runs list, got %v", sbomRunID, resp2.Runs)
	}
}
