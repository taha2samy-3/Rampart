package query_test

import (
	"context"
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

type heldCloseMockStore struct {
	*ingest.MemoryStore
	run       *domain.IngestRun
	heldClose *domain.HeldClose
	applied   bool
	discarded bool
}

func (m *heldCloseMockStore) GetIngestRun(ctx context.Context, tenantID, id uuid.UUID) (*domain.IngestRun, error) {
	if m.run != nil && m.run.ID == id && m.run.TenantID == tenantID {
		return m.run, nil
	}
	return nil, nil
}

func (m *heldCloseMockStore) GetHeldClose(ctx context.Context, tenantID, id uuid.UUID) (*domain.HeldClose, error) {
	if m.heldClose != nil && m.heldClose.ID == id && m.heldClose.TenantID == tenantID {
		return m.heldClose, nil
	}
	return nil, nil
}

func (m *heldCloseMockStore) ListHeldCloses(ctx context.Context, tenantID uuid.UUID, decision string) ([]domain.HeldClose, error) {
	if m.heldClose != nil && m.heldClose.TenantID == tenantID {
		return []domain.HeldClose{*m.heldClose}, nil
	}
	return []domain.HeldClose{}, nil
}

func (m *heldCloseMockStore) ApplyHeldClose(ctx context.Context, tenantID, id uuid.UUID, decidedBy string) (int, error) {
	m.applied = true
	m.heldClose.Decision = domain.HeldCloseDecisionConfirmed
	m.heldClose.DecidedBy = decidedBy
	return len(m.heldClose.FindingIDs), nil
}

func (m *heldCloseMockStore) DecideHeldClose(ctx context.Context, tenantID, id uuid.UUID, decision, decidedBy string) error {
	m.discarded = true
	m.heldClose.Decision = decision
	m.heldClose.DecidedBy = decidedBy
	return nil
}

func TestHeldClosesAPI_AuthorizationAndDecisions(t *testing.T) {
	tenantID := uuid.New()
	appID := uuid.New()
	runID := uuid.New()
	hcID := uuid.New()

	mem := ingest.NewMemoryStore()
	mock := &heldCloseMockStore{
		MemoryStore: mem,
		run: &domain.IngestRun{
			ID:            runID,
			TenantID:      tenantID,
			ApplicationID: appID,
			Status:        domain.RunCompletedWithErrors,
			Error:         "close_held",
			CreatedAt:     time.Now().UTC(),
		},
		heldClose: &domain.HeldClose{
			ID:          hcID,
			TenantID:    tenantID,
			IngestRunID: runID,
			Scope: domain.CloseScope{
				TenantID: tenantID,
				AssetID:  appID,
				Track:    "main",
			},
			FindingIDs: []uuid.UUID{uuid.New(), uuid.New()},
			CreatedAt:  time.Now().UTC(),
		},
	}

	authn := auth.NewAuthenticatorWithStore(mock)
	api := query.NewAPIWithAuth(mock, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// Create tokens: viewer, and maintainer on appID
	viewerRaw, viewerRec, _ := auth.GenerateToken(tenantID, auth.RoleViewer, "viewer", []string{"*"}, time.Hour)
	_ = mock.SaveToken(context.Background(), viewerRec)

	maintRaw, maintRec, _ := auth.GenerateToken(tenantID, auth.RoleMaintainer, "maint", []string{"*"}, time.Hour)
	_ = mock.SaveToken(context.Background(), maintRec)

	// 1. Unauthenticated request to list held closes -> 401
	r0 := httptest.NewRequest("GET", "/api/v1/held-closes", nil)
	w0 := httptest.NewRecorder()
	mux.ServeHTTP(w0, r0)
	if w0.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", w0.Code)
	}

	// 2. Viewer lists held closes -> 200 OK
	r1 := httptest.NewRequest("GET", "/api/v1/held-closes", nil)
	r1.Header.Set("Authorization", "Bearer "+viewerRaw)
	w1 := httptest.NewRecorder()
	mux.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for viewer list, got %d", w1.Code)
	}

	// 3. Viewer attempts to confirm held close -> 403 Forbidden!
	r2 := httptest.NewRequest("POST", "/api/v1/held-closes/"+hcID.String()+"/confirm", nil)
	r2.Header.Set("Authorization", "Bearer "+viewerRaw)
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, r2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer confirm, got %d", w2.Code)
	}

	// 4. Viewer attempts to discard held close -> 403 Forbidden!
	r3 := httptest.NewRequest("POST", "/api/v1/held-closes/"+hcID.String()+"/discard", nil)
	r3.Header.Set("Authorization", "Bearer "+viewerRaw)
	w3 := httptest.NewRecorder()
	mux.ServeHTTP(w3, r3)
	if w3.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer discard, got %d", w3.Code)
	}

	// 5. Maintainer confirms held close -> 200 OK
	r4 := httptest.NewRequest("POST", "/api/v1/held-closes/"+hcID.String()+"/confirm", nil)
	r4.Header.Set("Authorization", "Bearer "+maintRaw)
	w4 := httptest.NewRecorder()
	mux.ServeHTTP(w4, r4)
	if w4.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for maintainer confirm, got %d (body: %s)", w4.Code, w4.Body.String())
	}
	if !mock.applied {
		t.Fatalf("expected ApplyHeldClose to be called")
	}
}
