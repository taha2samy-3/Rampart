package webhook_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
	"rampart/internal/upstream/dependencytrack/webhook"
)

type mockDTrackStore struct {
	mu           sync.Mutex
	sources      map[uuid.UUID]sourceInfo
	syncs        map[string]*domain.DTrackSync
	enqueueCount int
}

type sourceInfo struct {
	tenantID uuid.UUID
	name     string
}

func newMockStore() *mockDTrackStore {
	return &mockDTrackStore{
		sources: make(map[uuid.UUID]sourceInfo),
		syncs:   make(map[string]*domain.DTrackSync),
	}
}

func (m *mockDTrackStore) LookupScanSource(ctx context.Context, sourceID uuid.UUID) (uuid.UUID, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info, ok := m.sources[sourceID]
	if !ok {
		return uuid.Nil, "", store.ErrNotFound
	}
	return info.tenantID, info.name, nil
}

func (m *mockDTrackStore) EnqueueDTrackSync(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enqueueCount++
	key := tenantID.String() + ":" + projectUUID
	s, ok := m.syncs[key]
	if !ok {
		now := time.Now()
		m.syncs[key] = &domain.DTrackSync{
			TenantID:    tenantID,
			SourceID:    sourceID,
			ProjectUUID: projectUUID,
			State:       domain.DTrackSyncStateSyncing,
			Dirty:       false,
			LastSyncAt:  &now,
		}
		return true, nil
	}
	if s.State == domain.DTrackSyncStateSyncing {
		s.Dirty = true
		return false, nil
	}
	s.State = domain.DTrackSyncStateSyncing
	s.Dirty = false
	return true, nil
}

func (m *mockDTrackStore) CompleteDTrackSync(ctx context.Context, tenantID uuid.UUID, projectUUID string, syncErr error) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID.String() + ":" + projectUUID
	s, ok := m.syncs[key]
	if !ok {
		return false, nil
	}
	if s.Dirty {
		s.Dirty = false
		s.State = domain.DTrackSyncStateSyncing
		return true, nil
	}
	s.State = domain.DTrackSyncStateIdle
	return false, nil
}

func (m *mockDTrackStore) GetDTrackSync(ctx context.Context, tenantID uuid.UUID, projectUUID string) (*domain.DTrackSync, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID.String() + ":" + projectUUID
	s, ok := m.syncs[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return s, nil
}

func (m *mockDTrackStore) UpsertDTrackProject(ctx context.Context, proj domain.DTrackProjectRecord) error {
	return nil
}

func (m *mockDTrackStore) ListUnmappedDTrackProjects(ctx context.Context, tenantID, sourceID uuid.UUID) ([]domain.DTrackProjectRecord, error) {
	return nil, nil
}

type mockSecretResolver struct {
	secrets map[string][]byte
}

func (r *mockSecretResolver) GetSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string) ([]byte, error) {
	mapKey := tenantID.String() + ":" + key
	sec, ok := r.secrets[mapKey]
	if !ok {
		return nil, store.ErrNotFound
	}
	return sec, nil
}

type mockSyncer struct {
	mu    sync.Mutex
	calls []string
}

func (s *mockSyncer) SyncProject(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, projectUUID)
	return nil
}

func TestWebhookHandler(t *testing.T) {
	tenantID := uuid.New()
	sourceID := uuid.New()

	st := newMockStore()
	st.sources[sourceID] = sourceInfo{tenantID: tenantID, name: "dtrack-main"}

	sec := &mockSecretResolver{
		secrets: map[string][]byte{
			tenantID.String() + ":scansource:dtrack-main:webhook": []byte("valid-webhook-secret-12345"),
		},
	}

	syncer := &mockSyncer{}
	handler := webhook.NewHandler(st, sec, syncer)

	// 1. Wrong method
	req := httptest.NewRequest(http.MethodGet, "/hooks/dependency-track/"+sourceID.String(), nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("got status %d, want 405", rr.Code)
	}

	// 2. Unknown source
	req = httptest.NewRequest(http.MethodPost, "/hooks/dependency-track/"+uuid.New().String(), bytes.NewReader([]byte("{}")))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("got status %d, want 404", rr.Code)
	}

	// 3. Wrong secret
	req = httptest.NewRequest(http.MethodPost, "/hooks/dependency-track/"+sourceID.String(), bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer wrong-secret")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want 401", rr.Code)
	}

	// 4. Valid secret and payload
	payload := `{
		"notification": {
			"level": "INFORMATIONAL",
			"group": "BOM_PROCESSED",
			"subject": {
				"project": {
					"uuid": "project-uuid-1",
					"name": "payments-api"
				}
			}
		}
	}`
	req = httptest.NewRequest(http.MethodPost, "/hooks/dependency-track/"+sourceID.String(), bytes.NewReader([]byte(payload)))
	req.Header.Set("Authorization", "Bearer valid-webhook-secret-12345")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("got status %d, want 202", rr.Code)
	}

	// 5. Burst of 50 events makes two syncs (trailing-edge debounce check)
	pUUID := "burst-project-99"
	burstPayload := fmt.Sprintf(`{"notification":{"group":"BOM_PROCESSED","subject":{"project":{"uuid":"%s"}}}}`, pUUID)

	// First event: should start sync
	s1, err := st.EnqueueDTrackSync(context.Background(), tenantID, sourceID, pUUID)
	if err != nil || !s1 {
		t.Fatalf("first event should start sync: s1=%t, err=%v", s1, err)
	}

	// Send 49 more events via HTTP handler
	for i := 0; i < 49; i++ {
		r := httptest.NewRequest(http.MethodPost, "/hooks/dependency-track/"+sourceID.String(), bytes.NewReader([]byte(burstPayload)))
		r.Header.Set("Authorization", "Bearer valid-webhook-secret-12345")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("event %d failed with status %d", i, rec.Code)
		}
	}

	// First sync pass completes: dirty was true, so trailing pass is triggered
	hasTrailing1, err := st.CompleteDTrackSync(context.Background(), tenantID, pUUID, nil)
	if err != nil || !hasTrailing1 {
		t.Fatalf("first completion should have trailing sync: %t, %v", hasTrailing1, err)
	}

	// Second sync pass completes: dirty was cleared, so it goes to idle
	hasTrailing2, err := st.CompleteDTrackSync(context.Background(), tenantID, pUUID, nil)
	if err != nil || hasTrailing2 {
		t.Fatalf("second completion should not have trailing sync: %t, %v", hasTrailing2, err)
	}

	// Verify state is idle
	syncRecord, err := st.GetDTrackSync(context.Background(), tenantID, pUUID)
	if err != nil || syncRecord.State != domain.DTrackSyncStateIdle {
		t.Fatalf("expected state idle after 2 syncs, got %+v", syncRecord)
	}
}
