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
	"rampart/internal/query"
	"rampart/internal/query/grammar"
	"rampart/internal/query/sqlbuilder"
	"rampart/internal/store"
)

type mockGroupViewStore struct {
	*mockGateStore
	groups  map[uuid.UUID]*domain.FindingGroup
	members map[uuid.UUID][]uuid.UUID
	views   map[uuid.UUID]*domain.SavedView
}

func newMockGroupViewStore() *mockGroupViewStore {
	return &mockGroupViewStore{
		mockGateStore: newMockGateStore(),
		groups:        make(map[uuid.UUID]*domain.FindingGroup),
		members:       make(map[uuid.UUID][]uuid.UUID),
		views:         make(map[uuid.UUID]*domain.SavedView),
	}
}

func (m *mockGroupViewStore) CreateFindingGroup(ctx context.Context, g *domain.FindingGroup) error {
	m.groups[g.ID] = g
	return nil
}

func (m *mockGroupViewStore) GetFindingGroup(ctx context.Context, tenantID, id uuid.UUID) (*domain.FindingGroup, error) {
	g, ok := m.groups[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	g.MemberCount = len(m.members[id])
	return g, nil
}

func (m *mockGroupViewStore) ListFindingGroups(ctx context.Context, tenantID uuid.UUID) ([]domain.FindingGroup, error) {
	var list []domain.FindingGroup
	for _, g := range m.groups {
		if g.TenantID == tenantID {
			g.MemberCount = len(m.members[g.ID])
			list = append(list, *g)
		}
	}
	return list, nil
}

func (m *mockGroupViewStore) DeleteFindingGroup(ctx context.Context, tenantID, id uuid.UUID) error {
	delete(m.groups, id)
	delete(m.members, id)
	return nil
}

func (m *mockGroupViewStore) AddGroupMembers(ctx context.Context, tenantID, groupID uuid.UUID, findingIDs []uuid.UUID) error {
	m.members[groupID] = append(m.members[groupID], findingIDs...)
	return nil
}

func (m *mockGroupViewStore) RemoveGroupMembers(ctx context.Context, tenantID, groupID uuid.UUID, findingIDs []uuid.UUID) error {
	var remaining []uuid.UUID
	toRemove := make(map[uuid.UUID]bool)
	for _, id := range findingIDs {
		toRemove[id] = true
	}
	for _, id := range m.members[groupID] {
		if !toRemove[id] {
			remaining = append(remaining, id)
		}
	}
	m.members[groupID] = remaining
	return nil
}

func (m *mockGroupViewStore) ListGroupFindings(ctx context.Context, tenantID, groupID uuid.UUID) ([]uuid.UUID, error) {
	return m.members[groupID], nil
}

func (m *mockGroupViewStore) CreateSavedView(ctx context.Context, v *domain.SavedView) error {
	m.views[v.ID] = v
	return nil
}

func (m *mockGroupViewStore) GetSavedView(ctx context.Context, tenantID, id uuid.UUID) (*domain.SavedView, error) {
	v, ok := m.views[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return v, nil
}

func (m *mockGroupViewStore) ListSavedViews(ctx context.Context, tenantID uuid.UUID, owner string) ([]domain.SavedView, error) {
	var list []domain.SavedView
	for _, v := range m.views {
		if v.TenantID == tenantID && (v.Scope == "tenant" || v.Owner == owner) {
			list = append(list, *v)
		}
	}
	return list, nil
}

func (m *mockGroupViewStore) DeleteSavedView(ctx context.Context, tenantID, id uuid.UUID) error {
	delete(m.views, id)
	return nil
}

func (m *mockGroupViewStore) QueryFindings(ctx context.Context, tenantID uuid.UUID, q *grammar.Query, sortKey string, limit int, cur *sqlbuilder.Cursor) ([]*domain.Finding, error) {
	return []*domain.Finding{
		{
			ID:                uuid.New(),
			TenantID:          tenantID,
			RuleID:            "TEST-001",
			RuleScannerFamily: "sast",
			Title:             "SQL Injection",
			Severity:          domain.SeverityCritical,
			Category:          domain.CategorySAST,
			State:             domain.StateOpen,
			Location:          domain.Location{Code: &domain.CodeLocation{FilePath: "src/db.go"}},
			RiskScore:         95,
			FirstSeen:         time.Now(),
			LastSeen:          time.Now(),
		},
	}, nil
}

func (m *mockGroupViewStore) CountFindings(ctx context.Context, tenantID uuid.UUID, q *grammar.Query) (int, error) {
	return 1, nil
}

func TestAPI_SavedViews(t *testing.T) {
	st := newMockGroupViewStore()
	tenantID := uuid.New()
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// 1. Create Saved View with valid grammar
	body := `{"name":"Critical SAST","query":"severity:critical category:sast","scope":"tenant"}`
	req := httptest.NewRequest("POST", "/api/v1/views", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}

	var created domain.SavedView
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding view response: %v", err)
	}

	// 2. Reject invalid grammar (unknown field per D16/D59)
	badBody := `{"name":"Bad View","query":"notafield:critical"}`
	badReq := httptest.NewRequest("POST", "/api/v1/views", bytes.NewReader([]byte(badBody)))
	badReq.Header.Set("Authorization", "Bearer "+token)
	badW := httptest.NewRecorder()
	mux.ServeHTTP(badW, badReq)

	if badW.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for invalid grammar, got %d", badW.Code)
	}

	// 3. List Views
	listReq := httptest.NewRequest("GET", "/api/v1/views", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listW := httptest.NewRecorder()
	mux.ServeHTTP(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("list views code = %d", listW.Code)
	}

	// 4. Delete View
	delReq := httptest.NewRequest("DELETE", "/api/v1/views/"+created.ID.String(), nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delW := httptest.NewRecorder()
	mux.ServeHTTP(delW, delReq)

	if delW.Code != http.StatusNoContent {
		t.Errorf("delete view code = %d", delW.Code)
	}
}

func TestAPI_FindingGroups(t *testing.T) {
	st := newMockGroupViewStore()
	tenantID := uuid.New()
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// 1. Create Group
	body := `{"name":"Log4j Campaign","description":"All affected assets"}`
	req := httptest.NewRequest("POST", "/api/v1/groups", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create group code = %d: %s", w.Code, w.Body.String())
	}

	var grp domain.FindingGroup
	_ = json.Unmarshal(w.Body.Bytes(), &grp)

	// 2. Add members
	f1 := uuid.New()
	f2 := uuid.New()
	memBody, _ := json.Marshal(map[string]any{"finding_ids": []uuid.UUID{f1, f2}})
	memReq := httptest.NewRequest("POST", "/api/v1/groups/"+grp.ID.String()+"/members", bytes.NewReader(memBody))
	memReq.Header.Set("Authorization", "Bearer "+token)
	memW := httptest.NewRecorder()
	mux.ServeHTTP(memW, memReq)

	if memW.Code != http.StatusNoContent {
		t.Fatalf("add members code = %d", memW.Code)
	}

	// 3. Get Group
	getReq := httptest.NewRequest("GET", "/api/v1/groups/"+grp.ID.String(), nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getW := httptest.NewRecorder()
	mux.ServeHTTP(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("get group code = %d", getW.Code)
	}
}

func TestAPI_LiveEventsSSE(t *testing.T) {
	st := newMockGroupViewStore()
	tenantID := uuid.New()
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest("GET", "/api/v1/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("sse status = %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("content-type = %s", w.Header().Get("Content-Type"))
	}
	if w.Header().Get("X-Accel-Buffering") != "no" {
		t.Errorf("X-Accel-Buffering = %s", w.Header().Get("X-Accel-Buffering"))
	}
}

func TestAPI_Exports(t *testing.T) {
	st := newMockGroupViewStore()
	tenantID := uuid.New()
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// 1. Export CSV
	reqCSV := httptest.NewRequest("GET", "/api/v1/findings/export?format=csv", nil)
	reqCSV.Header.Set("Authorization", "Bearer "+token)
	wCSV := httptest.NewRecorder()
	mux.ServeHTTP(wCSV, reqCSV)

	if wCSV.Code != http.StatusOK {
		t.Fatalf("export csv code = %d: %s", wCSV.Code, wCSV.Body.String())
	}
	if wCSV.Header().Get("Content-Type") != "text/csv" {
		t.Errorf("expected text/csv, got %s", wCSV.Header().Get("Content-Type"))
	}
	if !bytes.Contains(wCSV.Body.Bytes(), []byte("SQL Injection")) {
		t.Errorf("csv missing finding content: %s", wCSV.Body.String())
	}

	// 2. Export JSON
	reqJSON := httptest.NewRequest("GET", "/api/v1/findings/export?format=json", nil)
	reqJSON.Header.Set("Authorization", "Bearer "+token)
	wJSON := httptest.NewRecorder()
	mux.ServeHTTP(wJSON, reqJSON)

	if wJSON.Code != http.StatusOK {
		t.Fatalf("export json code = %d: %s", wJSON.Code, wJSON.Body.String())
	}
	if wJSON.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json, got %s", wJSON.Header().Get("Content-Type"))
	}

	// 3. Export OCSF
	reqOCSF := httptest.NewRequest("GET", "/api/v1/findings/export?format=ocsf", nil)
	reqOCSF.Header.Set("Authorization", "Bearer "+token)
	wOCSF := httptest.NewRecorder()
	mux.ServeHTTP(wOCSF, reqOCSF)

	if wOCSF.Code != http.StatusOK {
		t.Fatalf("export ocsf code = %d: %s", wOCSF.Code, wOCSF.Body.String())
	}
	if wOCSF.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json, got %s", wOCSF.Header().Get("Content-Type"))
	}
	if !bytes.Contains(wOCSF.Body.Bytes(), []byte(`"class_uid":2001`)) {
		t.Errorf("ocsf missing class_uid: %s", wOCSF.Body.String())
	}

	// 4. Invalid query filter rejected
	reqBad := httptest.NewRequest("GET", "/api/v1/findings/export?q=badfield:test", nil)
	reqBad.Header.Set("Authorization", "Bearer "+token)
	wBad := httptest.NewRecorder()
	mux.ServeHTTP(wBad, reqBad)

	if wBad.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad query param, got %d", wBad.Code)
	}
}
