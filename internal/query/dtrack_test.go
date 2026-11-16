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
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/query"
)

type dtrackMockStore struct {
	*ingest.MemoryStore
	unmappedProjects []domain.DTrackProjectRecord
	mapped           map[string]uuid.UUID
}

func (m *dtrackMockStore) ListUnmappedDTrackProjects(ctx context.Context, tenantID, sourceID uuid.UUID) ([]domain.DTrackProjectRecord, error) {
	var out []domain.DTrackProjectRecord
	for _, p := range m.unmappedProjects {
		if p.TenantID == tenantID && p.SourceID == sourceID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (m *dtrackMockStore) MapDTrackProject(ctx context.Context, tenantID uuid.UUID, projectUUID string, appID uuid.UUID) error {
	m.mapped[projectUUID] = appID
	return nil
}

func TestDTrackAPI_UnmappedProjectsAndMapping(t *testing.T) {
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	projUUID := "7b2e8a10-2f63-4b6c-8a62-9e1234567890"
	sourceID := uuid.New()

	st := &dtrackMockStore{
		MemoryStore: ingest.NewMemoryStore(),
		unmappedProjects: []domain.DTrackProjectRecord{
			{
				TenantID:       tenantID,
				SourceID:       sourceID,
				ProjectUUID:    projUUID,
				Name:           "payments-worker",
				Version:        "1.4.0",
				Purl:           "pkg:npm/payments-worker@1.4.0",
				Active:         true,
				UnmappedReason: "No matching application rule",
				CreatedAt:      time.Now(),
			},
		},
		mapped: make(map[string]uuid.UUID),
	}

	authn := auth.NewAuthenticatorWithStore(st)
	adminToken := authn.DefaultAdminToken(tenantID)

	viewerToken, _, err := auth.GenerateToken(tenantID, auth.RoleViewer, "viewer@acme.com", []string{"tenant"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SaveToken(context.Background(), &auth.TokenRecord{
		TokenHash: auth.HashToken(viewerToken), TenantID: tenantID, Role: auth.RoleViewer,
	})

	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// 1. List unmapped projects with adminToken -> 200 OK
	reqList := httptest.NewRequest("GET", "/api/v1/sources/"+sourceID.String()+"/unmapped", nil)
	reqList.Header.Set("Authorization", "Bearer "+adminToken)
	recList := httptest.NewRecorder()
	mux.ServeHTTP(recList, reqList)

	if recList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", recList.Code, recList.Body.String())
	}

	var listRes struct {
		Projects []domain.DTrackProjectRecord `json:"projects"`
		Count    int                          `json:"count"`
	}
	if err := json.NewDecoder(recList.Body).Decode(&listRes); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if listRes.Count != 1 || len(listRes.Projects) != 1 {
		t.Fatalf("expected 1 unmapped project, got count=%d", listRes.Count)
	}
	if listRes.Projects[0].Name != "payments-worker" {
		t.Errorf("unexpected project name: %s", listRes.Projects[0].Name)
	}

	// 2. Viewer cannot map project -> 403 Forbidden
	appID := uuid.New()
	_ = st.CreateApplication(context.Background(), &domain.Application{ID: appID, TenantID: tenantID, Name: "payments", Slug: "payments"})
	mapPath := "/api/v1/sources/" + sourceID.String() + "/map"
	mapBody, _ := json.Marshal(map[string]any{"project_uuid": projUUID, "application_id": appID})
	reqViewerMap := httptest.NewRequest("POST", mapPath, bytes.NewReader(mapBody))
	reqViewerMap.Header.Set("Authorization", "Bearer "+viewerToken)
	reqViewerMap.Header.Set("Content-Type", "application/json")
	recViewerMap := httptest.NewRecorder()
	mux.ServeHTTP(recViewerMap, reqViewerMap)

	if recViewerMap.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer role, got %d", recViewerMap.Code)
	}

	// 3. Admin maps project -> 200 OK
	// A project of another source is not mapped through this one (docs/23 DT6: the route names the source).
	otherPath := "/api/v1/sources/" + uuid.NewString() + "/map"
	reqOther := httptest.NewRequest("POST", otherPath, bytes.NewReader(mapBody))
	reqOther.Header.Set("Authorization", "Bearer "+adminToken)
	recOther := httptest.NewRecorder()
	mux.ServeHTTP(recOther, reqOther)
	if recOther.Code != http.StatusNotFound {
		t.Fatalf("another source's project: %d", recOther.Code)
	}

	reqAdminMap := httptest.NewRequest("POST", mapPath, bytes.NewReader(mapBody))
	reqAdminMap.Header.Set("Authorization", "Bearer "+adminToken)
	reqAdminMap.Header.Set("Content-Type", "application/json")
	recAdminMap := httptest.NewRecorder()
	mux.ServeHTTP(recAdminMap, reqAdminMap)

	if recAdminMap.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin mapping project, got %d: %s", recAdminMap.Code, recAdminMap.Body.String())
	}
	if st.mapped[projUUID] != appID {
		t.Errorf("expected project %s to be mapped to %s", projUUID, appID)
	}
}
