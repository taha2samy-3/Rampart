package query_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/query"

	"github.com/google/uuid"
)

type refreshStore struct {
	*ingest.MemoryStore
	projects []domain.DTrackProjectRecord
}

func (s *refreshStore) ListMappedDTrackProjects(_ context.Context, _, source uuid.UUID) ([]domain.DTrackProjectRecord, error) {
	var out []domain.DTrackProjectRecord
	for _, p := range s.projects {
		if (source == uuid.Nil || p.SourceID == source) && p.ApplicationID != nil {
			out = append(out, p)
		}
	}
	return out, nil
}

type recordingEnqueuer struct{ got []string }

func (r *recordingEnqueuer) EnqueueDTrackProject(_ context.Context, _, _ uuid.UUID, project string, _ time.Duration) error {
	r.got = append(r.got, project)
	return nil
}

// "Scan this application" is a sync of its Dependency-Track projects, asked for by someone who may triage there; the
// per-package button no longer pretends to scan, and needs the same right (D126).
func TestRefreshVulnerabilities(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	appA, appB, src := uuid.New(), uuid.New(), uuid.New()
	st := &refreshStore{MemoryStore: ingest.NewMemoryStore(), projects: []domain.DTrackProjectRecord{
		{TenantID: tenantID, SourceID: src, ProjectUUID: "p-1", ApplicationID: &appA},
		{TenantID: tenantID, SourceID: src, ProjectUUID: "p-2", ApplicationID: &appA},
		{TenantID: tenantID, SourceID: src, ProjectUUID: "p-other", ApplicationID: &appB},
	}}
	_ = st.CreateApplication(ctx, &domain.Application{ID: appA, TenantID: tenantID, Name: "payments", Slug: "payments"})
	_ = st.CreateApplication(ctx, &domain.Application{ID: appB, TenantID: tenantID, Name: "search", Slug: "search"})
	empty := uuid.New()
	_ = st.CreateApplication(ctx, &domain.Application{ID: empty, TenantID: tenantID, Name: "empty", Slug: "empty"})
	authn := auth.NewAuthenticatorWithStore(st)
	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	enq := &recordingEnqueuer{}
	api.SetDTrackEnqueuer(enq)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// a triager on payments only
	tri, rec, _ := auth.GenerateToken(tenantID, auth.RoleViewer, "pay-tri", []string{"*"}, time.Hour)
	_ = st.SaveToken(ctx, rec)
	_ = st.UpsertAccessBinding(ctx, tenantID, &domain.AccessBinding{ID: uuid.New(), Subject: "pay-tri", Role: "triager", ApplicationID: appA})
	viewer, vrec, _ := auth.GenerateToken(tenantID, auth.RoleViewer, "plain", []string{"*"}, time.Hour)
	_ = st.SaveToken(ctx, vrec)

	post := func(token, path, body string) int {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	if c := post(viewer, "/api/v1/applications/"+appA.String()+"/refresh-vulnerabilities", ""); c != http.StatusForbidden {
		t.Fatalf("a viewer: %d", c)
	}
	if c := post(tri, "/api/v1/applications/"+appB.String()+"/refresh-vulnerabilities", ""); c != http.StatusForbidden {
		t.Fatalf("a triager on payments cannot refresh search: %d", c)
	}
	if c := post(tri, "/api/v1/applications/"+appA.String()+"/refresh-vulnerabilities", ""); c != http.StatusAccepted || len(enq.got) != 2 || enq.got[0] != "p-1" || enq.got[1] != "p-2" {
		t.Fatalf("both projects of payments and no other: %d %v", c, enq.got)
	}
	if c := post(authn.DefaultAdminToken(tenantID), "/api/v1/applications/"+empty.String()+"/refresh-vulnerabilities", ""); c != http.StatusConflict {
		t.Fatalf("an application with no Dependency-Track project: %d", c)
	}
	if c := post(authn.DefaultAdminToken(tenantID), "/api/v1/applications/not-an-id/refresh-vulnerabilities", ""); c != http.StatusBadRequest {
		t.Fatalf("a bad id: %d", c)
	}
	// the per-package button needs triage rights too
	if c := post(viewer, "/api/v1/inventory/components/scan", `{"purl":"pkg:npm/lodash@4"}`); c != http.StatusForbidden {
		t.Fatalf("a viewer cannot re-score the tenant: %d", c)
	}
}
