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

// "Scan this application" triggers native vulnerability matching.
func TestRefreshVulnerabilities(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	appA, appB := uuid.New(), uuid.New()
	st := ingest.NewMemoryStore()
	_ = st.CreateApplication(ctx, &domain.Application{ID: appA, TenantID: tenantID, Name: "payments", Slug: "payments"})
	_ = st.CreateApplication(ctx, &domain.Application{ID: appB, TenantID: tenantID, Name: "search", Slug: "search"})
	authn := auth.NewAuthenticatorWithStore(st)
	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
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
	if c := post(tri, "/api/v1/applications/"+appA.String()+"/refresh-vulnerabilities", ""); c != http.StatusAccepted {
		t.Fatalf("expected accepted: %d", c)
	}
	if c := post(authn.DefaultAdminToken(tenantID), "/api/v1/applications/"+uuid.New().String()+"/refresh-vulnerabilities", ""); c != http.StatusNotFound {
		t.Fatalf("an application that does not exist: %d", c)
	}
	if c := post(authn.DefaultAdminToken(tenantID), "/api/v1/applications/not-an-id/refresh-vulnerabilities", ""); c != http.StatusBadRequest {
		t.Fatalf("a bad id: %d", c)
	}
	// the per-package button needs triage rights too
	if c := post(viewer, "/api/v1/inventory/components/scan", `{"purl":"pkg:npm/lodash@4"}`); c != http.StatusForbidden {
		t.Fatalf("a viewer cannot re-score the tenant: %d", c)
	}
}
