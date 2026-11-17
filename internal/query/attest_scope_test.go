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
	"rampart/internal/ingest"
	"rampart/internal/query"
	"rampart/internal/store"

	"github.com/google/uuid"
)

const manualControl = `{"id":"TM-1","name":"Threat model signed off","manual":true}`

// An attestation is made where the caller may decide (D48): a maintainer on one application attests for that
// application and no other, and for the whole tenant only with the tenant role. The door used to be the tenant role
// alone, so the person the page offered the button to was answered 403.
func TestAttest_ScopedByApplication(t *testing.T) {
	ctx := context.Background()
	s := &fwStore{MemoryStore: ingest.NewMemoryStore(), specs: []store.StoredFramework{spec("acme-policy", "", "", manualControl)}}
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(s.MemoryStore)
	api := query.NewAPIWithAuth(s, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	appA, appB := uuid.New(), uuid.New()
	_ = s.CreateApplication(ctx, &domain.Application{ID: appA, TenantID: tenantID, Name: "payments", Slug: "payments"})
	_ = s.CreateApplication(ctx, &domain.Application{ID: appB, TenantID: tenantID, Name: "search", Slug: "search"})
	// a tenant viewer who is maintainer on payments only
	raw, rec, _ := auth.GenerateToken(tenantID, auth.RoleViewer, "pay-maint", []string{"*"}, time.Hour)
	_ = s.SaveToken(ctx, rec)
	_ = s.UpsertAccessBinding(ctx, tenantID, &domain.AccessBinding{ID: uuid.New(), Subject: "pay-maint", Role: "maintainer", ApplicationID: appA})
	// a tenant viewer with no binding at all
	vRaw, vRec, _ := auth.GenerateToken(tenantID, auth.RoleViewer, "plain", []string{"*"}, time.Hour)
	_ = s.SaveToken(ctx, vRec)

	id := "acme-policy"
	post := func(token, body string) int {
		r := httptest.NewRequest("POST", "/api/v1/taxonomies/"+id+"/controls/TM-1/attestations", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusCreated && w.Code != http.StatusForbidden {
			t.Logf("body: %s", w.Body.String())
		}
		return w.Code
	}
	ok := `"status":"passed","note":"reviewed in the design meeting"`

	if c := post(raw, `{`+ok+`,"application_id":"`+appA.String()+`","owner":"team:payments-security"}`); c != http.StatusCreated {
		t.Fatalf("a maintainer on payments attests for payments: %d", c)
	}
	if got := s.attested[0]; got.Owner != "team:payments-security" {
		t.Fatalf("the owner is kept: %+v", got)
	}
	if c := post(raw, `{`+ok+`,"application_id":"`+appB.String()+`"}`); c != http.StatusForbidden {
		t.Fatalf("not on search: %d", c)
	}
	if c := post(raw, `{`+ok+`}`); c != http.StatusForbidden {
		t.Fatalf("a maintainer on one application cannot attest for the whole tenant: %d", c)
	}
	if c := post(vRaw, `{`+ok+`,"application_id":"`+appA.String()+`"}`); c != http.StatusForbidden {
		t.Fatalf("a viewer cannot attest: %d", c)
	}
	if c := post(authn.DefaultAdminToken(tenantID), `{`+ok+`}`); c != http.StatusCreated {
		t.Fatalf("an admin attests for the whole tenant: %d", c)
	}
}
