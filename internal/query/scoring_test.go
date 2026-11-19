package query_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/query"
	"rampart/internal/store"
	"rampart/internal/version"
)

// The page that explains the score reads the policy in force; it never writes the numbers out by hand.
func TestScoringEndpointDescribesThePolicyInForce(t *testing.T) {
	mem := ingest.NewMemoryStore()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(mem)
	token := authn.DefaultAdminToken(tenantID)
	mux := http.NewServeMux()
	query.NewAPIWithAuth(mem, nil, authn).RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/v1/scoring", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got query.ScoringResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Version != version.Version || got.Product != "Rampart" {
		t.Errorf("version = %q %q", got.Product, got.Version)
	}
	if got.Risk.Base["critical"] != 600 || got.Risk.Bands["critical"] != 800 || got.Risk.Bands["low"] != 0 {
		t.Errorf("the base points and the bands are the built-in ones: %+v", got.Risk)
	}
	names := map[string]int{}
	for _, f := range got.Risk.Factors {
		names[f.Name] = f.Points
		if f.Group == "" || f.Reason == "" {
			t.Errorf("a factor must say its group and why: %+v", f)
		}
	}
	for name, pts := range map[string]int{"KEV": 300, "INTERNET_FACING": 100, "SENSITIVE_DATA": 80, "APP_CRITICAL": 100, "PRODUCTION_ENV": 60, "COMPENSATING_CONTROL": -80} {
		if names[name] != pts {
			t.Errorf("factor %s = %d, want %d", name, names[name], pts)
		}
	}
	if got.Customised {
		t.Error("with no policy of the tenant's own the built-in one runs, and the page must say it is not customised")
	}
	if got.SLA.Matrix["critical"]["critical"] != 3 || got.SLA.Matrix["low"]["low"] != 365 {
		t.Errorf("the SLA matrix is the real one: %+v", got.SLA.Matrix)
	}
}

// fakeWriter stands for the PostgreSQL store, which implements the writer.
type fakeWriter struct {
	*ingest.MemoryStore
	got   domain.ApplicationContextUpdate
	err   error
	calls int
}

func (f *fakeWriter) UpdateApplicationContext(_ context.Context, tenantID, appID uuid.UUID, u domain.ApplicationContextUpdate) (*domain.Application, error) {
	f.calls++
	f.got = u
	if f.err != nil {
		return nil, f.err
	}
	return &domain.Application{ID: appID, TenantID: tenantID, Slug: "shop", Name: "Shop", BusinessCriticality: *u.BusinessCriticality}, nil
}

func TestUpdateApplicationContext(t *testing.T) {
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	appID := uuid.New()
	patch := func(f *fakeWriter, role, body string) *httptest.ResponseRecorder {
		authn := auth.NewAuthenticatorWithStore(f.MemoryStore)
		token := authn.DefaultAdminToken(tenantID)
		if role == "viewer" {
			raw, rec, _ := auth.GenerateToken(tenantID, auth.RoleViewer, "plain", []string{"*"}, time.Hour)
			authn.RegisterToken(raw, rec)
			token = raw
		}
		mux := http.NewServeMux()
		query.NewAPIWithAuth(f, nil, authn).RegisterRoutes(mux)
		req := httptest.NewRequest("PATCH", "/api/v1/applications/"+appID.String(), bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	f := &fakeWriter{MemoryStore: ingest.NewMemoryStore()}
	rec := patch(f, "admin", `{"business_criticality":"CRITICAL","internet_facing":true,"data_classification":["PCI","pii","pci"],"compensating_controls":["apiGateway","waf"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if *f.got.BusinessCriticality != "critical" || !*f.got.InternetFacing || strings.Join(*f.got.DataClassification, ",") != "pci,pii" || strings.Join(*f.got.CompensatingControls, ",") != "api_gateway,waf" {
		t.Errorf("the update is normalised before it is stored: %+v", f.got)
	}

	for name, body := range map[string]string{
		"a typo":          `{"business_criticality":"urgent"}`,
		"an unknown data": `{"data_classification":["cards"]}`,
		"nothing":         `{}`,
		"an unknown key":  `{"owner":"me"}`,
		"a bad lifecycle": `{"lifecycle":"live"}`,
	} {
		f := &fakeWriter{MemoryStore: ingest.NewMemoryStore()}
		if rec := patch(f, "admin", body); rec.Code != http.StatusBadRequest || f.calls != 0 {
			t.Errorf("%s: status %d, stored %d times; it must be refused before the store", name, rec.Code, f.calls)
		}
	}

	f = &fakeWriter{MemoryStore: ingest.NewMemoryStore(), err: store.ErrManagedByResource}
	if rec := patch(f, "admin", `{"business_criticality":"high"}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "Application resource") {
		t.Errorf("an application a resource manages answers 409 and says why: %d %s", rec.Code, rec.Body.String())
	}
	f = &fakeWriter{MemoryStore: ingest.NewMemoryStore()}
	if rec := patch(f, "viewer", `{"business_criticality":"high"}`); rec.Code != http.StatusForbidden || f.calls != 0 {
		t.Errorf("a viewer must not change the score's context: %d", rec.Code)
	}
}

// The screens build their choices for an application from the scoring endpoint, so a value that the program accepts is a value they
// offer, and one it does not accept is not offered (D140).
func TestScoringEndpointListsWhatAnApplicationCanSay(t *testing.T) {
	mem := ingest.NewMemoryStore()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(mem)
	mux := http.NewServeMux()
	query.NewAPIWithAuth(mem, nil, authn).RegisterRoutes(mux)
	req := httptest.NewRequest("GET", "/api/v1/scoring", nil)
	req.Header.Set("Authorization", "Bearer "+authn.DefaultAdminToken(tenantID))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var got query.ScoringResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Environments, ",") != "production,staging,test,development" {
		t.Fatalf("environments: %v", got.Environments)
	}
	if strings.Join(got.ApplicationTypes, ",") != "repo" {
		t.Fatalf("only repo is built: %v", got.ApplicationTypes)
	}
}
