package query_test

import (
	"context"
	"encoding/json"
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
	"rampart/internal/query/grammar"
	"rampart/internal/query/sqlbuilder"
	"rampart/internal/store"

	"github.com/google/uuid"
)

// queryStore answers QueryFindings with fixed findings, as PostgreSQL would for the filter cve:<id>.
type queryStore struct {
	*ingest.MemoryStore
	found []*domain.Finding
	asked string
}

func (q *queryStore) QueryFindings(_ context.Context, _ uuid.UUID, g *grammar.Query, _ string, _ int, _ *sqlbuilder.Cursor) ([]*domain.Finding, error) {
	if g != nil && len(g.Terms) > 0 && len(g.Terms[0].Values) > 0 {
		q.asked = g.Terms[0].Field + ":" + g.Terms[0].Values[0].Raw
	}
	return q.found, nil
}
func (q *queryStore) CountFindings(context.Context, uuid.UUID, *grammar.Query) (int, error) {
	return len(q.found), nil
}

type fakeIntel struct{ rec *enrich.VulnerabilityRecord }

func (f fakeIntel) Lookup(context.Context, []string) (*enrich.FeedStore, error) {
	return enrich.NewFeedStore(), nil
}
func (f fakeIntel) Record(_ context.Context, id string) (*enrich.VulnerabilityRecord, error) {
	if f.rec != nil && f.rec.ID == id {
		return f.rec, nil
	}
	return nil, nil
}

// Clicking a CVE must say in how many applications it is found, and describe it from the feeds even when the
// report that carried it held only the id. docs/11 specified both routes; neither existed, and the page
// aggregated the first 200 open findings in the browser.
func TestAPI_VulnerabilityRecordAndImpact(t *testing.T) {
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	mem := ingest.NewMemoryStore()
	appA, appB := &domain.Application{ID: domain.NewID(), TenantID: tenantID, Slug: "shop", Name: "Shop"}, &domain.Application{ID: domain.NewID(), TenantID: tenantID, Slug: "api", Name: "API"}
	for _, a := range []*domain.Application{appA, appB} {
		if err := mem.CreateApplication(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	asset1, asset2, asset3 := domain.NewID(), domain.NewID(), domain.NewID()
	mk := func(app *domain.Application, asset uuid.UUID, st domain.FindingState, sev domain.Severity, score int) *domain.Finding {
		return &domain.Finding{ID: domain.NewID(), TenantID: tenantID, ApplicationID: app.ID, AssetID: asset, State: st, Severity: sev, RiskScore: score, FirstSeen: time.Now(), LastSeen: time.Now()}
	}
	qs := &queryStore{MemoryStore: mem, found: []*domain.Finding{
		mk(appA, asset1, domain.StateOpen, domain.SeverityCritical, 1000),
		mk(appA, asset2, domain.StateOpen, domain.SeverityHigh, 700),
		mk(appA, asset2, domain.StateFixed, domain.SeverityCritical, 900), // fixed: counted as a finding, not as open
		mk(appB, asset3, domain.StateOpen, domain.SeverityMedium, 400),
	}}
	authn := auth.NewAuthenticatorWithStore(mem)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(qs, nil, authn)
	kevAdded := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)
	api.SetIntelSource(fakeIntel{rec: &enrich.VulnerabilityRecord{ID: "CVE-2021-44228", Summary: "Log4Shell", KEV: true, KEVDateAdded: &kevAdded, Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, CWEs: []int{917}, Links: enrich.VulnerabilityLinks("CVE-2021-44228", true)}})
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	get := func(url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// The record, by id or in lower case; an id no feed has still gets the public links.
	for _, id := range []string{"CVE-2021-44228"} {
		rec := get("/api/v1/vulnerabilities/" + id)
		var got query.VulnerabilityResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || !got.Known || got.Record == nil || got.Record.Summary != "Log4Shell" || !got.Record.KEV {
			t.Fatalf("record of %s: %d %s", id, rec.Code, rec.Body.String())
		}
	}
	var unknown query.VulnerabilityResponse
	if rec := get("/api/v1/vulnerabilities/CVE-2099-0001"); rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &unknown) != nil || unknown.Known || len(unknown.Links) == 0 {
		t.Fatalf("an unknown id must be 200, known=false, with links: %d %s", rec.Code, rec.Body.String())
	}

	// The impact: two applications, the one with more open findings first, assets counted once.
	rec := get("/api/v1/vulnerabilities/CVE-2021-44228/impact")
	var imp query.VulnerabilityImpact
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &imp) != nil {
		t.Fatalf("impact: %d %s", rec.Code, rec.Body.String())
	}
	if qs.asked != "cve:CVE-2021-44228" {
		t.Errorf("the impact must ask for the id or its aliases (cve:), asked %q", qs.asked)
	}
	if imp.Findings != 4 || imp.Open != 3 || len(imp.Applications) != 2 {
		t.Fatalf("want 4 findings, 3 open, 2 applications: %+v", imp)
	}
	first := imp.Applications[0]
	if first.Slug != "shop" || first.Open != 2 || first.Findings != 3 || first.MaxSeverity != domain.SeverityCritical || first.MaxScore != 1000 || len(first.AssetIDs) != 2 {
		t.Errorf("first application wrong: %+v", first)
	}

	// An id with a query in it is refused, not parsed.
	for _, bad := range []string{"CVE-1%20OR%20severity:low", "a%2Fb", "%00"} {
		if rec := get("/api/v1/vulnerabilities/" + bad + "/impact"); rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Errorf("id %q: want 400/404, got %d", bad, rec.Code)
		}
	}
	if rec := httptest.NewRecorder(); true {
		mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/vulnerabilities/CVE-2021-44228/impact", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("no credentials: want 401, got %d", rec.Code)
		}
	}
}

type inventoryStore struct {
	*ingest.MemoryStore
	assets []store.InventoryAsset
	comps  []store.InventoryComponent
	gotQ   string
	gotLim int
}

func (s *inventoryStore) ListInventoryAssets(context.Context, uuid.UUID, int) ([]store.InventoryAsset, error) {
	return s.assets, nil
}
func (s *inventoryStore) ListInventoryComponents(_ context.Context, _ uuid.UUID, q string, limit int) ([]store.InventoryComponent, int, error) {
	s.gotQ, s.gotLim = q, limit
	return s.comps, len(s.comps) + 5, nil
}

func TestAPI_Inventory(t *testing.T) {
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	mem := ingest.NewMemoryStore()
	is := &inventoryStore{MemoryStore: mem, assets: []store.InventoryAsset{{ID: uuid.New(), Name: "shop", Kind: "repository", Total: 3}}, comps: []store.InventoryComponent{{Name: "lodash", Version: "4", Type: "npm"}}}
	authn := auth.NewAuthenticatorWithStore(mem)
	token := authn.DefaultAdminToken(tenantID)
	mux := http.NewServeMux()
	query.NewAPIWithAuth(is, nil, authn).RegisterRoutes(mux)
	get := func(url string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", url, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	if rec := get("/api/v1/inventory", true); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"assets":[{`) || !strings.Contains(rec.Body.String(), `"kind":"repository"`) {
		t.Errorf("assets: %d %s", rec.Code, rec.Body.String())
	}
	rec := get("/api/v1/inventory/components?q=lod&limit=10", true)
	if rec.Code != 200 || is.gotQ != "lod" || is.gotLim != 10 || !strings.Contains(rec.Body.String(), `"truncated":true`) || !strings.Contains(rec.Body.String(), `"total":6`) {
		t.Errorf("components: %d %s (q=%q limit=%d)", rec.Code, rec.Body.String(), is.gotQ, is.gotLim)
	}
	for _, bad := range []string{"limit=0", "limit=-1", "limit=abc", "limit=99999", "q=" + strings.Repeat("a", 201)} {
		if rec := get("/api/v1/inventory/components?"+bad, true); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", bad, rec.Code)
		}
	}
	for _, u := range []string{"/api/v1/inventory", "/api/v1/inventory/components"} {
		if rec := get(u, false); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without credentials: want 401, got %d", u, rec.Code)
		}
	}

	// Scanning without credentials -> 401
	postScan := func(body string, auth bool) *httptest.ResponseRecorder {
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest("POST", "/api/v1/inventory/components/scan", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r = httptest.NewRequest("POST", "/api/v1/inventory/components/scan", nil)
		}
		if auth {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}
	if rec := postScan(`{"purl":"pkg:npm/lodash@4.17.20"}`, false); rec.Code != http.StatusUnauthorized {
		t.Errorf("scan without credentials: want 401, got %d", rec.Code)
	}

	// docs/51 step 2.12: scanning one component is not built. It used to ignore the purl and re-score the whole tenant;
	// now it says so with 501 and a detail the screens show, with or without a purl.
	for _, body := range []string{`{}`, `{"purl":"pkg:npm/lodash@4.17.20","name":"lodash","version":"4.17.20"}`} {
		rec := postScan(body, true)
		if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Header().Get("Content-Type"), "application/problem+json") || !strings.Contains(rec.Body.String(), `"detail"`) {
			t.Errorf("scan %s: want 501 problem with a detail, got %d %s", body, rec.Code, rec.Body.String())
		}
	}

	// App components endpoint -> 200 with matching application components
	appID := uuid.New()
	_ = mem.CreateApplication(context.Background(), &domain.Application{ID: appID, TenantID: tenantID, Name: "Shop", Slug: "shop"})
	is.comps = append(is.comps, store.InventoryComponent{Name: "express", Version: "4.18.2", Application: "Shop", Vulnerabilities: 2})
	recApp := get("/api/v1/applications/"+appID.String()+"/components", true)
	if recApp.Code != 200 || !strings.Contains(recApp.Body.String(), "express") || !strings.Contains(recApp.Body.String(), `"vulnerabilities":2`) {
		t.Errorf("app components: %d %s", recApp.Code, recApp.Body.String())
	}
	// The in-memory store has no inventory: 501, not a 500 or an empty list that hides it.
	mux2 := http.NewServeMux()
	query.NewAPIWithAuth(mem, nil, authn).RegisterRoutes(mux2)
	req := httptest.NewRequest("GET", "/api/v1/inventory", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	mux2.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNotImplemented {
		t.Errorf("no inventory store: want 501, got %d", rec2.Code)
	}
}
