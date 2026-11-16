package query_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rampart/internal/auth"
	"rampart/internal/compliance"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/query"
	"rampart/internal/store"

	"github.com/google/uuid"
)

// fwStore gives the API a tenant framework with a logo address, and the readings an evaluation needs.
type fwStore struct {
	*ingest.MemoryStore
	specs  []store.StoredFramework
	scopes map[uuid.UUID][]string
	open   map[string]int // control id -> open findings (in "high")
}

func (s *fwStore) ListComplianceFrameworks(context.Context, uuid.UUID) ([]store.StoredFramework, error) {
	return s.specs, nil
}
func (s *fwStore) ApplicationComplianceScopes(context.Context, uuid.UUID) (map[uuid.UUID][]string, error) {
	return s.scopes, nil
}
func (s *fwStore) ControlCounts(_ context.Context, _ uuid.UUID, _ []uuid.UUID, cs []store.ControlMatch) (map[string]store.ControlCount, error) {
	out := map[string]store.ControlCount{}
	for _, c := range cs {
		out[c.ID] = store.ControlCount{Open: map[string]int{"high": s.open[c.ID]}}
	}
	return out, nil
}
func (s *fwStore) RecentScans(_ context.Context, _ uuid.UUID, apps []uuid.UUID, _ time.Time) ([]store.ScanEvidence, error) {
	var out []store.ScanEvidence
	for _, a := range apps {
		out = append(out, store.ScanEvidence{App: a, Family: "semgrep", At: time.Now()}, store.ScanEvidence{App: a, Family: "trivy", At: time.Now()})
	}
	return out, nil
}
func (s *fwStore) FamilyFindingCategories(context.Context, uuid.UUID) (map[string][]string, error) {
	return map[string][]string{"semgrep": {"sast"}, "trivy": {"sca"}}, nil
}
func (s *fwStore) Attestations(context.Context, uuid.UUID, string) ([]store.Attestation, error) {
	return nil, nil
}
func (s *fwStore) AddAttestation(context.Context, uuid.UUID, store.Attestation) error { return nil }
func (s *fwStore) SaveComplianceSnapshot(context.Context, uuid.UUID, string, time.Time, []byte) error {
	return nil
}
func (s *fwStore) ComplianceSnapshot(context.Context, uuid.UUID, string, time.Time) ([]byte, error) {
	return nil, store.ErrNoSnapshot
}
func (s *fwStore) ComplianceSnapshotDays(context.Context, uuid.UUID, string, int) ([]time.Time, error) {
	return nil, nil
}

func spec(name, logo, scope string, controls string) store.StoredFramework {
	sc := ""
	if scope != "" {
		sc = `,"appliesTo":{"complianceScope":"` + scope + `"}`
	}
	lg := ""
	if logo != "" {
		lg = `,"logoUrl":"` + logo + `"`
	}
	return store.StoredFramework{Origin: "tenant", Name: name,
		Spec: []byte(`{"displayName":"` + name + `","version":"1"` + lg + sc + `,"controls":[` + controls + `]}`)}
}

const (
	sastControl = `{"id":"SC-1","name":"No injection","match":{"categories":["sast"]}}`
	scaControl  = `{"id":"SC-2","name":"No vulnerable packages","match":{"categories":["sca"]}}`
	dastControl = `{"id":"SC-3","name":"No DAST findings","match":{"categories":["dast"]}}`
)

func setup(t *testing.T, s *fwStore) (*http.ServeMux, string, *query.API) {
	t.Helper()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(s.MemoryStore)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(s, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	return mux, token, api
}

func getAs(mux *http.ServeMux, token, url string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

const pngBytes = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"

func TestAPI_FrameworkLogoIsServedFromThisServer(t *testing.T) {
	s := &fwStore{MemoryStore: ingest.NewMemoryStore(), specs: []store.StoredFramework{
		spec("acme-policy", "https://logos.acme.example/mark.png", "", sastControl),
		spec("plain-policy", "", "", sastControl),
	}}
	mux, token, api := setup(t, s)
	var asked []string
	api.SetLogoFetcher(func(_ context.Context, u string) ([]byte, string, error) {
		asked = append(asked, u)
		return []byte(pngBytes), "image/png", nil
	})

	// The list says where the mark is, on this server, and never gives the address it came from.
	rec := getAs(mux, token, "/api/v1/taxonomies")
	var list struct{ Items []query.TaxonomyInfo }
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var acme, plain, builtin *query.TaxonomyInfo
	for i := range list.Items {
		switch it := &list.Items[i]; it.ID {
		case "acme-policy":
			acme = it
		case "plain-policy":
			plain = it
		case "owasp-top10-2021":
			builtin = it
		}
	}
	if acme == nil || !strings.HasPrefix(acme.Logo, "/api/v1/taxonomies/acme-policy/logo?v=") {
		t.Fatalf("a framework with a logoUrl is listed with a path on this server: %+v", acme)
	}
	if plain == nil || plain.Logo != "" || builtin == nil || builtin.Logo != "" {
		t.Errorf("a framework with no logoUrl has no logo (the screen draws its own): %+v %+v", plain, builtin)
	}
	if strings.Contains(rec.Body.String(), "logos.acme.example") {
		t.Error("the address of the logo must stay on the server")
	}

	// The mark: served with headers that keep it a picture, and read once.
	for i := 0; i < 3; i++ {
		img := getAs(mux, token, acme.Logo)
		if img.Code != 200 || img.Header().Get("Content-Type") != "image/png" || img.Body.String() != pngBytes {
			t.Fatalf("logo: %d %q", img.Code, img.Header().Get("Content-Type"))
		}
		if img.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(img.Header().Get("Content-Security-Policy"), "sandbox") {
			t.Errorf("the mark must be served with nosniff and a sandbox policy: %v", img.Header())
		}
	}
	if len(asked) != 1 || asked[0] != "https://logos.acme.example/mark.png" {
		t.Errorf("the address is read once, then kept: %v", asked)
	}

	for url, want := range map[string]int{
		"/api/v1/taxonomies/plain-policy/logo": 404, // no logoUrl
		"/api/v1/taxonomies/nope/logo":         404,
	} {
		if rec := getAs(mux, token, url); rec.Code != want {
			t.Errorf("%s: want %d, got %d", url, want, rec.Code)
		}
	}
	if rec := getAs(mux, "", acme.Logo); rec.Code != http.StatusUnauthorized {
		t.Errorf("a logo needs a session: %d", rec.Code)
	}
}

func TestAPI_FrameworkLogoFailureIsAnErrorNotAHang(t *testing.T) {
	s := &fwStore{MemoryStore: ingest.NewMemoryStore(), specs: []store.StoredFramework{spec("acme-policy", "https://logos.acme.example/x.png", "", sastControl)}}
	mux, token, api := setup(t, s)
	calls := 0
	api.SetLogoFetcher(func(context.Context, string) ([]byte, string, error) {
		calls++
		return nil, "", errors.New("the address answered 404")
	})
	for i := 0; i < 3; i++ {
		if rec := getAs(mux, token, "/api/v1/taxonomies/acme-policy/logo"); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "answered 404") {
			t.Fatalf("a dead address is 502 with the reason: %d %s", rec.Code, rec.Body.String())
		}
	}
	if calls != 1 {
		t.Errorf("a failure is remembered for a while, not asked at every view: %d calls", calls)
	}
}

// What an application meets today: every framework that reads it, with the controls clear, open and not read.
func TestAPI_ApplicationCompliance(t *testing.T) {
	appID := domain.NewID()
	s := &fwStore{
		MemoryStore: ingest.NewMemoryStore(),
		specs: []store.StoredFramework{
			spec("a-meets", "", "", sastControl+","+scaControl),
			spec("b-gaps", "https://logos.acme.example/b.png", "", sastControl+","+scaControl),
			spec("c-partial", "", "", sastControl+","+dastControl), // nobody ran a DAST scan
			spec("d-pci-only", "", "pci", sastControl),             // reads only applications that list "pci"
		},
		scopes: map[uuid.UUID][]string{appID: {"internal"}},
		open:   map[string]int{"SC-2": 0},
	}
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	if err := s.CreateApplication(context.Background(), &domain.Application{ID: appID, TenantID: tenantID, Slug: "shop", Name: "Shop"}); err != nil {
		t.Fatal(err)
	}
	mux, token, _ := setup(t, s)

	read := func() query.AppCompliance {
		rec := getAs(mux, token, "/api/v1/applications/"+appID.String()+"/compliance")
		var out query.AppCompliance
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		return out
	}
	by := func(o query.AppCompliance) map[string]query.AppFramework {
		m := map[string]query.AppFramework{}
		for _, f := range o.Frameworks {
			m[f.ID] = f
		}
		return m
	}

	got := by(read())
	if f := got["a-meets"]; f.Verdict != "meets" || f.Clear != 2 || f.Open != 0 || f.Controls != 2 {
		t.Errorf("a-meets: %+v", f)
	}
	if f := got["c-partial"]; f.Verdict != "partial" || f.Clear != 1 || f.Unread != 1 {
		t.Errorf("a control with no scan of its kind is not read, and the framework is partial: %+v", f)
	}
	if _, ok := got["d-pci-only"]; ok {
		t.Error("a framework with a scope reads only the applications that list it")
	}
	if out := read(); len(out.NotInScope) != 1 || out.NotInScope[0] != "d-pci-only" {
		t.Errorf("the screen must be able to say why a framework is missing: %v", out.NotInScope)
	}
	if len(got) < 9 { // the three of this test, and the six built in
		t.Errorf("the built-in frameworks read it too: %d", len(got))
	}
	if f := got["b-gaps"]; f.Logo == "" {
		t.Error("the logo path rides along, so the page needs no second request")
	}

	// A finding opens a control: gaps, with the count.
	s.open["SC-2"] = 3
	if f := by(read())["b-gaps"]; f.Verdict != "gaps" || f.Open != 1 || f.Findings != 3 || f.Clear != 1 {
		t.Errorf("b-gaps: %+v", f)
	}
	// The same application is in scope once it lists the scope.
	s.scopes[appID] = []string{"pci"}
	if _, ok := by(read())["d-pci-only"]; !ok {
		t.Error("an application that lists the scope is read by the framework")
	}

	for url, want := range map[string]int{
		"/api/v1/applications/not-a-uuid/compliance":               400,
		"/api/v1/applications/" + uuid.NewString() + "/compliance": 404,
	} {
		if rec := getAs(mux, token, url); rec.Code != want {
			t.Errorf("%s: want %d, got %d", url, want, rec.Code)
		}
	}
	if rec := getAs(mux, "", "/api/v1/applications/"+appID.String()+"/compliance"); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d", rec.Code)
	}
}

var _ = compliance.DefaultWindowDays
