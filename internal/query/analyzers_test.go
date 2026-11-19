package query_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	"rampart/internal/analyzer/client"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/query"
	analyzerv1 "rampart/pkg/api/analyzer/v1"
)

type analyzerRig struct {
	t       *testing.T
	st      *ingest.MemoryStore
	api     *query.API
	mux     *http.ServeMux
	tenant  uuid.UUID
	admin   string
	viewer  string
	triager string
}

func newAnalyzerRig(t *testing.T) *analyzerRig {
	t.Helper()
	st := ingest.NewMemoryStore()
	authn := auth.NewAuthenticatorWithStore(st)
	tenant := domain.NewID()
	r := &analyzerRig{t: t, st: st, tenant: tenant}
	r.admin = auth.FormatToken(tenant, "admin_token_for_analyzers_api")
	r.viewer = auth.FormatToken(tenant, "viewer_token_for_analyzers_api")
	authn.RegisterToken(r.admin, &auth.TokenRecord{ID: domain.NewID(), TenantID: tenant, Subject: "ada", Role: auth.RoleAdmin, CreatedAt: time.Now().UTC()})
	r.triager = auth.FormatToken(tenant, "triager_token_for_analyzers_api")
	authn.RegisterToken(r.triager, &auth.TokenRecord{ID: domain.NewID(), TenantID: tenant, Subject: "tess", Role: auth.RoleTriager, CreatedAt: time.Now().UTC()})
	authn.RegisterToken(r.viewer, &auth.TokenRecord{ID: domain.NewID(), TenantID: tenant, Subject: "vera", Role: auth.RoleViewer, CreatedAt: time.Now().UTC()})
	r.api = query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	r.mux = http.NewServeMux()
	r.api.RegisterRoutes(r.mux)
	return r
}

func (r *analyzerRig) call(token, method, path, body string) (int, map[string]any) {
	r.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.mux.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// gRPC analyzer on a loopback port, the real contract.
type fakeAnalyzer struct {
	analyzerv1.UnimplementedAnalyzerServiceServer
	status analyzerv1.HealthCheckResponse_ServingStatus
	msg    string
}

func (f *fakeAnalyzer) HealthCheck(context.Context, *analyzerv1.HealthCheckRequest) (*analyzerv1.HealthCheckResponse, error) {
	return &analyzerv1.HealthCheckResponse{Status: f.status, Message: f.msg}, nil
}
func (f *fakeAnalyzer) GetMetadata(context.Context, *analyzerv1.GetMetadataRequest) (*analyzerv1.GetMetadataResponse, error) {
	return &analyzerv1.GetMetadataResponse{Name: "Sonatype OSS Index", Version: "0.1.0", SupportedEcosystems: []string{"npm", "maven", "pypi"}}, nil
}

func startFakeAnalyzer(t *testing.T, f *fakeAnalyzer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	analyzerv1.RegisterAnalyzerServiceServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func jsonOf(v map[string]any) string { b, _ := json.Marshal(v); return string(b) }

func (r *analyzerRig) analyzers(token string) []map[string]any {
	r.t.Helper()
	code, out := r.call(token, http.MethodGet, "/api/v1/analyzers", "")
	if code != http.StatusOK {
		r.t.Fatalf("list: %d %v", code, out)
	}
	var items []map[string]any
	for _, x := range out["analyzers"].([]any) {
		items = append(items, x.(map[string]any))
	}
	return items
}

func TestAnalyzersTab_ListsEveryKindWithItsOwnFieldsAndTheReasonForARefusal(t *testing.T) {
	r := newAnalyzerRig(t)
	r.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, "sonatype", []byte(`{"service":{"name":"sonatype","namespace":"tools","port":50051},"timeoutSeconds":45}`), "")
	r.st.SaveTenantAnalyzer(r.tenant, domain.AnalyzerKindExternal, "acme-ns", "mine", []byte(`{"enabled":false,"service":{"name":"mine","port":9000}}`), "")
	r.st.SaveClusterAnalyzer(domain.AnalyzerKindSBOM, "native-matcher", []byte(`{"engine":"osv","rules":{"minConfidence":0.9,"matchDirectOnly":true},"sources":{"nvd":true},"schedule":"0 3 * * *"}`), "")
	r.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, "web", []byte(`{"protocol":"http","endpoint":"a:1"}`), "protocol http: no HTTP client is built")

	items := r.analyzers(r.viewer) // a viewer may look
	if len(items) != 4 {
		t.Fatalf("four analyzers: %v", items)
	}
	byName := map[string]map[string]any{}
	var order []string
	for _, it := range items {
		byName[it["name"].(string)] = it
		order = append(order, it["kind"].(string)+"/"+it["scope"].(string)+"/"+it["name"].(string))
	}
	// external first, the cluster's before the tenant's, then by name; the matcher last
	if strings.Join(order, ",") != "external/cluster/sonatype,external/cluster/web,external/tenant/mine,sbom/cluster/native-matcher" {
		t.Fatalf("order: %v", order)
	}
	s := byName["sonatype"]
	if s["target"] != "sonatype.tools.svc.cluster.local:50051" || s["protocol"] != "grpc" || s["timeout_seconds"] != float64(45) || s["enabled"] != true || s["ready"] != true || s["last_event"] != nil {
		t.Fatalf("external cluster analyzer: %v", s)
	}
	m := byName["mine"]
	if m["target"] != "mine.acme-ns.svc.cluster.local:9000" || m["enabled"] != false || m["namespace"] != "acme-ns" || m["timeout_seconds"] != float64(60) {
		t.Fatalf("a tenant's service in no namespace is in its own, and the default timeout is shown: %v", m)
	}
	n := byName["native-matcher"]
	src := n["sources"].(map[string]any)
	if n["engine"] != "osv" || n["min_confidence"] != 0.9 || n["match_direct_only"] != true || n["schedule"] != "0 3 * * *" || src["nvd"] != true || src["osv"] != true || src["ghsa"] != true {
		t.Fatalf("the matcher: %v", n)
	}
	w := byName["web"]
	if w["ready"] != false || !strings.Contains(w["error"].(string), "no HTTP client") {
		t.Fatalf("a refused analyzer says why: %v", w)
	}

	// another tenant sees the cluster's analyzers and none of this tenant's
	otherTenant := domain.NewID()
	other := auth.FormatToken(otherTenant, "other_tenant_token_analyzers")
	authn2 := auth.NewAuthenticatorWithStore(r.st)
	authn2.RegisterToken(other, &auth.TokenRecord{ID: domain.NewID(), TenantID: otherTenant, Subject: "o", Role: auth.RoleViewer, CreatedAt: time.Now().UTC()})
	mux := http.NewServeMux()
	query.NewAPIWithAuth(r.st, enrich.NewFeedStore(), authn2).RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analyzers", nil)
	req.Header.Set("Authorization", "Bearer "+other)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out struct {
		Analyzers []struct{ Scope, Name string } `json:"analyzers"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Analyzers) != 3 {
		t.Fatalf("the other tenant sees the three cluster analyzers: %s", rec.Body.String())
	}
	for _, a := range out.Analyzers {
		if a.Scope != "cluster" {
			t.Fatalf("the other tenant must not see %s: %s", a.Name, rec.Body.String())
		}
	}
	if code, _ := r.call("", http.MethodGet, "/api/v1/analyzers", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
}

func TestTestingAnExternalAnalyzer_CallsItAndKeepsTheAnswerAsAnEvent(t *testing.T) {
	r := newAnalyzerRig(t)
	fake := &fakeAnalyzer{status: analyzerv1.HealthCheckResponse_SERVING, msg: "ready; last call to Sonatype succeeded"}
	addr := startFakeAnalyzer(t, fake)
	r.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, "sonatype", []byte(`{"endpoint":"`+addr+`","timeoutSeconds":5}`), "")
	body := jsonOf(map[string]any{"kind": "external", "scope": "cluster", "name": "sonatype"})

	code, out := r.call(r.admin, http.MethodPost, "/api/v1/analyzers/test", body)
	if code != http.StatusOK || out["ok"] != true || out["outcome"] != "succeeded" || !strings.Contains(out["message"].(string), "Serving: Sonatype OSS Index 0.1.0, 3 package types") {
		t.Fatalf("a serving analyzer: %d %v", code, out)
	}
	d := out["detail"].(map[string]any)
	if d["target"] != addr || d["version"] != "0.1.0" || d["package_types"] != "npm,maven,pypi" || d["analyzer_says"] != "ready; last call to Sonatype succeeded" {
		t.Fatalf("detail: %v", d)
	}

	// it stops serving: the same test now fails, and says what the analyzer says
	fake.status, fake.msg = analyzerv1.HealthCheckResponse_NOT_SERVING, "Sonatype rejected the token at 2026-11-19T03:41:21Z (401)"
	code, out = r.call(r.admin, http.MethodPost, "/api/v1/analyzers/test", body)
	if code != http.StatusOK || out["ok"] != false || !strings.Contains(out["message"].(string), "not serving: Sonatype rejected the token") {
		t.Fatalf("a not-serving analyzer: %d %v", code, out)
	}

	// the two answers are events, newest first, and the list shows the last one
	_, ev := r.call(r.viewer, http.MethodGet, "/api/v1/analyzers/events?kind=external&scope=cluster&name=sonatype", "")
	events := ev["events"].([]any)
	if len(events) != 2 {
		t.Fatalf("two events: %v", ev)
	}
	first, second := events[0].(map[string]any), events[1].(map[string]any)
	if first["outcome"] != "failed" || second["outcome"] != "succeeded" || first["event"] != "test" || first["actor"] != "user:ada" {
		t.Fatalf("events: %v / %v", first, second)
	}
	items := r.analyzers(r.viewer)
	le := items[0]["last_event"].(map[string]any)
	if le["outcome"] != "failed" || !strings.Contains(le["message"].(string), "not serving") {
		t.Fatalf("the list says how the last test went: %v", items[0])
	}
}

func TestTestingAnExternalAnalyzer_SaysWhyItFailed(t *testing.T) {
	r := newAnalyzerRig(t)
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := lis.Addr().String()
	_ = lis.Close() // nothing listens here
	r.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, "down", []byte(`{"endpoint":"`+closed+`","timeoutSeconds":2}`), "")
	r.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, "web", []byte(`{"protocol":"http","endpoint":"a:1"}`), "protocol http: no HTTP client is built")
	r.st.SaveTenantAnalyzer(r.tenant, domain.AnalyzerKindExternal, "acme-ns", "ssrf", []byte(`{"endpoint":"169.254.169.254:80"}`), "a namespaced ExternalAnalyzer may name a service, not an endpoint")

	code, out := r.call(r.admin, http.MethodPost, "/api/v1/analyzers/test", jsonOf(map[string]any{"kind": "external", "scope": "cluster", "name": "down"}))
	if code != http.StatusOK || out["ok"] != false || !strings.Contains(out["message"].(string), "Could not reach "+closed) {
		t.Fatalf("an address nobody listens on: %d %v", code, out)
	}
	// a refused spec is not dialled: the test says the spec is refused
	code, out = r.call(r.admin, http.MethodPost, "/api/v1/analyzers/test", jsonOf(map[string]any{"kind": "external", "scope": "cluster", "name": "web"}))
	if code != http.StatusOK || out["ok"] != false || !strings.Contains(out["message"].(string), "spec is refused") {
		t.Fatalf("a refused spec: %d %v", code, out)
	}
	code, out = r.call(r.admin, http.MethodPost, "/api/v1/analyzers/test", jsonOf(map[string]any{"kind": "external", "scope": "tenant", "namespace": "acme-ns", "name": "ssrf"}))
	if code != http.StatusOK || out["ok"] != false || !strings.Contains(out["message"].(string), "not an endpoint") {
		t.Fatalf("a tenant's analyzer that names an address is never dialled: %d %v", code, out)
	}
	// every one of those is an event too
	_, ev := r.call(r.admin, http.MethodGet, "/api/v1/analyzers/events?kind=external&scope=cluster&name=down", "")
	if evs := ev["events"].([]any); len(evs) != 1 || evs[0].(map[string]any)["outcome"] != "failed" {
		t.Fatalf("the failure is kept: %v", ev)
	}
}

func TestTestingAnExternalAnalyzer_UsesTheProbeItIsGiven(t *testing.T) {
	r := newAnalyzerRig(t)
	r.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, "secure", []byte(`{"service":{"name":"a","namespace":"tools","port":1},"tls":{"insecure":false},"timeoutSeconds":600}`), "")
	var gotTarget string
	var gotSecure bool
	var gotDeadline time.Duration
	r.api.SetAnalyzerProbe(func(ctx context.Context, target string, secure bool) (client.ProbeResult, error) {
		gotTarget, gotSecure = target, secure
		dl, _ := ctx.Deadline()
		gotDeadline = time.Until(dl)
		return client.ProbeResult{Serving: true, Name: "x", Version: "1", Latency: time.Millisecond}, nil
	})
	code, out := r.call(r.admin, http.MethodPost, "/api/v1/analyzers/test", jsonOf(map[string]any{"kind": "external", "scope": "cluster", "name": "secure"}))
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if gotTarget != "a.tools.svc.cluster.local:1" || !gotSecure {
		t.Fatalf("the spec's target and its TLS choice reach the probe: %s %v", gotTarget, gotSecure)
	}
	if gotDeadline > 31*time.Second || gotDeadline < 20*time.Second {
		t.Fatalf("a test is bounded to 30 seconds whatever the spec asks (600): %s", gotDeadline)
	}
}

func TestTestingTheMatcher_ChecksThatThereIsAdvisoryDataToMatchAgainst(t *testing.T) {
	r := newAnalyzerRig(t)
	r.st.SaveClusterAnalyzer(domain.AnalyzerKindSBOM, "native-matcher", []byte(`{"engine":"hybrid"}`), "")
	body := jsonOf(map[string]any{"kind": "sbom", "scope": "cluster", "name": "native-matcher"})
	_, out := r.call(r.admin, http.MethodPost, "/api/v1/analyzers/test", body)
	if out["ok"] != false || !strings.Contains(out["message"].(string), "No advisory data is loaded") {
		t.Fatalf("no data: %v", out)
	}
	r.st.SetAdvisorySummary(domain.AdvisorySummary{Ranges: 1500, Ecosystems: []domain.EcosystemAdvisory{{Ecosystem: "npm", Ranges: 1000}, {Ecosystem: "Go", Ranges: 500}}})
	_, out = r.call(r.admin, http.MethodPost, "/api/v1/analyzers/test", body)
	if out["ok"] != true || out["message"] != "1500 affected ranges in 2 ecosystems are loaded for the matcher" {
		t.Fatalf("with data: %v", out)
	}
}

func TestTestingAnAnalyzer_NeedsAnAdministratorAndAnAnalyzerThatIsTheTenants(t *testing.T) {
	r := newAnalyzerRig(t)
	r.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, "sonatype", []byte(`{"endpoint":"127.0.0.1:1"}`), "")
	r.st.SaveTenantAnalyzer(domain.NewID(), domain.AnalyzerKindExternal, "other-ns", "theirs", []byte(`{"service":{"name":"a","port":1}}`), "")
	body := jsonOf(map[string]any{"kind": "external", "scope": "cluster", "name": "sonatype"})
	if code, _ := r.call(r.viewer, http.MethodPost, "/api/v1/analyzers/test", body); code != http.StatusForbidden {
		t.Fatalf("a viewer may not make the server dial an address: %d", code)
	}
	if code, _ := r.call("", http.MethodPost, "/api/v1/analyzers/test", body); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	for name, b := range map[string]string{
		"no such analyzer":       jsonOf(map[string]any{"kind": "external", "scope": "cluster", "name": "nope"}),
		"another tenant's":       jsonOf(map[string]any{"kind": "external", "scope": "tenant", "namespace": "other-ns", "name": "theirs"}),
		"the wrong kind of name": jsonOf(map[string]any{"kind": "sbom", "scope": "cluster", "name": "sonatype"}),
	} {
		if code, _ := r.call(r.admin, http.MethodPost, "/api/v1/analyzers/test", b); code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d", name, code)
		}
	}
	for name, b := range map[string]string{
		"not json":      `nope`,
		"unknown kind":  jsonOf(map[string]any{"kind": "magic", "scope": "cluster", "name": "x"}),
		"unknown scope": jsonOf(map[string]any{"kind": "external", "scope": "galaxy", "name": "x"}),
		"no name":       jsonOf(map[string]any{"kind": "external", "scope": "cluster"}),
	} {
		if code, _ := r.call(r.admin, http.MethodPost, "/api/v1/analyzers/test", b); code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
	for _, q := range []string{"", "?kind=external&scope=cluster", "?kind=x&scope=cluster&name=a", "?kind=external&scope=cluster&name=a&limit=0", "?kind=external&scope=cluster&name=a&limit=500"} {
		if code, _ := r.call(r.viewer, http.MethodGet, "/api/v1/analyzers/events"+q, ""); code != http.StatusBadRequest {
			t.Errorf("events%s: want 400, got %d", q, code)
		}
	}
}

// recordingDispatcher stands for the analysis service: it records what it was asked and answers with the count a test sets.
type recordingDispatcher struct {
	analyzers []domain.AnalyzerRef
	assets    []uuid.UUID
	tenants   []uuid.UUID
	triggers  []domain.AnalysisTrigger
	n         int
	err       error
}

func (d *recordingDispatcher) DispatchAnalyzer(_ context.Context, t uuid.UUID, ref domain.AnalyzerRef, tr domain.AnalysisTrigger) (int, error) {
	d.analyzers, d.tenants, d.triggers = append(d.analyzers, ref), append(d.tenants, t), append(d.triggers, tr)
	return d.n, d.err
}

func (d *recordingDispatcher) DispatchAsset(_ context.Context, t, asset uuid.UUID, tr domain.AnalysisTrigger) (int, error) {
	d.assets, d.tenants, d.triggers = append(d.assets, asset), append(d.tenants, t), append(d.triggers, tr)
	return d.n, d.err
}

func TestAnalyze_AnAdministratorAsksOneAnalyzerToAnalyseEverySBOM(t *testing.T) {
	r := newAnalyzerRig(t)
	d := &recordingDispatcher{n: 7}
	r.api.SetAnalysisDispatcher(d)
	body := `{"kind":"external","scope":"cluster","namespace":"","name":"sonatype"}`

	if code, _ := r.call(r.viewer, "POST", "/api/v1/analyzers/analyze", body); code != http.StatusForbidden {
		t.Fatalf("a viewer: %d", code)
	}
	if code, _ := r.call("", "POST", "/api/v1/analyzers/analyze", body); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	code, out := r.call(r.admin, "POST", "/api/v1/analyzers/analyze", body)
	if code != http.StatusAccepted || out["queued"] != float64(7) {
		t.Fatalf("admin: %d %v", code, out)
	}
	if len(d.analyzers) != 1 || d.analyzers[0] != (domain.AnalyzerRef{Kind: "external", Scope: "cluster", Name: "sonatype"}) || d.tenants[0] != r.tenant || d.triggers[0] != domain.TriggerManual {
		t.Fatalf("asked for: %+v tenant %v trigger %v", d.analyzers, d.tenants, d.triggers)
	}
	// a tenant's own analyzer carries its namespace; a cluster one does not, whatever the body says
	r.call(r.admin, "POST", "/api/v1/analyzers/analyze", `{"kind":"sbom","scope":"tenant","namespace":"acme","name":"mine"}`)
	r.call(r.admin, "POST", "/api/v1/analyzers/analyze", `{"kind":"sbom","scope":"cluster","namespace":"ignored","name":"c"}`)
	if d.analyzers[1].Namespace != "acme" || d.analyzers[2].Namespace != "" {
		t.Fatalf("namespaces: %+v", d.analyzers)
	}

	for body, why := range map[string]string{
		`{"kind":"other","scope":"cluster","name":"x"}`:    "kind",
		`{"kind":"external","scope":"world","name":"x"}`:   "scope",
		`{"kind":"external","scope":"cluster","name":" "}`: "name",
		`nope`: "not json",
	} {
		if code, _ := r.call(r.admin, "POST", "/api/v1/analyzers/analyze", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d", why, code)
		}
	}
	d.err = domain.ErrNoSuchAnalyzer
	if code, _ := r.call(r.admin, "POST", "/api/v1/analyzers/analyze", body); code != http.StatusNotFound {
		t.Fatalf("an analyzer that is not there: %d", code)
	}
	d.err, d.n = context.DeadlineExceeded, 0
	if code, _ := r.call(r.admin, "POST", "/api/v1/analyzers/analyze", body); code != http.StatusInternalServerError {
		t.Fatalf("nothing could be queued: %d", code)
	}
}

func TestAnalyze_ItIsRefusedWhenAnalysisIsSwitchedOff(t *testing.T) {
	r := newAnalyzerRig(t) // no dispatcher
	code, out := r.call(r.admin, "POST", "/api/v1/analyzers/analyze", `{"kind":"external","scope":"cluster","name":"x"}`)
	if code != http.StatusConflict || !strings.Contains(fmt.Sprint(out), "analysis.enabled") {
		t.Fatalf("analyzer: %d %v", code, out)
	}
	if code, _ := r.call(r.admin, "POST", "/api/v1/assets/"+uuid.NewString()+"/analyze", ""); code != http.StatusConflict {
		t.Fatalf("asset: %d", code)
	}
}

func TestAnalyze_ATriagerAsksForOneAsset(t *testing.T) {
	r := newAnalyzerRig(t)
	d := &recordingDispatcher{n: 2}
	r.api.SetAnalysisDispatcher(d)
	asset := uuid.New()
	if code, _ := r.call(r.viewer, "POST", "/api/v1/assets/"+asset.String()+"/analyze", ""); code != http.StatusForbidden {
		t.Fatalf("a viewer: %d", code)
	}
	code, out := r.call(r.triager, "POST", "/api/v1/assets/"+asset.String()+"/analyze", "")
	if code != http.StatusAccepted || out["queued"] != float64(2) {
		t.Fatalf("triager: %d %v", code, out)
	}
	// analysing with one analyzer everywhere is an administrator's, not a triager's
	if code, _ := r.call(r.triager, "POST", "/api/v1/analyzers/analyze", `{"kind":"external","scope":"cluster","name":"x"}`); code != http.StatusForbidden {
		t.Fatalf("a triager asking one analyzer to run everywhere: %d", code)
	}
	if len(d.assets) != 1 || d.assets[0] != asset || d.tenants[0] != r.tenant || d.triggers[0] != domain.TriggerManual {
		t.Fatalf("asked for: %v %v %v", d.assets, d.tenants, d.triggers)
	}
	if code, _ := r.call(r.admin, "POST", "/api/v1/assets/not-a-uuid/analyze", ""); code != http.StatusBadRequest {
		t.Fatalf("a bad id: %d", code)
	}
}
