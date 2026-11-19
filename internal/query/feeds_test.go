package query_test

import (
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
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/query"
)

func TestFeedsAPI(t *testing.T) {
	st := ingest.NewMemoryStore()
	feeds := enrich.NewFeedStore()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")

	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, feeds, authn)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// 1. Unauthenticated request -> 401
	unauthReq := httptest.NewRequest("GET", "/api/v1/feeds", nil)
	unauthRec := httptest.NewRecorder()
	mux.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", unauthRec.Code)
	}

	// 2. Default feeds with no mirror configured
	req := httptest.NewRequest("GET", "/api/v1/feeds", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp query.FeedsListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Mirror != nil {
		t.Fatalf("expected nil mirror initially, got %+v", resp.Mirror)
	}
	if len(resp.Items) < 4 {
		t.Fatalf("expected at least 4 default feeds, got %d", len(resp.Items))
	}
	for _, it := range resp.Items {
		if !it.Enabled {
			t.Errorf("feed %s should be enabled by default", it.Name)
		}
		if it.Status != "idle" {
			t.Errorf("feed %s should be idle initially, got %s", it.Name, it.Status)
		}
		if it.IsMirror {
			t.Errorf("feed %s should not be marked mirror by default", it.Name)
		}
	}

	// 3. Configure mirror and sync states
	now := time.Now().UTC()
	st.SetFeedState(domain.FeedState{
		Feed:     "cisa_kev",
		Status:   "success",
		Records:  1284,
		LastSync: &now,
	})
	st.SetFeedState(domain.FeedState{
		Feed:     "first_epss",
		Status:   "success",
		Records:  245000,
		LastSync: &now,
	})

	mirror := &domain.FeedMirrorSpec{
		Egress: "allow",
		KEV: &domain.FeedMirrorSource{
			URL: "https://mirror.internal/kev.json",
		},
		Vulnrichment: &domain.FeedSource{
			URL: "https://mirror.internal/vulnrichment.zip",
		},
		Custom: []domain.CustomFeed{
			{
				Name:   "inhouse-intel",
				Format: domain.CustomFeedIntelJSONL,
				URL:    "https://mirror.internal/inhouse.jsonl",
			},
		},
	}
	st.SetClusterFeedMirror(mirror)

	req = httptest.NewRequest("GET", "/api/v1/feeds", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp2 query.FeedsListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp2.Mirror == nil || resp2.Mirror.KEV == nil || resp2.Mirror.KEV.URL != "https://mirror.internal/kev.json" {
		t.Fatalf("expected mirror to be set in response, got %+v", resp2.Mirror)
	}

	byName := make(map[string]query.FeedItemResponse)
	for _, it := range resp2.Items {
		byName[it.Name] = it
	}

	kev := byName["cisa_kev"]
	if !kev.IsMirror || kev.URL != "https://mirror.internal/kev.json" {
		t.Errorf("expected KEV mirror url, got %s, isMirror=%v", kev.URL, kev.IsMirror)
	}
	if kev.Status != "success" || kev.Records != 1284 {
		t.Errorf("expected KEV status=success, records=1284, got status=%s, records=%d", kev.Status, kev.Records)
	}

	epss := byName["first_epss"]
	if epss.Status != "success" || epss.Records != 245000 {
		t.Errorf("expected EPSS status=success, records=245000, got status=%s, records=%d", epss.Status, epss.Records)
	}

	vulnrichment, hasVulnrichment := byName["vulnrichment"]
	if !hasVulnrichment || !vulnrichment.Enabled {
		t.Errorf("expected vulnrichment feed to be present and enabled")
	}

	customFeed, hasCustom := byName["inhouse-intel"]
	if !hasCustom || !customFeed.Enabled || customFeed.Category != "Custom Pull" {
		t.Errorf("expected custom feed inhouse-intel to be present and enabled")
	}

	// 4. Air-gapped / Egress Deny mode
	denyMirror := &domain.FeedMirrorSpec{
		Egress: "deny",
		KEV: &domain.FeedMirrorSource{
			URL: "https://airgap.internal/kev.json",
		},
		// No EPSS, NVD, or OSV mirrors provided
	}
	st.SetClusterFeedMirror(denyMirror)

	req = httptest.NewRequest("GET", "/api/v1/feeds", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var respDeny query.FeedsListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &respDeny); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	byNameDeny := make(map[string]query.FeedItemResponse)
	for _, it := range respDeny.Items {
		byNameDeny[it.Name] = it
	}

	if !byNameDeny["cisa_kev"].Enabled || byNameDeny["cisa_kev"].Status == "disabled" {
		t.Errorf("cisa_kev with mirror should remain enabled in egress deny mode")
	}
	if byNameDeny["first_epss"].Enabled || byNameDeny["first_epss"].Status != "disabled" {
		t.Errorf("first_epss without mirror should be disabled in egress deny mode")
	}
	if byNameDeny["nvd"].Enabled || byNameDeny["nvd"].Status != "disabled" {
		t.Errorf("nvd without mirror should be disabled in egress deny mode")
	}

	// 5. Test Live Connectivity Probe endpoint
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	testMirror := &domain.FeedMirrorSpec{
		Egress: "allow",
		KEV: &domain.FeedMirrorSource{
			URL: ts.URL,
		},
		EPSS: &domain.FeedMirrorSource{
			URL: ts.URL,
		},
		NVD: &domain.NVDSource{
			URL: ts.URL,
		},
		OSV: &domain.OSVSource{
			URL: ts.URL,
		},
	}
	st.SetClusterFeedMirror(testMirror)
	api.SetFeedProbeClient(enrich.NewFeedHTTPClient(6*time.Second, true)) // the test feed is on 127.0.0.1

	// Single feed probe
	req = httptest.NewRequest("POST", "/api/v1/feeds/test-connection?feed=cisa_kev", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from test-connection, got %d: %s", rec.Code, rec.Body.String())
	}

	var testResp query.FeedTestConnectionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &testResp); err != nil {
		t.Fatalf("failed to parse test-connection response: %v", err)
	}
	if len(testResp.Results) != 1 {
		t.Fatalf("expected 1 result for cisa_kev, got %d", len(testResp.Results))
	}
	if !testResp.Results[0].Reachable || testResp.Results[0].StatusCode != http.StatusOK {
		t.Errorf("expected cisa_kev to be reachable with 200 OK, got %+v", testResp.Results[0])
	}

	// All feeds probe
	req = httptest.NewRequest("POST", "/api/v1/feeds/test-connection", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for all feeds probe, got %d", rec.Code)
	}
	var allTestResp query.FeedTestConnectionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &allTestResp); err != nil {
		t.Fatalf("failed to parse all feeds test response: %v", err)
	}
	if len(allTestResp.Results) < 4 {
		t.Errorf("expected at least 4 feed probe results, got %d", len(allTestResp.Results))
	}

	// 5. On-demand sync. The API cannot write the global tables (D19), so it hands the work to the system syncer; a
	// server without one says so instead of answering 202 and doing nothing.
	post := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := post("/api/v1/feeds/sync?feed=cisa_kev"); w.Code != http.StatusNotImplemented {
		t.Fatalf("no system syncer: expected 501, got %d", w.Code)
	}
	fs := &fakeSyncer{}
	api.SetFeedSyncer(fs)
	syncRec := post("/api/v1/feeds/sync?feed=cisa_kev")
	if syncRec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for feed sync, got %d: %s", syncRec.Code, syncRec.Body.String())
	}
	var syncResp query.FeedSyncResponse
	if err := json.Unmarshal(syncRec.Body.Bytes(), &syncResp); err != nil {
		t.Fatalf("failed to parse feed sync response: %v", err)
	}
	if syncResp.Status != "started" || syncResp.Feed != "cisa_kev" || fs.feed != "cisa_kev" {
		t.Errorf("unexpected sync response: %+v (asked for %q)", syncResp, fs.feed)
	}
	if w := post("/api/v1/feeds/sync"); w.Code != http.StatusAccepted || fs.feed != "" || len(fs.names) < 3 { // NVD is opt-in, so it is not among them
		t.Errorf("all feeds: %d feed=%q names=%v", w.Code, fs.feed, fs.names)
	}
	if w := post("/api/v1/feeds/sync?feed=nope"); w.Code != http.StatusNotFound {
		t.Errorf("an unknown feed is 404, got %d", w.Code)
	}
	fs.err = enrich.ErrSyncBusy
	if w := post("/api/v1/feeds/sync"); w.Code != http.StatusConflict {
		t.Errorf("a sync already running is 409, got %d", w.Code)
	}
}

type fakeSyncer struct {
	feed  string
	names []string
	err   error
}

func (f *fakeSyncer) Start(_ context.Context, feed string, names []string) error {
	f.feed, f.names = feed, names
	return f.err
}

// Any signed-in user reads the feeds page, so it never shows where a token is read from; and the connection test, which
// makes the server call the feed addresses, is for an administrator.
func TestFeedsAPIRedactsTokenPathsAndRestrictsTheProbe(t *testing.T) {
	st := ingest.NewMemoryStore()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(st)
	adminToken := authn.DefaultAdminToken(tenantID)
	viewerToken, _, err := auth.GenerateToken(tenantID, auth.RoleViewer, "viewer@acme.com", []string{"tenant"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SaveToken(context.Background(), &auth.TokenRecord{TokenHash: auth.HashToken(viewerToken), TenantID: tenantID, Role: auth.RoleViewer})
	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	st.SetClusterFeedMirror(&domain.FeedMirrorSpec{
		NVD:    &domain.NVDSource{URL: "https://user:pw@mirror.internal/nvd?sig=abc", TokenFile: "/etc/rampart/feed-secrets/nvd-api-key"},
		Custom: []domain.CustomFeed{{Name: "intel", Format: domain.CustomFeedIntelJSONL, PushTokenFile: "/var/run/rampart/feeds/intel/token"}},
	})
	get := func(path, method, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	rec := get("/api/v1/feeds", "GET", viewerToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("a viewer reads the feeds page: %d", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{"/etc/rampart/feed-secrets", "/var/run/rampart/feeds", "pw@", "sig=abc"} {
		if strings.Contains(body, leak) {
			t.Errorf("the feeds page shows %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "(set)") || !strings.Contains(body, "mirror.internal/nvd") {
		t.Errorf("the page must say a token is set and still show the address: %s", body)
	}

	if rec := get("/api/v1/feeds/test-connection", "POST", viewerToken); rec.Code != http.StatusForbidden {
		t.Errorf("a viewer started a connection test: %d", rec.Code)
	}
	if rec := get("/api/v1/feeds/test-connection?feed=nvd", "POST", adminToken); rec.Code != http.StatusOK {
		t.Errorf("an administrator's connection test: %d %s", rec.Code, rec.Body.String())
	}
}

// The connection test uses the guarded client: an address the server must never call is reported unreachable, not called.
func TestFeedProbeRefusesTheMetadataAddress(t *testing.T) {
	st := ingest.NewMemoryStore()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	st.SetClusterFeedMirror(&domain.FeedMirrorSpec{KEV: &domain.FeedMirrorSource{URL: "http://169.254.169.254/latest/meta-data/"}})
	req := httptest.NewRequest("POST", "/api/v1/feeds/test-connection?feed=cisa_kev", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var resp query.FeedTestConnectionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Results) != 1 {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	if resp.Results[0].Reachable || !strings.Contains(resp.Results[0].Error, "blocked") {
		t.Errorf("the metadata address was not refused: %+v", resp.Results[0])
	}
}

// fakeSync stands for enrich.OnDemand: it answers the two questions only the server's configuration decides.
type fakeSync struct{ why map[string]string }

func (f fakeSync) Start(context.Context, string, []string) error { return nil }
func (f fakeSync) Why(_ context.Context, feed string) string     { return f.why[feed] }

// A feed that is not run says why, in a form the page can use, and the message of a refused sync says the same reason
// and not always "egress deny": a feed switched off in the ClusterFeed used to be explained as an egress rule.
func TestFeedsSayWhyAFeedIsNotRun(t *testing.T) {
	off, on := false, true
	list := func(mirror *domain.FeedMirrorSpec, sync fakeSync) map[string]query.FeedItemResponse {
		st := ingest.NewMemoryStore()
		st.SetClusterFeedMirror(mirror)
		tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
		authn := auth.NewAuthenticatorWithStore(st)
		token := authn.DefaultAdminToken(tenantID)
		api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
		api.SetFeedSyncer(sync)
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		req := httptest.NewRequest("GET", "/api/v1/feeds", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var resp query.FeedsListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		out := map[string]query.FeedItemResponse{}
		for _, it := range resp.Items {
			out[it.Name] = it
		}
		return out
	}

	got := list(&domain.FeedMirrorSpec{
		Egress:       "deny",
		KEV:          &domain.FeedMirrorSource{URL: "https://mirror.internal/kev.json"},
		EPSS:         &domain.FeedMirrorSource{Enabled: &off, URL: "https://mirror.internal/epss.gz"},
		Vulnrichment: &domain.FeedSource{Enabled: &off},
		NVD:          &domain.NVDSource{Enabled: &on}, // NVD runs only when it is switched on or has a key
	}, fakeSync{why: map[string]string{}})
	for name, want := range map[string]string{
		"cisa_kev":     "",                     // a mirror address: read, whatever the egress rule
		"first_epss":   enrich.FeedOffSwitched, // its own switch wins over its mirror address
		"nvd":          enrich.FeedOffEgress,   // deny and no mirror
		"osv":          enrich.FeedOffEgress,
		"vulnrichment": enrich.FeedOffSwitched,
	} {
		it := got[name]
		if it.DisabledReason != want || it.Enabled != (want == "") {
			t.Errorf("%s: reason %q, enabled %v; want reason %q", name, it.DisabledReason, it.Enabled, want)
		}
		if want != "" && it.Status != "disabled" {
			t.Errorf("%s: a feed that is not run has status %q, want disabled", name, it.Status)
		}
	}

	// what only the server's configuration decides
	got = list(&domain.FeedMirrorSpec{NVD: &domain.NVDSource{Enabled: &on}}, fakeSync{why: map[string]string{"nvd": enrich.FeedOffServerConfig, "osv": enrich.FeedOffNoEcosystem}})
	if got["nvd"].DisabledReason != enrich.FeedOffServerConfig || got["osv"].DisabledReason != enrich.FeedOffNoEcosystem {
		t.Errorf("the server's own reasons: nvd %q, osv %q", got["nvd"].DisabledReason, got["osv"].DisabledReason)
	}
	if !got["cisa_kev"].Enabled || !got["first_epss"].Enabled {
		t.Error("a feed nothing switches off is enabled")
	}
}

func TestSyncRefusalNamesTheRealReason(t *testing.T) {
	off := false
	st := ingest.NewMemoryStore()
	st.SetClusterFeedMirror(&domain.FeedMirrorSpec{KEV: &domain.FeedMirrorSource{Enabled: &off}})
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	api.SetFeedSyncer(fakeSync{})
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	req := httptest.NewRequest("POST", "/api/v1/feeds/sync?feed=cisa_kev", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "enabled: false") || strings.Contains(rec.Body.String(), "egress") {
		t.Errorf("a feed switched off in the ClusterFeed must be explained as that: %d %s", rec.Code, rec.Body.String())
	}
}
