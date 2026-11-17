package query_test

import (
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
		NVD: &domain.FeedMirrorSource{
			URL: ts.URL,
		},
		OSV: &domain.FeedMirrorSource{
			URL: ts.URL,
		},
	}
	st.SetClusterFeedMirror(testMirror)

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
}
