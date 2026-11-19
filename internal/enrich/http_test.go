package enrich

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryAfter(t *testing.T) {
	cases := []struct {
		in   string
		def  time.Duration
		want time.Duration
	}{
		{"7", time.Minute, 7 * time.Second},
		{"", 2 * time.Second, 2 * time.Second},
		{"soon", 3 * time.Second, 3 * time.Second},
		{"-5", 4 * time.Second, 4 * time.Second},
		{"99999", time.Second, maxRetryAfter}, // a server cannot park the sync for hours
	}
	for _, c := range cases {
		if got := retryAfter(c.in, c.def); got != c.want {
			t.Errorf("retryAfter(%q, %s) = %s, want %s", c.in, c.def, got, c.want)
		}
	}
	date := time.Now().Add(20 * time.Second).UTC().Format(http.TimeFormat)
	if got := retryAfter(date, time.Hour); got < 15*time.Second || got > 21*time.Second {
		t.Errorf("an HTTP date gave %s", got)
	}
	if got := retryAfter(time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat), time.Hour); got != 0 {
		t.Errorf("a date in the past gave %s, want 0", got)
	}
}

func TestEPSSScoreDate(t *testing.T) {
	want := time.Date(2025, 11, 17, 12, 55, 0, 0, time.UTC)
	for _, line := range []string{
		"#model_version:v2025.03.14,score_date:2025-11-17T12:55:00Z\n",
		"#model_version:v2025.03.14,score_date:2025-11-17T12:55:00Z",
		"# score_date:2025-11-17T12:55:00Z, model_version:v1\r\n",
	} {
		got, ok := epssScoreDate(line)
		if !ok || !got.Equal(want) {
			t.Errorf("%q = %v, %v", line, got, ok)
		}
	}
	if d, ok := epssScoreDate("#score_date:2025-11-17\n"); !ok || d.Format("2006-01-02") != "2025-11-17" {
		t.Errorf("a plain date: %v %v", d, ok)
	}
	if _, ok := epssScoreDate("#model_version:v1\n"); ok {
		t.Error("a line without score_date gave a date")
	}
}

// A feed client refuses what D69 never allows for anyone, and nothing else.
func TestFeedClientRefusesMetadataAndLoopback(t *testing.T) {
	c := NewFeedHTTPClient(2*time.Second, false)
	for _, u := range []string{"http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:1/", "http://[::1]:1/", "http://0.0.0.0:1/"} {
		_, err := c.Get(u)
		if err == nil || !strings.Contains(err.Error(), "blocked") {
			t.Errorf("%s: err = %v, want the address blocked", u, err)
		}
	}
	// A private address (a mirror in the company network) is a normal feed URL: the dial is attempted. 10.255.255.1 does
	// not answer here, so the failure must be a timeout or no route, never "blocked".
	c = NewFeedHTTPClient(300*time.Millisecond, false)
	if _, err := c.Get("http://10.255.255.1:9/"); err != nil && strings.Contains(err.Error(), "blocked") {
		t.Errorf("a private address was refused: %v", err)
	}
}

func TestFeedClientAllowsLoopbackOnlyWhenAsked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	if _, err := NewFeedHTTPClient(time.Second, false).Get(srv.URL); err == nil {
		t.Error("loopback was reached without AllowLoopback")
	}
	res, err := NewFeedHTTPClient(time.Second, true).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
}

// The credentials of a request do not follow a redirect to another host, and an https feed is not sent to http.
func TestRedirectDropsCredentialsOnAnotherHost(t *testing.T) {
	var gotKey, gotAuth atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey.Store(r.Header.Get("apiKey"))
		gotAuth.Store(r.Header.Get("Authorization"))
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer origin.Close()
	// 127.0.0.1:port differs from 127.0.0.1:port2 as a host, which is what the rule compares
	c := NewFeedHTTPClient(time.Second, true)
	req, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
	req.Header.Set("apiKey", "secret")
	req.Header.Set("Authorization", "Bearer secret")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if gotKey.Load() != "" || gotAuth.Load() != "" {
		t.Errorf("credentials reached another host: apiKey=%q Authorization=%q", gotKey.Load(), gotAuth.Load())
	}
}

func TestRedirectLimit(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusFound)
	}))
	defer srv.Close()
	if _, err := NewFeedHTTPClient(2*time.Second, true).Get(srv.URL); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("err = %v, want the redirect loop stopped", err)
	}
}

func TestGetIfChanged(t *testing.T) {
	var hits, conditional atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Tue, 17 Nov 2026 10:00:00 GMT")
		_, _ = io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()
	cfg := FeedConfig{AllowLoopback: true}
	cfg.defaults()
	ctx := context.Background()

	body, next, notModified, err := cfg.getIfChanged(ctx, srv.URL, 1<<20, nil)
	if err != nil || notModified {
		t.Fatalf("first fetch: notModified=%v err=%v", notModified, err)
	}
	b, _ := io.ReadAll(body)
	_ = body.Close()
	if !strings.Contains(string(b), "vulnerabilities") || next.ETag != `"v1"` || next.LastModified == "" || next.URL != srv.URL {
		t.Fatalf("body %q, next %+v", b, next)
	}

	// the stored validators make the second request conditional, and a 304 returns no body
	_, again, notModified, err := cfg.getIfChanged(ctx, srv.URL, 1<<20, &next)
	if err != nil || !notModified || again.ETag != `"v1"` || conditional.Load() != 1 {
		t.Fatalf("second fetch: notModified=%v err=%v conditional=%d", notModified, err, conditional.Load())
	}

	// validators of another URL (a changed mirror) are not sent
	stale := next
	stale.URL = "http://elsewhere.example/kev.json"
	body, _, notModified, err = cfg.getIfChanged(ctx, srv.URL, 1<<20, &stale)
	if err != nil || notModified {
		t.Fatalf("a changed URL must be downloaded: notModified=%v err=%v", notModified, err)
	}
	_ = body.Close()
	if conditional.Load() != 1 {
		t.Error("validators of another URL were sent")
	}

	// a 304 to a request that was not conditional is an error, not "unchanged"
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotModified) }))
	defer bad.Close()
	if _, _, nm, err := cfg.getIfChanged(ctx, bad.URL, 1<<20, nil); err == nil || nm {
		t.Errorf("an unexpected 304 was taken as unchanged (err=%v)", err)
	}
}

func TestFetchNVDPageWaitsOutRateLimits(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(http.StatusForbidden) // NIST's answer to a client that is too fast
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"resultsPerPage": 1, "totalResults": 1, "vulnerabilities": []any{}})
		}
	}))
	defer srv.Close()
	cfg := FeedConfig{NVDURL: srv.URL, AllowLoopback: true, NVDRetryBase: time.Millisecond}
	cfg.defaults()
	page, err := (&FeedSyncer{}).fetchNVDPage(context.Background(), cfg, srv.URL)
	if err != nil || page == nil || page.TotalResults != 1 || calls.Load() != 3 {
		t.Fatalf("page=%v err=%v calls=%d, want the third answer", page, err, calls.Load())
	}
}

func TestFetchNVDPageGivesUpAfterTheLastAttempt(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	cfg := FeedConfig{NVDURL: srv.URL, AllowLoopback: true, NVDRetryBase: time.Millisecond}
	cfg.defaults()
	_, err := (&FeedSyncer{}).fetchNVDPage(context.Background(), cfg, srv.URL)
	if err == nil || !strings.Contains(err.Error(), "429") || calls.Load() != nvdMaxAttempts {
		t.Fatalf("err=%v calls=%d, want %d attempts and the status in the error", err, calls.Load(), nvdMaxAttempts)
	}
}

func TestFetchNVDPageOtherErrorsAreNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	cfg := FeedConfig{NVDURL: srv.URL + "/x?apiKey=leak", AllowLoopback: true, NVDRetryBase: time.Millisecond}
	cfg.defaults()
	_, err := (&FeedSyncer{}).fetchNVDPage(context.Background(), cfg, srv.URL)
	if err == nil || calls.Load() != 1 || strings.Contains(err.Error(), "leak") {
		t.Fatalf("err=%v calls=%d: a 404 is final and the URL in the message carries no query", err, calls.Load())
	}
}

func TestRedactDropsQueryAndUserInfo(t *testing.T) {
	if got := redact("https://user:pw@feeds.example/x?sig=abc#f"); strings.Contains(got, "pw") || strings.Contains(got, "sig") {
		t.Errorf("redact left a credential: %s", got)
	}
}

func TestSummarizeNamesAnUnchangedFeed(t *testing.T) {
	_, body, failed := Summarize([]FeedResult{{Feed: "cisa_kev", Records: 1200, NotModified: true}})
	if failed || !strings.Contains(body, "unchanged (1200 records)") {
		t.Errorf("body = %q, failed = %v", body, failed)
	}
}
