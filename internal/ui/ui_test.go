package ui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"rampart/internal/ui"
)

func fixture() fstest.MapFS {
	return fstest.MapFS{
		"index.html":           {Data: []byte(`<!doctype html><title>Rampart</title><script type="module" src="/assets/app-1a2b3c.js"></script>`)},
		"assets/app-1a2b3c.js": {Data: []byte("console.log(1)")},
		"favicon.svg":          {Data: []byte("<svg/>")},
	}
}

func get(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestServesIndexWithSecurityHeadersAndNoCache(t *testing.T) {
	h := ui.Handler(ui.Options{FS: fixture()})
	rec := get(h, "GET", "/")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Rampart") {
		t.Fatalf("index: %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("index.html must be no-cache, got %q", rec.Header().Get("Cache-Control"))
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "connect-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP must not allow inline or eval: %s", csp)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Referrer-Policy") != "same-origin" {
		t.Errorf("missing hardening headers: %v", rec.Header())
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must only be sent when the public URL is https")
	}
}

func TestHashedAssetsAreImmutableAndHSTSFollowsHTTPS(t *testing.T) {
	h := ui.Handler(ui.Options{FS: fixture(), HSTS: true})
	rec := get(h, "GET", "/assets/app-1a2b3c.js")
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS expected")
	}
}

func TestClientRoutesFallBackToIndexButAPIAndMissingAssetsDoNot(t *testing.T) {
	h := ui.Handler(ui.Options{FS: fixture()})
	for _, p := range []string{"/login", "/t/acme/findings/0193abcd", "/findings"} {
		if rec := get(h, "GET", p); rec.Code != 200 || !strings.Contains(rec.Body.String(), "<title>Rampart") {
			t.Errorf("%s must serve the SPA shell, got %d", p, rec.Code)
		}
	}
	for _, p := range []string{"/api/v1/nope", "/auth/nope", "/ingest/v1/nope", "/assets/missing.js", "/missing.png"} {
		if rec := get(h, "GET", p); rec.Code != 404 {
			t.Errorf("%s must be 404, got %d", p, rec.Code)
		}
	}
	if rec := get(h, "POST", "/"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /: %d", rec.Code)
	}
}

func TestExplainsWhenTheUIIsNotBuilt(t *testing.T) {
	h := ui.Handler(ui.Options{FS: fstest.MapFS{}})
	rec := get(h, "GET", "/")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "not built") {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}
