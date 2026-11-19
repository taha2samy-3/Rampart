package query_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/parsertest"
	"rampart/internal/query"
	"rampart/internal/wasmstore"
)

func TestParsersAPI_List(t *testing.T) {
	tenantID := uuid.New()
	st := ingest.NewMemoryStore()
	// The server knows no parser: with nothing installed the list is empty, and what the control plane stores is what is listed.
	for _, m := range parsertest.Manifests(t) {
		st.SaveClusterParser(m.Name, m.Stored)
	}
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)

	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// 1. Authorized GET /api/v1/parsers
	req := httptest.NewRequest(http.MethodGet, "/api/v1/parsers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var res struct {
		Parsers []map[string]any `json:"parsers"`
		Total   int              `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Total != 20 {
		t.Errorf("expected the 17 report parsers and 3 SBOM readers that were installed, got %d", res.Total)
	}
	ids := map[string]bool{}
	for _, p := range res.Parsers {
		ids[p["id"].(string)] = true
	}
	for _, want := range []string{"builtin:trivy", "builtin:sarif", "builtin:genericjson", "builtin:sbom-spdx", "builtin:sbom-cyclonedx", "builtin:sbom-syft"} {
		if !ids[want] {
			t.Errorf("%s is installed and must be listed with the id the runs and the compliance report use: %v", want, ids)
		}
	}

	// 2. Unauthorized request returns 401
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/v1/parsers", nil)
	unauthW := httptest.NewRecorder()
	mux.ServeHTTP(unauthW, unauthReq)
	if unauthW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthW.Code)
	}
}

// A server that was given no parser has none to list: nothing is compiled in.
func TestParsersAPI_ListIsEmptyWhenNothingIsInstalled(t *testing.T) {
	tenantID := uuid.New()
	st := ingest.NewMemoryStore()
	authn := auth.NewAuthenticatorWithStore(st)
	mux := http.NewServeMux()
	query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn).RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/parsers", nil)
	req.Header.Set("Authorization", "Bearer "+authn.DefaultAdminToken(tenantID))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var res struct {
		Parsers []any `json:"parsers"`
		Total   int   `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if res.Total != 0 || res.Parsers == nil || len(res.Parsers) != 0 {
		t.Fatalf("an empty server lists an empty list (never null): %s", w.Body.String())
	}
}

// A parser is listed as able to run only when its module is on the server: with none installed, the WASM parsers and the SBOM readers say why,
// and the Lua parsers, which need no module, do not (docs/34 item 21, W1: the dev cluster listed readers that failed at the first upload).
func TestParsersAPI_SaysWhichParsersCannotRun(t *testing.T) {
	tenantID := uuid.New()
	st := ingest.NewMemoryStore()
	for _, m := range parsertest.Manifests(t) {
		st.SaveClusterParser(m.Name, m.Stored)
	}
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	list := func() map[string]string {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/parsers", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		var res struct {
			Parsers []struct {
				ID          string `json:"id"`
				Unavailable string `json:"unavailable"`
			} `json:"parsers"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, p := range res.Parsers {
			out[p.ID] = p.Unavailable
		}
		return out
	}

	dir := t.TempDir()
	zero := strings.Repeat("0", 64)
	// Strict, as in production, so that no development location is searched: a server with no module in its directory.
	wasmstore.SetDefault(&wasmstore.Store{Dir: dir, Digests: map[string]string{"x": zero}})
	t.Cleanup(func() { wasmstore.SetDefault(&wasmstore.Store{}) })
	none := list()
	for _, id := range []string{"builtin:sarif", "builtin:semgrep", "builtin:sbom-cyclonedx", "builtin:sbom-spdx"} {
		if !strings.Contains(none[id], "WASM module is not installed") {
			t.Errorf("%s has no module and must say so: %q", id, none[id])
		}
	}
	for _, id := range []string{"builtin:bandit", "builtin:genericjson", "builtin:nuclei"} {
		if none[id] != "" {
			t.Errorf("%s is a Lua parser and needs no module: %q", id, none[id])
		}
	}

	// Install two modules, one for a report parser and one for an SBOM reader.
	for _, m := range []string{"sarif", "sbom-cyclonedx"} {
		if err := os.MkdirAll(filepath.Join(dir, m), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, m, "parser.wasm"), []byte("\x00asm"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wasmstore.SetDefault(&wasmstore.Store{Dir: dir, Digests: map[string]string{"sarif": zero, "sbom-cyclonedx": zero, "x": zero}})
	some := list()
	if some["builtin:sarif"] != "" || some["builtin:sbom-cyclonedx"] != "" {
		t.Errorf("the two with a module must be available: sarif %q, cyclonedx %q", some["builtin:sarif"], some["builtin:sbom-cyclonedx"])
	}
	if some["builtin:semgrep"] == "" || some["builtin:sbom-spdx"] == "" {
		t.Errorf("the others still have no module: %v", some)
	}
}
