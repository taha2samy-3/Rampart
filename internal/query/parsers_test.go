package query_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
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
		t.Errorf("expected the 16 report parsers and 4 SBOM readers that were installed, got %d", res.Total)
	}
	ids := map[string]bool{}
	for _, p := range res.Parsers {
		ids[p["id"].(string)] = true
	}
	for _, want := range []string{"cluster:trivy", "cluster:sarif", "cluster:genericjson", "cluster:sbom-spdx", "cluster:sbom-cyclonedx", "cluster:sbom-syft", "cluster:sbom-openvex"} {
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
	for _, id := range []string{"cluster:sarif", "cluster:semgrep", "cluster:sbom-cyclonedx", "cluster:sbom-spdx"} {
		if !strings.Contains(none[id], "WASM module is not installed") {
			t.Errorf("%s has no module and must say so: %q", id, none[id])
		}
	}
	for _, id := range []string{"cluster:bandit", "cluster:genericjson", "cluster:nuclei"} {
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
	if some["cluster:sarif"] != "" || some["cluster:sbom-cyclonedx"] != "" {
		t.Errorf("the two with a module must be available: sarif %q, cyclonedx %q", some["cluster:sarif"], some["cluster:sbom-cyclonedx"])
	}
	if some["cluster:semgrep"] == "" || some["cluster:sbom-spdx"] == "" {
		t.Errorf("the others still have no module: %v", some)
	}
}

// The Parsers page shows what each parser is (report parser or SBOM reader, the runtime), whether it is installed correctly (ready, its module
// missing, or its resource refused with the reason) and when it last worked.
func TestParsersAPI_FamilyRuntimeStatusAndLastRun(t *testing.T) {
	tenantID := uuid.New()
	st := ingest.NewMemoryStore()
	for _, m := range parsertest.Manifests(t) {
		st.SaveClusterParser(m.Name, m.Stored)
	}
	st.SaveClusterParser("broken", []byte(`:::not yaml`)) // refused
	// a refused resource is stored with its reason by the control plane; the memory store keeps it as given
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	zero := strings.Repeat("0", 64)
	wasmstore.SetDefault(&wasmstore.Store{Dir: t.TempDir(), Digests: map[string]string{"x": zero}})
	t.Cleanup(func() { wasmstore.SetDefault(&wasmstore.Store{}) })

	// two runs of the SARIF parser, the later one failed; the earlier one completed
	now := time.Now().UTC()
	mk := func(format string, status domain.IngestRunStatus, ago time.Duration, errText string) {
		_ = st.CreateIngestRun(context.Background(), &domain.IngestRun{ID: uuid.New(), TenantID: tenantID, Format: format, Status: status, Error: errText, CreatedAt: now.Add(-ago)})
	}
	mk("cluster:sarif", domain.RunCompleted, 3*time.Hour, "")
	mk("cluster:sarif", domain.RunFailed, time.Hour, "parse_error")
	mk("sbom-analysis", domain.RunCompleted, time.Minute, "") // an analyzer's merge is not a parser's work

	req := httptest.NewRequest(http.MethodGet, "/api/v1/parsers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var res struct {
		Parsers []struct {
			ID          string     `json:"id"`
			Family      string     `json:"family"`
			Runtime     string     `json:"runtime"`
			Origin      string     `json:"origin"`
			Status      string     `json:"status"`
			Module      string     `json:"module"`
			Error       string     `json:"error"`
			LastSuccess *time.Time `json:"last_success"`
			LastRun     *struct {
				Status string `json:"status"`
				Error  string `json:"error"`
			} `json:"last_run"`
		} `json:"parsers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	by := map[string]int{}
	for i, p := range res.Parsers {
		by[p.ID] = i
	}
	get := func(id string) int {
		i, ok := by[id]
		if !ok {
			t.Fatalf("%s is not listed: %v", id, by)
		}
		return i
	}
	sarif := res.Parsers[get("cluster:sarif")]
	if sarif.Family != "report" || sarif.Runtime != "wasm" || sarif.Origin != "cluster" || sarif.Status != "module_missing" || sarif.Module != "sarif" {
		t.Errorf("sarif: %+v", sarif)
	}
	if sarif.LastRun == nil || sarif.LastRun.Status != "failed" || sarif.LastRun.Error != "parse_error" || sarif.LastSuccess == nil {
		t.Errorf("sarif's last run failed and an earlier one completed: %+v", sarif)
	}
	if cdx := res.Parsers[get("cluster:sbom-cyclonedx")]; cdx.Family != "sbom" || cdx.Runtime != "wasm" || cdx.Status != "module_missing" || cdx.LastRun != nil {
		t.Errorf("an SBOM reader, never used: %+v", cdx)
	}
	if lua := res.Parsers[get("cluster:bandit")]; lua.Family != "report" || lua.Runtime != "lua" || lua.Status != "ready" {
		t.Errorf("a Lua parser needs no module: %+v", lua)
	}
	if bad := res.Parsers[get("cluster:broken")]; bad.Status != "refused" || bad.Error == "" {
		t.Errorf("a resource that cannot be read is listed with a reason: %+v", bad)
	}
}
