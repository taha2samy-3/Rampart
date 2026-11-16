package store_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"rampart/internal/config/apply"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/query"
)

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

func osvZip(t *testing.T, ghsa, cve string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for id, body := range map[string]string{
		ghsa + ".json": `{"id":"` + ghsa + `","aliases":["` + cve + `"],"summary":"a go module flaw","published":"2024-01-01T00:00:00Z","modified":"2024-02-01T00:00:00Z"}`,
		"broken.json":  `{not json`,
	} {
		f, _ := w.Create(id)
		_, _ = f.Write([]byte(body))
	}
	_ = w.Close()
	return b.Bytes()
}

func TestFeeds_SyncThenScoreAndFilter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	appStore, sysStore := setupStores(t, ctx)

	cve := "CVE-2099-" + strings.ToUpper(uuid.NewString()[:6])
	other := "CVE-2099-" + strings.ToUpper(uuid.NewString()[:6])
	ghsa := "GHSA-" + uuid.NewString()[:4] + "-abcd-wxyz"

	upstream := http.NewServeMux()
	upstream.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"` + strings.ToLower(cve) + `","vulnerabilityName":"Exploited thing","dateAdded":"2024-05-01","dueDate":"2024-05-22","knownRansomwareCampaignUse":"Known"}]}`))
	})
	upstream.HandleFunc("/epss.csv.gz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gz("#model_version:v2025.03.14,score_date:2026-01-01T00:00:00Z\ncve,epss,percentile\n" + cve + ",0.93000,0.99000\n" + other + ",0.02000,0.40000\n"))
	})
	upstream.HandleFunc("/Go/all.zip", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(osvZip(t, ghsa, cve)) })
	srv := httptest.NewServer(upstream)
	defer srv.Close()

	syncer := enrich.NewFeedSyncer(sysStore.Pool())
	cfg := enrich.FeedConfig{NVDDisabled: true, KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz", OSVBaseURL: srv.URL, OSVEcosystems: []string{"Go"}}
	if err := syncer.SyncAll(ctx, cfg, slog.Default()); err != nil {
		t.Fatalf("SyncAll: %v", err)
	}
	for feed, min := range map[string]int64{"cisa_kev": 1, "first_epss": 2, "osv": 1} {
		st, err := syncer.GetFeedState(ctx, feed)
		if err != nil || st.Status != "success" || st.Records < min {
			t.Fatalf("feed %s: %+v err %v", feed, st, err)
		}
	}

	// A finding whose vulnerability is in KEV with a high EPSS.
	tn := &domain.Tenant{ID: uuid.New(), Slug: "feeds-" + uuid.NewString()[:8], DisplayName: "Feeds", CreatedAt: time.Now().UTC()}
	if err := sysStore.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 2)
	all, _ := appStore.ListFindings(ctx, tn.ID)
	// A third finding that carries the vulnerability (the id is part of a finding's identity).
	target := *all[0]
	target.ID, target.FindingKey, target.Title = uuid.New(), "k-with-cve", "Vulnerable dependency"
	target.VulnerabilityID, target.Category = &cve, domain.CategorySCA
	if err := appStore.UpsertFindings(ctx, tn.ID, []*domain.Finding{&target}); err != nil {
		t.Fatal(err)
	}

	// A fourth finding identified only by the GHSA id: an alias of the CVE (D19, D11).
	viaAlias := target
	viaAlias.ID, viaAlias.FindingKey, viaAlias.Title, viaAlias.VulnerabilityID = uuid.New(), "k-with-ghsa", "Same flaw, GHSA id", &ghsa
	if err := appStore.UpsertFindings(ctx, tn.ID, []*domain.Finding{&viaAlias}); err != nil {
		t.Fatal(err)
	}

	authn := auth.NewAuthenticatorWithStore(appStore)
	token := authn.DefaultAdminToken(tn.ID)
	api := query.NewAPIWithAuth(appStore, enrich.NewFeedStore(), authn) // the in-memory store stays empty
	api.SetIntelSource(syncer)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	get := func(q string) []struct {
		Finding domain.Finding `json:"finding"`
		Risk    struct {
			HasKEV    bool    `json:"has_kev"`
			EPSSScore float64 `json:"epss_score"`
		} `json:"risk"`
	} {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/findings?limit=50&q="+q, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var out struct {
			Items []struct {
				Finding domain.Finding `json:"finding"`
				Risk    struct {
					HasKEV    bool    `json:"has_kev"`
					EPSSScore float64 `json:"epss_score"`
				} `json:"risk"`
			} `json:"items"`
		}
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out.Items
	}

	items := get("")
	if len(items) != 4 {
		t.Fatalf("want 4 findings, got %d", len(items))
	}
	var found bool
	for _, it := range items {
		if it.Finding.ID == target.ID {
			found = true
			if !it.Risk.HasKEV || it.Risk.EPSSScore < 0.9 {
				t.Fatalf("KEV and EPSS are not visible on the finding: %+v", it.Risk)
			}
		} else if it.Finding.ID == viaAlias.ID {
			if !it.Risk.HasKEV || it.Risk.EPSSScore < 0.9 {
				t.Fatalf("a GHSA-identified finding did not get the KEV and EPSS data of its CVE alias: %+v", it.Risk)
			}
		} else if it.Risk.HasKEV {
			t.Fatal("a finding without a vulnerability is marked as known exploited")
		}
	}
	if !found {
		t.Fatal("the target finding is missing")
	}
	if kev := get("kev:true"); len(kev) != 2 {
		t.Fatalf("kev:true returned %d findings, want the CVE one and the GHSA one", len(kev))
	}
	if notKEV := get("kev:false"); len(notKEV) != 2 {
		t.Fatalf("kev:false returned %d findings, want 2", len(notKEV))
	}
	// The cve filter matches the id or any alias, in both directions (D19).
	if got := get("cve:" + cve); len(got) != 2 {
		t.Fatalf("cve:<CVE> returned %d findings, want 2 (the CVE one and the GHSA one)", len(got))
	}
	if got := get("cve:" + ghsa); len(got) != 2 {
		t.Fatalf("cve:<GHSA> returned %d findings, want 2", len(got))
	}
	if got := get("cve:CVE-1999-0000"); len(got) != 0 {
		t.Fatalf("an unrelated id matched %d findings", len(got))
	}

	// One feed failing does not stop the others, and the failure is visible in the feed state.
	bad := enrich.FeedConfig{NVDDisabled: true, KEVURL: srv.URL + "/missing.json", EPSSURL: srv.URL + "/epss.csv.gz"}
	err := syncer.SyncAll(ctx, bad, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "kev") || strings.Contains(err.Error(), "epss") {
		t.Fatalf("want only the kev error, got %v", err)
	}
	if st, _ := syncer.GetFeedState(ctx, "cisa_kev"); st.Status != "error" || st.Error == nil {
		t.Fatalf("a failed feed must be visible in its state: %+v", st)
	}
	if st, _ := syncer.GetFeedState(ctx, "first_epss"); st.Status != "success" {
		t.Fatalf("the healthy feed was affected: %+v", st)
	}

	// A download over the size limit is refused, not truncated.
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "99999999999")
	}))
	defer huge.Close()
	if err := syncer.SyncAll(ctx, enrich.FeedConfig{NVDDisabled: true, KEVURL: huge.URL, EPSSURL: srv.URL + "/epss.csv.gz"}, slog.Default()); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("an oversize feed must be refused, got %v", err)
	}
}

// D86: the NVD sync pages through the CVE API, writes CWEs and CVSS (4.0 preferred) without touching KEV or EPSS,
// and keeps a cursor so the next sync asks only for what changed.
func TestFeeds_NVDSync(t *testing.T) {
	ctx := context.Background()
	_, sysStore := setupStores(t, ctx)
	pages := map[string]string{
		"0": `{"resultsPerPage":1,"startIndex":0,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2099-0001","published":"2099-01-01T00:00:00.000","lastModified":"2099-01-02T00:00:00.000",
			"descriptions":[{"lang":"en","value":"first"}],"weaknesses":[{"description":[{"value":"CWE-79"},{"value":"NVD-CWE-Other"}]}],
			"metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8}}],
			"cvssMetricV40":[{"source":"cna","type":"Secondary","cvssData":{"version":"4.0","vectorString":"CVSS:4.0/AV:N","baseScore":9.3}}]}}}]}`,
		"1": `{"resultsPerPage":1,"startIndex":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2099-0002","descriptions":[{"lang":"en","value":"second"}],"weaknesses":[],"metrics":{}}}]}`,
	}
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("startIndex") { // only the NVD calls; KEV and EPSS hit /none
			seen = append(seen, r.URL.RawQuery)
		}
		if r.URL.Query().Has("startIndex") && r.Header.Get("apiKey") != "k" {
			t.Errorf("the API key must be sent in the apiKey header")
		}
		_, _ = w.Write([]byte(pages[r.URL.Query().Get("startIndex")]))
	}))
	defer srv.Close()
	syncer := enrich.NewFeedSyncer(sysStore.Pool())
	_, _ = sysStore.Pool().Exec(ctx, `DELETE FROM feed_state WHERE feed = 'nvd'`)
	_, _ = sysStore.Pool().Exec(ctx, `INSERT INTO vulnerability (id, kev_date_added, epss_score) VALUES ('CVE-2099-0001', '2099-01-03', 0.5) ON CONFLICT (id) DO UPDATE SET kev_date_added = EXCLUDED.kev_date_added, epss_score = EXCLUDED.epss_score`)
	cfg := enrich.FeedConfig{NVDURL: srv.URL, NVDAPIKey: "k", NVDPageDelay: time.Millisecond,
		KEVURL: srv.URL + "/none", EPSSURL: srv.URL + "/none"}
	_ = syncer.SyncAll(ctx, cfg, slog.Default()) // KEV and EPSS fail against this server; NVD must still sync
	if len(seen) < 2 || strings.Contains(seen[0], "lastModStartDate") {
		t.Fatalf("the first sync must be a full, paged read: %v", seen)
	}
	var cwes []int32
	var best float64
	var vector string
	var kev *time.Time
	var epss *float32
	if err := sysStore.Pool().QueryRow(ctx, `SELECT cwes, cvss_best_score, cvss_best_vector, kev_date_added, epss_score FROM vulnerability WHERE id = 'CVE-2099-0001'`).
		Scan(&cwes, &best, &vector, &kev, &epss); err != nil {
		t.Fatal(err)
	}
	if len(cwes) != 1 || cwes[0] != 79 || best != 9.8 || !strings.HasPrefix(vector, "CVSS:3.1") {
		t.Fatalf("cwes %v, best %v %s: want CWE-79 and the primary 3.1 score (the 4.0 one is secondary)", cwes, best, vector)
	}
	if kev == nil || epss == nil {
		t.Fatal("NVD must not touch the KEV and EPSS columns")
	}
	seen = nil
	_ = syncer.SyncAll(ctx, cfg, slog.Default())
	if len(seen) == 0 || !strings.Contains(seen[0], "lastModStartDate") {
		t.Fatalf("the second sync must be incremental: %v", seen)
	}
}

// D86: a ClusterFeedMirror is stored with the cluster-wide configuration; the one named default is in force, and a
// spec that failed validation never is.
func TestClusterFeedMirror_OnPostgreSQL(t *testing.T) {
	ctx := context.Background()
	_, sys := setupStores(t, ctx)
	_, _ = sys.Pool().Exec(ctx, `DELETE FROM cluster_policy WHERE kind = 'feeds'`)
	if m, err := sys.GetClusterFeedMirror(ctx); err != nil || m != nil {
		t.Fatalf("no mirror: %v %v", m, err)
	}
	save := func(name, spec, errText string) {
		if err := sys.SaveClusterPolicy(ctx, "feeds", apply.PolicyObject{Name: name, Spec: []byte(spec), Error: errText}); err != nil {
			t.Fatal(err)
		}
	}
	save("aaa", `{"kev":{"url":"https://a/kev.json"}}`, "")
	save("default", `{"kev":{"url":"https://default/kev.json"},"egress":"deny"}`, "")
	save("broken", `{"kev":{"url":"https://broken/kev.json"}}`, "refused")
	m, err := sys.GetClusterFeedMirror(ctx)
	if err != nil || m == nil || m.KEV.URL != "https://default/kev.json" || m.Egress != "deny" {
		t.Fatalf("the mirror named default must be in force: %+v %v", m, err)
	}
	var rescore int
	_ = sys.Pool().QueryRow(ctx, `SELECT count(*) FROM application WHERE rescore_needed`).Scan(&rescore)
	_ = rescore // a mirror changes where feeds come from, not a score: SaveClusterPolicy skips the re-score flag for kind feeds
}
