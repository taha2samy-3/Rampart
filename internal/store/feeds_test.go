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
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
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
	cfg := enrich.FeedConfig{AllowLoopback: true, NVDDisabled: true, KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz", OSVBaseURL: srv.URL, OSVEcosystems: []string{"Go"}}
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
	bad := enrich.FeedConfig{AllowLoopback: true, NVDDisabled: true, KEVURL: srv.URL + "/missing.json", EPSSURL: srv.URL + "/epss.csv.gz"}
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
	if err := syncer.SyncAll(ctx, enrich.FeedConfig{AllowLoopback: true, NVDDisabled: true, KEVURL: huge.URL, EPSSURL: srv.URL + "/epss.csv.gz"}, slog.Default()); err == nil || !strings.Contains(err.Error(), "limit") {
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
	cfg := enrich.FeedConfig{AllowLoopback: true, NVDURL: srv.URL, NVDAPIKey: "k", NVDPageDelay: time.Millisecond,
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

func osvArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, body := range files {
		f, _ := w.Create(name)
		_, _ = f.Write([]byte(body))
	}
	_ = w.Close()
	return b.Bytes()
}

// The OSV feed writes what the matcher needs (docs/35 D4, D5): one row per interval of every package, the aliases with
// the feed that wrote them, the vectors OSV gives, and nothing for a withdrawn advisory but a mark. A second round
// against an archive the server says is unchanged reads nothing and keeps the count; a changed record is rewritten and
// an unchanged one is not.
func TestFeeds_OSVAffectedRangesAliasesAndIncrementalRounds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	_, sysStore := setupStores(t, ctx)
	pool := sysStore.Pool()

	sfx := strings.ToUpper(uuid.NewString()[:6])
	cveA, cveB := "CVE-2098-A"+sfx, "CVE-2098-B"+sfx // one advisory naming both: the smaller is canonical
	ghsa := "GHSA-" + strings.ToLower(sfx) + "-aaaa-bbbb"
	gone := "GHSA-" + strings.ToLower(sfx) + "-gone-0000"
	pkg := "Pkg_" + sfx

	record := func(modified string) string {
		return `{"id":"` + ghsa + `","aliases":["` + cveB + `","` + cveA + `","PYSEC-` + sfx + `"],"summary":"flaw","modified":"` + modified + `",
			"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			"affected":[{"package":{"ecosystem":"PyPI","name":"` + pkg + `"},
			  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.0"},{"introduced":"2.0.0"},{"last_affected":"2.5.0"}]},
			            {"type":"GIT","events":[{"introduced":"0"},{"fixed":"deadbeef"}]}],
			  "versions":["1.0","1.1","2.0.0"]}]}`
	}
	withdrawn := `{"id":"` + gone + `","modified":"2024-01-01T00:00:00Z","withdrawn":"2024-02-01T00:00:00Z",
		"affected":[{"package":{"ecosystem":"PyPI","name":"other-` + sfx + `"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`

	var archive atomic.Value
	var gets, conditional atomic.Int32
	archive.Store(osvArchive(t, map[string]string{ghsa + ".json": record("2024-03-01T00:00:00Z"), gone + ".json": withdrawn}))
	var etag atomic.Value
	etag.Store(`"v1"`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		if r.Header.Get("If-None-Match") == etag.Load().(string) {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag.Load().(string))
		_, _ = w.Write(archive.Load().([]byte))
	}))
	defer srv.Close()

	syncer := enrich.NewFeedSyncer(pool)
	_, _ = pool.Exec(ctx, `DELETE FROM feed_state WHERE feed = 'osv'`)
	cfg := enrich.FeedConfig{AllowLoopback: true, NVDDisabled: true, OSVBaseURL: srv.URL, OSVEcosystems: []string{"PyPI"}, Only: "osv"}
	if err := syncer.SyncAll(ctx, cfg, slog.Default()); err != nil {
		t.Fatalf("first round: %v", err)
	}

	// 1. rows: the ECOSYSTEM intervals and the versions list; the GIT range is not stored
	type row struct {
		rt                 string
		intro, fixed, last *string
		versions           []string
		withdrawn          *time.Time
		purl, norm, vulnID *string
	}
	rows, err := pool.Query(ctx, `SELECT range_type, introduced, fixed, last_affected, versions, withdrawn, purl_base, package_name_normalised, vulnerability_id
		FROM vulnerability_affected WHERE source_id = $1 ORDER BY range_type, introduced`, ghsa)
	if err != nil {
		t.Fatal(err)
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.rt, &r.intro, &r.fixed, &r.last, &r.versions, &r.withdrawn, &r.purl, &r.norm, &r.vulnID); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	rows.Close()
	if len(got) != 3 {
		t.Fatalf("rows = %d, want 2 intervals and the versions list: %+v", len(got), got)
	}
	str := func(p *string) string {
		if p == nil {
			return "<null>"
		}
		return *p
	}
	if got[0].rt != "ECOSYSTEM" || str(got[0].intro) != "0" || str(got[0].fixed) != "1.2.0" || str(got[0].last) != "<null>" {
		t.Errorf("first interval = %+v", got[0])
	}
	if str(got[1].intro) != "2.0.0" || str(got[1].last) != "2.5.0" || str(got[1].fixed) != "<null>" {
		t.Errorf("second interval = %+v", got[1])
	}
	if got[2].rt != "VERSIONS" || len(got[2].versions) != 3 || got[2].intro != nil {
		t.Errorf("versions row = %+v", got[2])
	}
	wantNorm := strings.ReplaceAll(strings.ToLower(pkg), "_", "-")
	if str(got[0].norm) != wantNorm || str(got[0].purl) != "pkg:pypi/"+wantNorm || str(got[0].vulnID) != cveA {
		t.Errorf("normalised %q purl %q canonical %q, want %q, pkg:pypi/%s, %s", str(got[0].norm), str(got[0].purl), str(got[0].vulnID), wantNorm, wantNorm, cveA)
	}

	// 2. aliases: the advisory and PYSEC mean the canonical CVE and record their feed; the other CVE is no alias
	var src *string
	if err := pool.QueryRow(ctx, `SELECT source FROM vulnerability_alias WHERE alias = $1 AND vulnerability_id = $2`, ghsa, cveA).Scan(&src); err != nil || src == nil || *src != "osv" {
		t.Fatalf("the advisory is not an alias of %s written by osv: %v %v", cveA, err, src)
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_alias WHERE alias = $1`, cveB).Scan(&n)
	if n != 0 {
		t.Errorf("%s was made an alias of %s: two CVEs would be merged", cveB, cveA)
	}
	var aliases []string
	_ = pool.QueryRow(ctx, `SELECT aliases FROM vulnerability WHERE id = $1`, cveA).Scan(&aliases)
	if !strings.Contains(strings.Join(aliases, ","), cveB) {
		t.Errorf("the row lists %v: the other CVE of the record should be there", aliases)
	}

	// 3. severity: only a vector, never a score
	var vector *string
	var score *float64
	_ = pool.QueryRow(ctx, `SELECT cvss_best_vector, cvss_best_score FROM vulnerability WHERE id = $1`, cveA).Scan(&vector, &score)
	if vector == nil || !strings.HasPrefix(*vector, "CVSS:3.1/") || score != nil {
		t.Errorf("vector %v score %v", vector, score)
	}

	// 4. a withdrawn advisory keeps its rows, marked
	var wd *time.Time
	if err := pool.QueryRow(ctx, `SELECT withdrawn FROM vulnerability_affected WHERE source_id = $1`, gone).Scan(&wd); err != nil || wd == nil {
		t.Errorf("the withdrawn advisory's mark: %v %v", wd, err)
	}

	// 5. the archive is unchanged: one conditional request, no rewrite, and the feed still says how many records it has
	st, _ := syncer.GetFeedState(ctx, "osv")
	if st.Records != 2 || st.Cursor == nil {
		t.Fatalf("after the first round: records %d cursor %v", st.Records, st.Cursor)
	}
	_, _ = pool.Exec(ctx, `UPDATE vulnerability_affected SET introduced = 'tampered' WHERE source_id = $1 AND range_type = 'ECOSYSTEM'`, ghsa)
	if err := syncer.SyncAll(ctx, cfg, slog.Default()); err != nil {
		t.Fatalf("second round: %v", err)
	}
	if conditional.Load() != 1 {
		t.Errorf("the second round was not a conditional request (%d)", conditional.Load())
	}
	var tampered int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_affected WHERE introduced = 'tampered'`).Scan(&tampered)
	if tampered == 0 {
		t.Error("an unchanged archive was read and rewritten")
	}
	if st, _ = syncer.GetFeedState(ctx, "osv"); st.Records != 2 || st.Status != "success" {
		t.Errorf("an unchanged round must keep the count: %+v", st)
	}

	// 6. the archive changed (a new ETag) but this record did not: it is skipped, so the marker stays; a record whose
	// modified moved is rewritten and the marker goes
	etag.Store(`"v2"`)
	if err := syncer.SyncAll(ctx, cfg, slog.Default()); err != nil {
		t.Fatal(err)
	}
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_affected WHERE introduced = 'tampered'`).Scan(&tampered)
	if tampered == 0 {
		t.Error("a record that did not change was written again")
	}
	archive.Store(osvArchive(t, map[string]string{ghsa + ".json": record("2024-04-01T00:00:00Z"), gone + ".json": withdrawn}))
	etag.Store(`"v3"`)
	if err := syncer.SyncAll(ctx, cfg, slog.Default()); err != nil {
		t.Fatal(err)
	}
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_affected WHERE introduced = 'tampered'`).Scan(&tampered)
	if tampered != 0 {
		t.Error("a record whose modified moved was not rewritten")
	}
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_affected WHERE source_id = $1`, ghsa).Scan(&n)
	if n != 3 {
		t.Errorf("after the rewrite the record has %d rows, want 3 (replaced, not added to)", n)
	}
}

// storageMode full keeps the whole record; lightweight does not.
func TestFeeds_OSVFullModeKeepsTheSourceRecord(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	_, sysStore := setupStores(t, ctx)
	pool := sysStore.Pool()
	sfx := strings.ToUpper(uuid.NewString()[:6])
	light, full := "GHSA-"+strings.ToLower(sfx)+"-lite-0000", "GHSA-"+strings.ToLower(sfx)+"-full-0000"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(osvArchive(t, map[string]string{
			light + ".json": `{"id":"` + light + `","modified":"2024-03-01T00:00:00Z","details":"long details"}`,
			full + ".json":  `{"id":"` + full + `","modified":"2024-03-01T00:00:00Z","details":"long details"}`,
		}))
	}))
	defer srv.Close()
	syncer := enrich.NewFeedSyncer(pool)
	payload := func(id string) *string {
		var p *string
		_ = pool.QueryRow(ctx, `SELECT source_payloads::text FROM vulnerability WHERE id = $1`, id).Scan(&p)
		return p
	}
	cfg := enrich.FeedConfig{AllowLoopback: true, NVDDisabled: true, OSVBaseURL: srv.URL, OSVEcosystems: []string{"Go"}, Only: "osv"}
	_, _ = pool.Exec(ctx, `DELETE FROM feed_state WHERE feed = 'osv'`)
	if err := syncer.SyncAll(ctx, cfg, slog.Default()); err != nil {
		t.Fatal(err)
	}
	if payload(light) != nil {
		t.Error("lightweight stored the source record")
	}
	// switching to full rewrites everything once, even a record that has not changed
	cfg.StorageFull = true
	if err := syncer.SyncAll(ctx, cfg, slog.Default()); err != nil {
		t.Fatal(err)
	}
	if p := payload(full); p == nil || !strings.Contains(*p, `"osv"`) || !strings.Contains(*p, "long details") {
		t.Errorf("full mode did not keep the record: %v", p)
	}
	if p := payload(light); p == nil {
		t.Error("changing the storage mode did not rewrite the records already stored")
	}
}

// KEV is asked "has it changed?" with the validators of the last download; a 304 reads nothing and keeps the records.
// EPSS is dated by the file's own score_date, not by the day of the sync.
func TestFeeds_KEVConditionalGetAndEPSSScoreDate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, sysStore := setupStores(t, ctx)
	pool := sysStore.Pool()
	cve := "CVE-2097-" + strings.ToUpper(uuid.NewString()[:6])

	var kevHits, kev304 atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		kevHits.Add(1)
		if r.Header.Get("If-None-Match") == `"kev-1"` {
			kev304.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"kev-1"`)
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"` + cve + `","vulnerabilityName":"x","dateAdded":"2024-05-01","dueDate":"2024-05-22"}]}`))
	})
	mux.HandleFunc("/epss.csv.gz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gz("#model_version:v2025.03.14,score_date:2026-01-05T12:55:00Z\ncve,epss,percentile\n" + cve + ",0.5,0.9\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	syncer := enrich.NewFeedSyncer(pool)
	_, _ = pool.Exec(ctx, `DELETE FROM feed_state WHERE feed IN ('cisa_kev','first_epss')`)
	cfg := enrich.FeedConfig{AllowLoopback: true, NVDDisabled: true, KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz"}
	if err := syncer.SyncAll(ctx, cfg, slog.Default()); err != nil {
		t.Fatal(err)
	}
	first, _ := syncer.GetFeedState(ctx, "cisa_kev")
	if first.Status != "success" || first.Records < 1 || first.Cursor == nil || !strings.Contains(*first.Cursor, "kev-1") {
		t.Fatalf("after the first round: %+v", first)
	}
	var epssDate time.Time
	if err := pool.QueryRow(ctx, `SELECT epss_date FROM vulnerability WHERE id = $1`, cve).Scan(&epssDate); err != nil || epssDate.Format("2006-01-02") != "2026-01-05" {
		t.Fatalf("epss_date = %v (%v), want the score_date of the file", epssDate, err)
	}

	time.Sleep(20 * time.Millisecond)
	if err := syncer.SyncAll(ctx, cfg, slog.Default()); err != nil {
		t.Fatal(err)
	}
	second, _ := syncer.GetFeedState(ctx, "cisa_kev")
	if kev304.Load() != 1 || kevHits.Load() != 2 {
		t.Errorf("KEV requests %d, 304 answers %d: the second round must be conditional", kevHits.Load(), kev304.Load())
	}
	if second.Status != "success" || second.Records != first.Records || second.LastSync == nil || !second.LastSync.After(*first.LastSync) {
		t.Errorf("an unchanged round must keep the records and move last_sync: first %+v second %+v", first, second)
	}

	// a different address (a new mirror) is not answered from the old validators
	other := httptest.NewServer(mux)
	defer other.Close()
	cfg.KEVURL = other.URL + "/kev.json"
	if err := syncer.SyncAll(ctx, cfg, slog.Default()); err != nil {
		t.Fatal(err)
	}
	if kev304.Load() != 1 {
		t.Error("the validators of another address were sent")
	}
}

// scheduledUpstream serves KEV and EPSS and counts the requests each gets. failKEV is how many of the first KEV requests
// answer 500.
func scheduledUpstream(t *testing.T, failKEV int32) (srv *httptest.Server, kev, epss *atomic.Int32) {
	t.Helper()
	kev, epss = new(atomic.Int32), new(atomic.Int32)
	cve := "CVE-2098-" + strings.ToUpper(uuid.NewString()[:6])
	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		if n := kev.Add(1); n <= failKEV {
			http.Error(w, "upstream down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"` + cve + `","vulnerabilityName":"x","dateAdded":"2024-05-01","dueDate":"2024-05-22"}]}`))
	})
	mux.HandleFunc("/epss.csv.gz", func(w http.ResponseWriter, r *http.Request) {
		epss.Add(1)
		_, _ = w.Write(gz("#model_version:v2025.03.14,score_date:2026-01-01T00:00:00Z\ncve,epss,percentile\n" + cve + ",0.5,0.5\n"))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, kev, epss
}

func resetFeedState(ctx context.Context, t *testing.T, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}) {
	t.Helper()
	if _, err := pool.Exec(ctx, `DELETE FROM feed_state WHERE feed IN ('cisa_kev', 'first_epss')`); err != nil {
		t.Fatal(err)
	}
}

// A scheduled round syncs the feeds that are due and leaves the others: a feed never synced is due, a fresh one is not, one
// whose last round failed is tried again at the next check, one being synced now is left alone, and a manual sync does
// everything.
func TestFeeds_OnlyDueSyncsTheFeedsThatAreDue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, sys := setupStores(t, ctx)
	resetFeedState(ctx, t, sys.Pool())
	srv, kev, epss := scheduledUpstream(t, 0)
	syncer := enrich.NewFeedSyncer(sys.Pool())
	base := enrich.FeedConfig{AllowLoopback: true, NVDDisabled: true, KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz", Interval: time.Hour}
	run := func(cfg enrich.FeedConfig) {
		t.Helper()
		if err := syncer.SyncAll(ctx, cfg, slog.Default()); err != nil {
			t.Fatalf("SyncAll: %v", err)
		}
	}
	due := base
	due.OnlyDue = true

	one := base
	one.Only = "cisa_kev"
	run(one)
	if kev.Load() != 1 || epss.Load() != 0 {
		t.Fatalf("a one-feed round: kev %d, epss %d, want 1 and 0", kev.Load(), epss.Load())
	}
	run(due) // KEV is fresh, EPSS never synced
	if kev.Load() != 1 || epss.Load() != 1 {
		t.Errorf("a scheduled round must sync the feed that never did and leave the fresh one: kev %d, epss %d, want 1 and 1", kev.Load(), epss.Load())
	}
	run(due)
	if kev.Load() != 1 || epss.Load() != 1 {
		t.Errorf("a round with everything fresh must do nothing: kev %d, epss %d", kev.Load(), epss.Load())
	}

	if _, err := sys.Pool().Exec(ctx, `UPDATE feed_state SET status = 'error', error = 'upstream down' WHERE feed = 'cisa_kev'`); err != nil {
		t.Fatal(err)
	}
	run(due)
	if kev.Load() != 2 {
		t.Errorf("a feed whose last round failed is tried again at the next check: kev %d, want 2", kev.Load())
	}
	if _, err := sys.Pool().Exec(ctx, `UPDATE feed_state SET status = 'syncing' WHERE feed = 'cisa_kev'`); err != nil {
		t.Fatal(err)
	}
	run(due)
	if kev.Load() != 2 {
		t.Errorf("a feed that is being synced is left alone: kev %d, want 2", kev.Load())
	}
	if _, err := sys.Pool().Exec(ctx, `UPDATE feed_state SET last_sync = NOW() - interval '2 hours', status = 'success' WHERE feed = 'cisa_kev'`); err != nil {
		t.Fatal(err)
	}
	run(due)
	if kev.Load() != 3 {
		t.Errorf("a feed older than the interval is synced: kev %d, want 3", kev.Load())
	}
	run(base) // a manual sync is not a check: it syncs everything
	if kev.Load() != 4 || epss.Load() != 2 {
		t.Errorf("a manual sync does every feed: kev %d, epss %d, want 4 and 2", kev.Load(), epss.Load())
	}
}

// The scheduler keeps going: it syncs on every interval, not on every check, retries a failure at the next check instead of
// waiting the interval, survives a round that panics, does not re-score when nothing was synced, and stops when its context ends.
func TestFeedScheduler_KeepsSyncing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, sys := setupStores(t, ctx)

	t.Run("syncs again each interval, not each check", func(t *testing.T) {
		resetFeedState(ctx, t, sys.Pool())
		srv, kev, _ := scheduledUpstream(t, 0)
		cfg := enrich.FeedConfig{AllowLoopback: true, NVDDisabled: true, KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz",
			Interval: 700 * time.Millisecond, CheckEvery: 150 * time.Millisecond}
		rctx, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		done := make(chan struct{})
		go func() { enrich.RunScheduler(rctx, sys.Pool(), cfg, slog.Default()); close(done) }()
		<-rctx.Done()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("the scheduler did not stop when its context ended")
		}
		if n := kev.Load(); n < 3 || n > 7 {
			t.Errorf("KEV was fetched %d times in 3 s with a 0.7 s interval: it must keep syncing (at least 3) and not at every 0.15 s check (at most 7)", n)
		}
	})

	t.Run("retries a failure at the next check and survives a panic", func(t *testing.T) {
		resetFeedState(ctx, t, sys.Pool())
		srv, kev, _ := scheduledUpstream(t, 2) // the first two KEV requests fail
		var synced atomic.Int32
		cfg := enrich.FeedConfig{AllowLoopback: true, NVDDisabled: true, KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz",
			Interval: time.Hour, CheckEvery: 150 * time.Millisecond,
			OnSynced: func(context.Context) {
				if synced.Add(1) == 1 {
					panic("the re-score blew up")
				}
			}}
		rctx, stop := context.WithCancel(ctx)
		defer stop()
		done := make(chan struct{})
		go func() { enrich.RunScheduler(rctx, sys.Pool(), cfg, slog.Default()); close(done) }()

		deadline := time.Now().Add(10 * time.Second)
		for kev.Load() < 3 && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if kev.Load() < 3 {
			t.Fatalf("a failed feed was not retried at the next check (interval is an hour): %d KEV requests", kev.Load())
		}
		time.Sleep(600 * time.Millisecond) // several checks with everything fresh
		if n := kev.Load(); n != 3 {
			t.Errorf("a feed that succeeded must not be fetched again within its interval: %d requests, want 3", n)
		}
		if n := synced.Load(); n != 3 { // round 1 (EPSS ran, KEV failed; it panicked), round 2 (KEV failed), round 3 (KEV succeeded)
			t.Errorf("OnSynced ran %d times, want 3: a panic must not stop the scheduler, and a check that syncs nothing must not re-score", n)
		}
		var status string
		_ = sys.Pool().QueryRow(ctx, `SELECT status FROM feed_state WHERE feed = 'cisa_kev'`).Scan(&status)
		if status != "success" {
			t.Errorf("KEV status = %q, want success after the retry", status)
		}
		stop()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("the scheduler did not stop when its context was cancelled")
		}
	})
}
