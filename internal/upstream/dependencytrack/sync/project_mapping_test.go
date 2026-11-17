package sync_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	gosync "sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	dtclient "rampart/internal/upstream/dependencytrack/client"
	dtsync "rampart/internal/upstream/dependencytrack/sync"
)

const oneFinding = `[{"component":{"name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"},"vulnerability":{"vulnId":"CVE-2021-23337","severity":"HIGH"}}]`

// mappingFixture serves a Dependency-Track with projects whose application property can change, and builds a syncer.
type mappingFixture struct {
	syncer    *dtsync.Syncer
	st        *mockSyncerStore
	eng       *mockMergeEngine
	appA      uuid.UUID
	appB      uuid.UUID
	tenant    uuid.UUID
	source    uuid.UUID
	mu        gosync.Mutex
	prop      map[string]string // project uuid -> value of the rampart.application property
	notLatest map[string]bool
}

func newMappingFixture(t *testing.T, cfg dtsync.MappingConfig) *mappingFixture {
	t.Helper()
	f := &mappingFixture{st: newMockSyncerStore(), eng: &mockMergeEngine{}, appA: uuid.New(), appB: uuid.New(), tenant: uuid.New(), source: uuid.New(),
		prop: map[string]string{}, notLatest: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var id, rest string
		if n, _ := splitProjectPath(r.URL.Path); n != "" {
			id, rest = n, ""
			_ = rest
		}
		switch {
		case matchPath(r.URL.Path, "/api/v1/finding/project/"):
			_, _ = w.Write([]byte(oneFinding))
		case matchSuffix(r.URL.Path, "/property"):
			v := f.prop[projectOf(r.URL.Path)]
			if v == "" {
				_ = json.NewEncoder(w).Encode([]dtclient.Property{})
				return
			}
			_ = json.NewEncoder(w).Encode([]dtclient.Property{{Group: "integrations", Name: "rampart.application", Value: v}})
		case matchPath(r.URL.Path, "/api/v1/project/"):
			id = projectOf(r.URL.Path)
			latest := !f.notLatest[id]
			_ = json.NewEncoder(w).Encode(dtclient.Project{UUID: id, Name: "svc-" + id, Version: "1", Active: true, IsLatest: &latest})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client := dtclient.NewClient(dtclient.Config{BaseURL: srv.URL, APIKey: "k", Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true}})
	apps := &mockAppResolver{apps: map[string]*domain.Application{
		"app-a": {ID: f.appA, TenantID: f.tenant, Slug: "app-a"}, "app-b": {ID: f.appB, TenantID: f.tenant, Slug: "app-b"}}}
	engine, err := dtsync.NewMappingEngine(cfg, nil, apps)
	if err != nil {
		t.Fatal(err)
	}
	f.syncer = dtsync.NewSyncer(client, f.st, f.eng, engine)
	f.syncer.SetSettleChecker(dtsync.NewSettleChecker(client, 5*time.Millisecond, 50*time.Millisecond))
	return f
}

func (f *mappingFixture) setProp(project, app string) {
	f.mu.Lock()
	f.prop[project] = app
	f.mu.Unlock()
}
func (f *mappingFixture) sync(t *testing.T, project string) {
	t.Helper()
	if err := f.syncer.SyncProject(context.Background(), f.tenant, f.source, project); err != nil {
		t.Fatalf("SyncProject %s: %v", project, err)
	}
}

func projectOf(path string) string {
	parts := splitPath(path)
	for i, p := range parts {
		if p == "project" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
func splitPath(p string) []string {
	var out []string
	cur := ""
	for _, c := range p {
		if c == '/' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
func matchPath(p, prefix string) bool { return len(p) >= len(prefix) && p[:len(prefix)] == prefix }
func matchSuffix(p, suffix string) bool {
	return len(p) >= len(suffix) && p[len(p)-len(suffix):] == suffix
}
func splitProjectPath(p string) (string, string) { return projectOf(p), "" }

// "Map project" in the UI stored the mapping and nothing read it: the sync took the application from the rules only, so a
// project mapped by hand kept no findings, and the portfolio sync did not schedule it. A person's mapping comes first,
// and it bypasses the project filters (an older version a person chose to read).
func TestSyncer_AProjectMappedByHandIsRead(t *testing.T) {
	f := newMappingFixture(t, dtsync.MappingConfig{UseProjectProperties: true}) // no default: the rules map nothing for p1
	f.sync(t, "p1")
	if f.eng.mergedBatches != 0 {
		t.Fatalf("no rule maps p1, so nothing is read: %d batches", f.eng.mergedBatches)
	}

	if err := f.st.MapDTrackProject(context.Background(), f.tenant, "p1", f.appA); err != nil {
		t.Fatal(err)
	}
	f.sync(t, "p1")
	if f.eng.mergedBatches != 1 {
		t.Fatalf("a project mapped by hand must be read: %d batches", f.eng.mergedBatches)
	}
	if a := f.st.assets["dtrack://dtrack/svc-p1"]; a == nil || a.ApplicationID == nil || *a.ApplicationID != f.appA {
		t.Fatalf("its asset is in the application the person chose: %+v", a)
	}

	// A person's mapping beats a rule that names another application.
	f.setProp("p1", "app-b")
	f.sync(t, "p1")
	if a := f.st.assets["dtrack://dtrack/svc-p1"]; *a.ApplicationID != f.appA {
		t.Errorf("the property says app-b, the person said app-a: the person wins: %v", *a.ApplicationID)
	}

	// And it bypasses the filters: an older version that versions: latest would drop.
	f.notLatest["p2"] = true
	f.sync(t, "p2")
	before := f.eng.mergedBatches // p1 was read twice
	if before != 2 {
		t.Fatalf("p1 was read twice, p2 (an older version) not at all: %d batches", before)
	}
	_ = f.st.UpsertDTrackProject(context.Background(), domain.DTrackProjectRecord{TenantID: f.tenant, SourceID: f.source, ProjectUUID: "p2", Name: "svc-p2"})
	_ = f.st.MapDTrackProject(context.Background(), f.tenant, "p2", f.appB)
	f.sync(t, "p2")
	if f.eng.mergedBatches != before+1 {
		t.Fatalf("a person who maps an older version wants it read: %d batches, was %d", f.eng.mergedBatches, before)
	}
}

// The asset of a project was made once, in the application the mapping gave that day, and stayed there when the
// mapping changed: a rule edited, the default removed, a project mapped by hand. Its findings are in the new one now.
func TestSyncer_TheAssetFollowsTheMapping(t *testing.T) {
	f := newMappingFixture(t, dtsync.MappingConfig{UseProjectProperties: true})
	f.setProp("p1", "app-a")
	f.sync(t, "p1")
	a := f.st.assets["dtrack://dtrack/svc-p1"]
	if a == nil || *a.ApplicationID != f.appA {
		t.Fatalf("created under app-a: %+v", a)
	}

	f.setProp("p1", "app-b") // the rule now says app-b
	f.sync(t, "p1")
	if a := f.st.assets["dtrack://dtrack/svc-p1"]; *a.ApplicationID != f.appB {
		t.Errorf("the asset must follow the mapping to app-b, it stayed in %v", *a.ApplicationID)
	}
	if f.eng.mergedBatches != 2 {
		t.Errorf("both syncs read the project: %d", f.eng.mergedBatches)
	}
}
