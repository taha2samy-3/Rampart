package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	ingestpkg "rampart/internal/ingest"
	"rampart/internal/query"
)

func getJSON[T any](t *testing.T, h *uploadHarness, token, path string) (int, T) {
	t.Helper()
	var out T
	code, body := h.callAs(token, "GET", path, nil, nil)
	_ = json.Unmarshal(body, &out)
	return code, out
}

func TestOverviewAndApplications(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	viewer := h.tokenFor(auth.RoleViewer, "viewer@acme.example")
	ingest := func(repo string, rules map[string]string) {
		rep := miniSARIF(rules)
		run := h.waitRun(h.uploadAndComplete(rep, domain.UploadContext{Repository: repo, Branch: "main", Commit: "c-" + uuid.NewString()[:6]}))
		if run.Status != domain.RunCompleted {
			t.Fatalf("ingest: %s %s", run.Status, run.Error)
		}
	}
	// The applications exist before anything is scanned (the operator creates them from Application objects), and
	// their repositories are linked to them, so each scan lands under its own application (D10).
	for _, name := range []string{"shop", "billing"} {
		app := &domain.Application{ID: uuid.New(), TenantID: h.tenant, Slug: name, Name: name, BusinessCriticality: "high", Lifecycle: "production", CreatedAt: time.Now().UTC()}
		if err := h.store.CreateApplication(ctx, app); err != nil {
			t.Fatal(err)
		}
		repo := domain.UploadContext{Repository: "github.com/acme/" + name, Branch: "main"}
		now := time.Now().UTC()
		if err := h.store.CreateAsset(ctx, &domain.Asset{ID: uuid.New(), TenantID: h.tenant, ApplicationID: &app.ID, Type: domain.AssetRepository,
			Key: ingestpkg.DeriveAssetKey(domain.AssetRepository, repo), DisplayName: name, Active: true, FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	ingest("github.com/acme/shop", map[string]string{"rule.a": "9.8", "rule.b": "7.5", "rule.c": "2.0"})
	ingest("github.com/acme/billing", map[string]string{"rule.d": "2.0"})
	// An application nothing has ever been scanned for.
	empty := &domain.Application{ID: uuid.New(), TenantID: h.tenant, Slug: "ghost", Name: "Ghost", BusinessCriticality: "low", Lifecycle: "production", CreatedAt: time.Now().UTC()}
	if err := h.store.CreateApplication(ctx, empty); err != nil {
		t.Fatal(err)
	}

	// The list: the riskiest first, the counts add up, the application with no scan is there with zeros.
	code, list := getJSON[struct{ Items []domain.AppSummary }](t, h, viewer, "/api/v1/applications")
	if code != http.StatusOK || len(list.Items) != 3 {
		t.Fatalf("applications: %d, %d items", code, len(list.Items))
	}
	shop, billing, ghost := list.Items[0], list.Items[1], list.Items[2]
	total := func(s domain.AppSummary) int {
		return s.Open["critical"] + s.Open["high"] + s.Open["medium"] + s.Open["low"]
	}
	if total(shop) != 3 || total(billing) != 1 || total(ghost) != 0 || ghost.Name != "Ghost" {
		t.Fatalf("open findings: %d %d %d", total(shop), total(billing), total(ghost))
	}
	if shop.RiskScore <= billing.RiskScore || shop.RiskScore == 0 {
		t.Fatalf("the riskiest application is first: %d vs %d", shop.RiskScore, billing.RiskScore)
	}
	if shop.Exposure != shop.Open["critical"]+shop.Open["high"] || shop.Exposure == 0 {
		t.Fatalf("exposure %d", shop.Exposure)
	}
	if shop.LastScan == nil || ghost.LastScan != nil {
		t.Fatalf("last scan: %v / %v", shop.LastScan, ghost.LastScan)
	}

	// One of the shop's findings is overdue (and marked), one is fixed by a rescan without it.
	ids := findingIDs(t, h)
	a, _, _ := h.store.GetFinding(ctx, h.tenant, ids["rule.a"])
	past := time.Now().UTC().Add(-48 * time.Hour)
	a.SLADue = &past
	if err := h.store.UpdateFindingRisk(ctx, h.tenant, []*domain.Finding{a}); err != nil {
		t.Fatal(err)
	}
	if n, err := h.scorer.MarkBreaches(ctx, h.tenant, time.Now().UTC()); err != nil || n != 1 {
		t.Fatalf("breaches: %d %v", n, err)
	}
	ingest("github.com/acme/shop", map[string]string{"rule.a": "9.8", "rule.b": "7.5"}) // rule.c is gone: fixed

	code, page := getJSON[query.ApplicationPage](t, h, viewer, "/api/v1/applications/"+shop.ID.String()+"/summary")
	if code != http.StatusOK || page.Slug != "shop" {
		t.Fatalf("application page: %d %+v", code, page.AppSummary)
	}
	if total(page.AppSummary) != 2 || page.SLABreached != 1 {
		t.Fatalf("after the rescan: %d open, %d breached", total(page.AppSummary), page.SLABreached)
	}
	if page.SLA.Within != 1 || page.SLA.Breached != 1 || page.SLA.Late != 0 || page.SLA.Adherence == nil || *page.SLA.Adherence != 0.5 {
		t.Fatalf("SLA standing: %+v (one fixed in time, one breached: 50 %%)", page.SLA)
	}
	if len(page.MTTR) != 1 || page.MTTR[0].Fixed != 1 || page.MTTR[0].Days < 0 {
		t.Fatalf("MTTR: %+v", page.MTTR)
	}
	if len(page.Coverage) != 1 || page.Coverage[0].Scanner != "semgrep" || page.Coverage[0].Asset == "" {
		t.Fatalf("coverage: %+v", page.Coverage)
	}
	if len(page.TopFindings) != 2 || page.TopFindings[0].RiskScore < page.TopFindings[1].RiskScore {
		t.Fatalf("top findings: %+v", page.TopFindings)
	}

	// The overview.
	code, ov := getJSON[domain.Overview](t, h, viewer, "/api/v1/dashboards/overview")
	if code != http.StatusOK {
		t.Fatalf("overview: %d", code)
	}
	if ov.Changes.New != 4 || ov.Changes.Fixed != 1 || ov.Changes.Reopened != 0 {
		t.Fatalf("what changed: %+v (4 first seen, 1 fixed)", ov.Changes)
	}
	if got := ov.Open["critical"] + ov.Open["high"] + ov.Open["medium"] + ov.Open["low"]; got != 3 {
		t.Fatalf("open by band: %v", ov.Open)
	}
	if ov.OverdueTotal != 1 || len(ov.Overdue) != 1 || ov.Overdue[0].ID != a.ID || ov.Overdue[0].AppSlug != "shop" {
		t.Fatalf("overdue queue: %d %+v", ov.OverdueTotal, ov.Overdue)
	}
	if ov.SLA.Adherence == nil || len(ov.TopApps) == 0 || ov.TopApps[0].Slug != "shop" {
		t.Fatalf("sla %+v top %+v", ov.SLA, ov.TopApps)
	}
	var gap bool
	for _, g := range ov.Gaps {
		gap = gap || g.Slug == "ghost"
		if g.Slug == "shop" {
			t.Fatal("an application scanned a minute ago is not a coverage gap")
		}
	}
	if !gap {
		t.Fatal("an application that was never scanned is a coverage gap")
	}
	// A paused clock is not overdue: accepting the risk takes it off the queue.
	boss := h.tokenFor(auth.RoleAdmin, "boss@acme.example")
	if code, body := h.callAs(boss, "POST", "/api/v1/risk-acceptances", map[string]any{"findingIds": []string{a.ID.String()}, "justification": "tracked", "expiresAt": days(20)}, nil); code != http.StatusCreated {
		t.Fatalf("accept: %d %s", code, body)
	}
	if _, ov2 := getJSON[domain.Overview](t, h, viewer, "/api/v1/dashboards/overview"); ov2.OverdueTotal != 0 {
		t.Fatalf("an accepted finding is off the overdue queue, got %d", ov2.OverdueTotal)
	}

	// The trend: today's point matches what the overview says.
	code, tr := getJSON[struct {
		Metric string
		Points []struct {
			Day   string
			Value int
		}
	}](t, h, viewer, "/api/v1/metrics/trend?metric=open&days=7")
	if code != http.StatusOK || len(tr.Points) != 7 || tr.Points[6].Day != time.Now().UTC().Format("2006-01-02") {
		t.Fatalf("trend: %d %+v", code, tr)
	}
	if tr.Points[0].Value != 0 || tr.Points[6].Value != 2 { // 3 open, then the accepted one is no longer active
		t.Fatalf("open per day: %+v", tr.Points)
	}
	_, news := getJSON[struct{ Points []struct{ Value int } }](t, h, viewer, "/api/v1/metrics/trend?metric=new&days=3")
	_, closed := getJSON[struct{ Points []struct{ Value int } }](t, h, viewer, "/api/v1/metrics/trend?metric=closed&days=3")
	if news.Points[2].Value != 4 || closed.Points[2].Value != 1 {
		t.Fatalf("new %v closed %v", news.Points, closed.Points)
	}
	if code, _ := getJSON[map[string]any](t, h, viewer, "/api/v1/metrics/trend?metric=banana"); code != http.StatusBadRequest {
		t.Fatalf("bad metric: %d", code)
	}

	// Another tenant sees none of it.
	other := newUploadHarness(t)
	oViewer := other.tokenFor(auth.RoleViewer, "eve@other.example")
	if _, l := getJSON[struct{ Items []domain.AppSummary }](t, other, oViewer, "/api/v1/applications"); len(l.Items) != 0 {
		t.Fatalf("SECURITY VIOLATION: another tenant lists %d applications", len(l.Items))
	}
	if code, _ := getJSON[map[string]any](t, other, oViewer, "/api/v1/applications/"+shop.ID.String()+"/summary"); code != http.StatusNotFound {
		t.Fatalf("SECURITY VIOLATION: another tenant read an application page: %d", code)
	}
	if _, o := getJSON[domain.Overview](t, other, oViewer, "/api/v1/dashboards/overview"); o.Changes.New != 0 || o.OverdueTotal != 0 || len(o.TopApps) != 0 {
		t.Fatalf("SECURITY VIOLATION: another tenant's overview shows data: %+v", o.Changes)
	}
	// And a request without a token is refused.
	if code, _ := getJSON[map[string]any](t, h, "nope", "/api/v1/dashboards/overview"); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", code)
	}
}
