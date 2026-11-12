package store_test

import (
	"context"
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

// Two scanners report the same flaw on the same package and asset, one under the CVE and one under a GHSA id
// that is an alias of it. They stay two findings (D24: no merge) but form one correlation group.
func TestCorrelationGroup_AcrossScannersAndAliases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sysStore := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "corr-" + uuid.NewString()[:8], DisplayName: "c", CreatedAt: time.Now().UTC()}
	if err := sysStore.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	cve, ghsa := "CVE-2088-"+uuid.NewString()[:6], "GHSA-"+uuid.NewString()[:4]+"-zzzz-yyyy"
	cve = "CVE-2088-" + cve[len(cve)-6:]
	if _, err := sysStore.Pool().Exec(ctx, `INSERT INTO vulnerability (id, aliases) VALUES ($1, $2) ON CONFLICT DO NOTHING`, cve, []string{ghsa}); err != nil {
		t.Fatal(err)
	}
	if _, err := sysStore.Pool().Exec(ctx, `INSERT INTO vulnerability_alias (alias, vulnerability_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, ghsa, cve); err != nil {
		t.Fatal(err)
	}

	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	source, err := appStore.EnsureScanSource(ctx, tn.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	engine := ingest.NewEngine(appStore)
	merge := func(family, vuln string) {
		run := &domain.IngestRun{ID: uuid.New(), TenantID: tn.ID, ScanSourceID: source, ApplicationID: app.ID, AssetID: asset.ID, Track: "main",
			ScannerFamily: family, Status: domain.RunMerging, CreatedAt: time.Now().UTC()}
		if err := appStore.CreateIngestRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		scope := ingest.CloseScope{TenantID: tn.ID, ScanSourceID: source, ScannerFamily: family, AssetID: asset.ID, Track: "main"}
		rec := ingest.StagedRecord{ScannerFamily: family, FindingKey: family + "-" + vuln, Category: domain.CategorySCA, RuleID: vuln, Title: "lodash flaw",
			Severity: domain.SeverityHigh, ToolSeverity: "high", VulnID: vuln, ContentHash: "h", SeenAt: time.Now().UTC(),
			Location: domain.Location{Package: &domain.PackageLocation{PurlBase: "pkg:npm/lodash"}}}
		if _, err := engine.MergeBatch(ctx, scope, run.ID, app.ID, []ingest.StagedRecord{rec}); err != nil {
			t.Fatal(err)
		}
	}
	merge("trivy", cve)
	merge("grype", ghsa)
	merge("trivy", "CVE-2088-000000") // an unrelated finding must not join the group

	all, _ := appStore.ListFindings(ctx, tn.ID)
	var trivy, grype *domain.Finding
	for _, f := range all {
		switch f.RuleScannerFamily {
		case "grype":
			grype = f
		case "trivy":
			if f.RuleID == cve {
				trivy = f
			}
		}
	}
	if trivy == nil || grype == nil || trivy.ID == grype.ID {
		t.Fatal("each tool keeps its own finding (D24)")
	}

	authn := auth.NewAuthenticatorWithStore(appStore)
	token := authn.DefaultAdminToken(tn.ID)
	api := query.NewAPIWithAuth(appStore, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	get := func(id uuid.UUID) []query.CorrelatedRef {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/findings/"+id.String(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var out query.FindingResponse
		_ = json.NewDecoder(res.Body).Decode(&out)
		return out.AlsoReportedBy
	}
	if g := get(trivy.ID); len(g) != 1 || g[0].ID != grype.ID || g[0].Scanner != "grype" {
		t.Fatalf("trivy finding: also_reported_by = %+v, want the grype finding", g)
	}
	if g := get(grype.ID); len(g) != 1 || g[0].ID != trivy.ID {
		t.Fatalf("grype finding (GHSA id): also_reported_by = %+v, want the trivy finding", g)
	}
}
