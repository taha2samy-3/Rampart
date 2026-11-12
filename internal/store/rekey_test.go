package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/normalize"
)

// A scanner reports a flaw under a GHSA id. Later enrichment learns the id is an alias of a CVE. The RekeyJob moves
// the finding to the CVE's key, keeps the decision a person made, still finds it under the old key, and merges it
// with a finding that already has the CVE's key (docs/16 D11, D50).
func TestRekeyJob_AliasBecomesCVE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "rk-" + uuid.NewString()[:8], DisplayName: "r", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	sfx := uuid.NewString()[:5]
	cve1, ghsa1 := "CVE-2088-1"+sfx, "GHSA-"+sfx[:4]+"-aaaa-bbbb"
	cve2, ghsa2 := "CVE-2088-2"+sfx, "GHSA-"+sfx[:4]+"-cccc-dddd"
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	source, err := appStore.EnsureScanSource(ctx, tn.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	engine := ingest.NewEngine(appStore)
	loc := func(pkg string) domain.Location {
		return domain.Location{Package: &domain.PackageLocation{Purl: "pkg:npm/" + pkg + "@1.0.0", PurlBase: "pkg:npm/" + pkg, ManifestPath: "package-lock.json"}}
	}
	merge := func(family, vuln, pkg string) {
		raw := domain.RawFinding{Category: domain.CategorySCA, VulnIDs: []string{vuln}, Location: loc(pkg)}
		fp := normalize.ComputeFingerprint(normalize.FingerprintParams{TenantID: tn.ID, AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
			Scope: normalize.ScopeAsset, Family: family, Category: domain.CategorySCA, RuleID: vuln, RawFinding: raw})
		run := &domain.IngestRun{ID: uuid.New(), TenantID: tn.ID, ScanSourceID: source, ApplicationID: app.ID, AssetID: asset.ID, Track: "main",
			ScannerFamily: family, Status: domain.RunMerging, CreatedAt: time.Now().UTC()}
		if err := appStore.CreateIngestRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		scope := ingest.CloseScope{TenantID: tn.ID, ScanSourceID: source, ScannerFamily: family, AssetID: asset.ID, Track: "main"}
		rec := ingest.StagedRecord{ScannerFamily: family, FindingKey: fp.FindingKey, Category: domain.CategorySCA, RuleID: vuln, Title: pkg + " flaw",
			Severity: domain.SeverityHigh, ToolSeverity: "high", VulnID: vuln, ContentHash: "h", SeenAt: time.Now().UTC(), Location: raw.Location}
		if _, err := engine.MergeBatch(ctx, scope, run.ID, app.ID, []ingest.StagedRecord{rec}); err != nil {
			t.Fatal(err)
		}
	}
	findings := func() map[string]*domain.Finding { // by vulnerability id
		all, _ := appStore.ListFindings(ctx, tn.ID)
		out := map[string]*domain.Finding{}
		for _, f := range all {
			out[*f.VulnerabilityID] = f
		}
		return out
	}
	keyOf := func(vuln, pkg string) string {
		return normalize.ComputeFingerprint(normalize.FingerprintParams{TenantID: tn.ID, AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
			Scope: normalize.ScopeAsset, Family: "grype", Category: domain.CategorySCA, RuleID: vuln,
			RawFinding: domain.RawFinding{Category: domain.CategorySCA, VulnIDs: []string{vuln}, Location: loc(pkg)}}).FindingKey
	}

	// Two flaws seen under GHSA ids; the second also under its CVE (another run, another tool version).
	merge("grype", ghsa1, "lodash")
	merge("grype", ghsa2, "express")
	merge("grype", cve2, "express")
	if n := len(findings()); n != 3 {
		t.Fatalf("before the alias: %d findings, want 3", n)
	}
	// A person decided about the first. For the second, the CVE one is the older.
	f1 := findings()[ghsa1]
	req := domain.TriageRequest{State: domain.StateNotAffected, Justification: "vulnerable_code_not_present", Note: "checked"}
	events, err := domain.ApplyTriage(f1, req, "user:sara@acme.example", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := appStore.UpdateFindingTriage(ctx, tn.ID, f1, f1.Version, events); err != nil {
		t.Fatal(err)
	}
	if _, err := sys.Pool().Exec(ctx, `UPDATE finding SET first_seen = NOW() - interval '5 days' WHERE tenant_id = $1 AND vulnerability_id = $2`, tn.ID, cve2); err != nil {
		t.Fatal(err)
	}

	// No alias yet: nothing to do.
	if st, err := ingest.RekeyTenant(ctx, sys, tn.ID); err != nil || st.Renamed+st.Merged != 0 {
		t.Fatalf("no alias: %+v %v", st, err)
	}

	for _, p := range [][2]string{{cve1, ghsa1}, {cve2, ghsa2}} {
		if _, err := sys.Pool().Exec(ctx, `INSERT INTO vulnerability (id, aliases) VALUES ($1, $2) ON CONFLICT DO NOTHING`, p[0], []string{p[1]}); err != nil {
			t.Fatal(err)
		}
		if _, err := sys.Pool().Exec(ctx, `INSERT INTO vulnerability_alias (alias, vulnerability_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, p[1], p[0]); err != nil {
			t.Fatal(err)
		}
	}
	st, err := ingest.RekeyTenant(ctx, sys, tn.ID)
	if err != nil || st.Renamed != 1 || st.Merged != 1 || st.Unverified != 0 {
		t.Fatalf("rekey: %+v %v", st, err)
	}
	got := findings()
	if len(got) != 2 || got[cve1] == nil || got[cve2] == nil {
		t.Fatalf("after the job there are two findings, by CVE: %v", got)
	}
	r := got[cve1]
	if r.ID != f1.ID || r.FindingKey != keyOf(cve1, "lodash") || r.State != domain.StateNotAffected || r.Justification != "vulnerable_code_not_present" {
		t.Fatalf("the finding keeps its identity and its decision, under the CVE's key: %+v", r)
	}
	m := got[cve2]
	if m.FindingKey != keyOf(cve2, "express") || m.OccurrenceCount < 1 {
		t.Fatalf("the merged finding: %+v", m)
	}
	var aliases int
	_ = sys.Pool().QueryRow(ctx, `SELECT count(*) FROM finding_key_alias WHERE tenant_id = $1`, tn.ID).Scan(&aliases)
	if aliases != 2 {
		t.Fatalf("each old key stays resolvable: %d aliases", aliases)
	}
	if again, err := ingest.RekeyTenant(ctx, sys, tn.ID); err != nil || again.Renamed+again.Merged != 0 {
		t.Fatalf("a second pass changes nothing: %+v %v", again, err)
	}
	evs, _ := appStore.GetFindingEvents(ctx, tn.ID, r.ID)
	var rekeyed bool
	for _, e := range evs {
		rekeyed = rekeyed || e.Type == "rekeyed"
	}
	if !rekeyed {
		t.Fatal("the timeline must say the finding was re-keyed")
	}

	// A tool that goes on reporting the GHSA id updates the same finding, it does not make a second one, and the
	// decision stands. A tool that reports the CVE finds it directly.
	merge("grype", ghsa1, "lodash")
	merge("grype", cve1, "lodash")
	if all := findings(); len(all) != 2 || all[cve1].State != domain.StateNotAffected {
		t.Fatalf("after rescans under both ids: %d findings, state %v", len(all), all[cve1].State)
	}
}
