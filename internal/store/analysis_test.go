package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"rampart/internal/analyzer/matcher"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// D143 on PostgreSQL: the record of an analysis (claim, state, due), and the SBOMs it reads, with the isolation of tenants.
func TestSBOMAnalysis_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	mk := func() *domain.Tenant {
		tn := &domain.Tenant{ID: uuid.New(), Slug: "ana-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
		if err := sys.CreateTenant(ctx, tn); err != nil {
			t.Fatal(err)
		}
		return tn
	}
	tn, other := mk(), mk()
	seedFindings(t, ctx, appStore, tn.ID, 0)
	seedFindings(t, ctx, appStore, other.ID, 0)

	seedSBOM := func(tenant uuid.UUID, track string, age time.Duration, pkgs ...string) uuid.UUID {
		app, _ := appStore.LookupApplication(ctx, tenant, "shop")
		asset, _ := appStore.LookupAsset(ctx, tenant, domain.AssetRepository, "github.com/acme/shop")
		run := &domain.IngestRun{ID: uuid.New(), TenantID: tenant, ApplicationID: app.ID, AssetID: asset.ID, Track: track, ScannerFamily: "cyclonedx",
			Format: "cyclonedx", Status: domain.RunCompleted, CreatedAt: time.Now().UTC()}
		if err := appStore.CreateIngestRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		id := uuid.New()
		var comps []domain.SBOMComponent
		for i, p := range pkgs {
			comps = append(comps, domain.SBOMComponent{TenantID: tenant, SBOMID: id, Ref: "ref-" + p, Purl: "pkg:npm/" + p + "@1.0.0", PurlBase: "pkg:npm/" + p, Name: p, Version: "1.0.0", Direct: i == 0})
		}
		if err := appStore.SaveSBOM(ctx, &domain.SBOM{ID: id, TenantID: tenant, AssetID: asset.ID, IngestRunID: run.ID, Track: track, Format: "cyclonedx", SpecVersion: "1.5",
			ComponentCount: len(comps), CreatedAt: time.Now().UTC().Add(-age)}, comps); err != nil {
			t.Fatal(err)
		}
		return id
	}
	oldMain := seedSBOM(tn.ID, "main", 48*time.Hour, "old")
	newMain := seedSBOM(tn.ID, "main", time.Hour, "lodash", "express")
	staging := seedSBOM(tn.ID, "staging", 2*time.Hour, "left-pad")
	foreign := seedSBOM(other.ID, "main", 0, "secret-lib")

	// reading SBOMs
	b, comps, err := appStore.GetSBOMByID(ctx, tn.ID, newMain)
	if err != nil || b.ID != newMain || b.Track != "main" || b.IngestRunID == uuid.Nil || len(comps) != 2 {
		t.Fatalf("GetSBOMByID: %+v %d %v", b, len(comps), err)
	}
	direct := 0
	for _, c := range comps {
		if c.Direct {
			direct++
		}
	}
	if direct != 1 {
		t.Fatalf("direct flags lost: %d", direct)
	}
	if _, _, err := appStore.GetSBOMByID(ctx, tn.ID, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no such SBOM: %v", err)
	}
	if _, _, err := appStore.GetSBOMByID(ctx, tn.ID, foreign); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another tenant's SBOM was readable: %v", err)
	}
	latest, err := appStore.LatestSBOMs(ctx, tn.ID, nil)
	if err != nil || len(latest) != 2 {
		t.Fatalf("LatestSBOMs: %d %v", len(latest), err)
	}
	got := map[uuid.UUID]string{}
	for _, l := range latest {
		got[l.ID] = l.Track
	}
	if got[newMain] != "main" || got[staging] != "staging" || got[oldMain] != "" {
		t.Fatalf("the newest of each track, not the old one: %v", got)
	}
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	if one, _ := appStore.LatestSBOMs(ctx, tn.ID, &asset.ID); len(one) != 2 {
		t.Fatalf("for the asset: %d", len(one))
	}
	if none, _ := appStore.LatestSBOMs(ctx, tn.ID, &[]uuid.UUID{uuid.New()}[0]); len(none) != 0 {
		t.Fatalf("for another asset: %d", len(none))
	}

	ref := domain.AnalyzerRef{Kind: "external", Scope: "cluster", Name: "sonatype"}
	otherRef := domain.AnalyzerRef{Kind: "sbom", Scope: "cluster", Name: "default"}
	rec := func(sbom uuid.UUID, r domain.AnalyzerRef) domain.SBOMAnalysis {
		return domain.SBOMAnalysis{TenantID: tn.ID, SBOMID: sbom, Analyzer: r, Trigger: domain.TriggerUpload}
	}

	// claiming: one at a time, and a finished one can be claimed again
	if ok, err := appStore.ClaimSBOMAnalysis(ctx, rec(newMain, ref), time.Hour); err != nil || !ok {
		t.Fatalf("first claim: %v %v", ok, err)
	}
	if ok, err := appStore.ClaimSBOMAnalysis(ctx, rec(newMain, ref), time.Hour); err != nil || ok {
		t.Fatalf("a second claim while pending succeeded: %v %v", ok, err)
	}
	if ok, _ := appStore.ClaimSBOMAnalysis(ctx, rec(newMain, otherRef), time.Hour); !ok {
		t.Fatal("another analyzer on the same SBOM must be claimable")
	}
	if ok, _ := appStore.ClaimSBOMAnalysis(ctx, rec(staging, ref), time.Hour); !ok {
		t.Fatal("the same analyzer on another SBOM must be claimable")
	}
	time.Sleep(20 * time.Millisecond)
	if ok, _ := appStore.ClaimSBOMAnalysis(ctx, rec(newMain, ref), 0); !ok {
		t.Fatal("a pending analysis that is stale must be claimable (a worker died)")
	}

	// state round trip
	started, finished := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond), time.Now().UTC().Truncate(time.Microsecond)
	a := rec(newMain, ref)
	a.State, a.Attempts, a.Error, a.Components, a.Findings, a.Created, a.Closed, a.StartedAt, a.FinishedAt = domain.AnalysisTimedOut, 3, "no answer", 2, 5, 4, 1, &started, &finished
	if err := appStore.SaveSBOMAnalysis(ctx, a); err != nil {
		t.Fatal(err)
	}
	back, err := appStore.GetSBOMAnalysis(ctx, tn.ID, newMain, ref)
	if err != nil || back.State != domain.AnalysisTimedOut || back.Attempts != 3 || back.Error != "no answer" || back.Components != 2 || back.Findings != 5 ||
		back.Created != 4 || back.Closed != 1 || back.Trigger != domain.TriggerUpload || back.StartedAt == nil || !back.StartedAt.Equal(started) || back.FinishedAt == nil || !back.FinishedAt.Equal(finished) {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	if _, err := appStore.GetSBOMAnalysis(ctx, tn.ID, oldMain, ref); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no record: %v", err)
	}
	if _, err := appStore.GetSBOMAnalysis(ctx, other.ID, newMain, ref); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another tenant read the record: %v", err)
	}
	// a claim that finds the row settled starts it again from nothing
	if ok, _ := appStore.ClaimSBOMAnalysis(ctx, rec(newMain, ref), time.Hour); !ok {
		t.Fatal("a timed out analysis must be claimable")
	}
	if back, _ := appStore.GetSBOMAnalysis(ctx, tn.ID, newMain, ref); back.State != domain.AnalysisPending || back.Attempts != 0 || back.Error != "" || back.Findings != 0 || back.FinishedAt != nil {
		t.Fatalf("a new claim must start clean: %+v", back)
	}

	// what is due
	now := time.Now().UTC()
	settle := func(sbom uuid.UUID, r domain.AnalyzerRef, st domain.AnalysisState, ago time.Duration) {
		t.Helper()
		if _, err := appStore.ClaimSBOMAnalysis(ctx, rec(sbom, r), 0); err != nil {
			t.Fatal(err)
		}
		fin := now.Add(-ago)
		x := rec(sbom, r)
		x.State, x.FinishedAt = st, &fin
		if err := appStore.SaveSBOMAnalysis(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	due := func(r domain.AnalyzerRef) []uuid.UUID {
		t.Helper()
		ids, err := appStore.ListDueSBOMs(ctx, tn.ID, r, now.Add(-24*time.Hour), now.Add(-time.Hour), 10)
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	// never analysed by "fresh": both newest SBOMs, never the old one
	if ids := due(domain.AnalyzerRef{Kind: "external", Scope: "cluster", Name: "fresh"}); len(ids) != 2 {
		t.Fatalf("never analysed: %v", ids)
	}
	time.Sleep(20 * time.Millisecond)
	settle(newMain, ref, domain.AnalysisCompleted, 30*time.Hour) // older than a day: due
	settle(staging, ref, domain.AnalysisFailed, 30*time.Minute)  // failed a moment ago: not yet
	if ids := due(ref); len(ids) != 1 || ids[0] != newMain {
		t.Fatalf("due: %v, want only the completed analysis older than a day", ids)
	}
	settle(staging, ref, domain.AnalysisFailed, 3*time.Hour) // failed long ago: due again
	ids := due(ref)
	if len(ids) != 2 || ids[0] != newMain || ids[1] != staging {
		t.Fatalf("due: %v, want the oldest analysis first", ids)
	}
	settle(newMain, ref, domain.AnalysisCompleted, time.Hour)
	if ids := due(ref); len(ids) != 1 || ids[0] != staging {
		t.Fatalf("due: %v, a fresh analysis is not due", ids)
	}
	settle(staging, ref, domain.AnalysisCancelled, 40*time.Hour)
	if ids := due(ref); len(ids) != 1 || ids[0] != staging {
		t.Fatalf("a cancelled analysis older than a day is due again: %v", ids)
	}
	if _, err := appStore.ClaimSBOMAnalysis(ctx, rec(staging, ref), time.Hour); err != nil { // pending: in flight
		t.Fatal(err)
	}
	if ids := due(ref); len(ids) != 0 {
		t.Fatalf("an analysis in flight is not due: %v", ids)
	}
	// the other analyzer's rows are its own
	if ids := due(otherRef); len(ids) != 1 || ids[0] != staging {
		// otherRef was claimed (pending) on newMain above, never on staging
		t.Fatalf("other analyzer: %v", ids)
	}

	// in flight, across tenants (the system role)
	if _, err := appStore.ClaimSBOMAnalysis(ctx, domain.SBOMAnalysis{TenantID: other.ID, SBOMID: foreign, Analyzer: ref, Trigger: domain.TriggerManual}, time.Hour); err != nil {
		t.Fatal(err)
	}
	n, err := sys.CountAnalysesInFlight(ctx, time.Hour)
	if err != nil || n < 3 { // staging/ref, newMain/otherRef, foreign/ref
		t.Fatalf("in flight: %d %v", n, err)
	}
	if stale, _ := sys.CountAnalysesInFlight(ctx, time.Nanosecond); stale >= n {
		t.Fatalf("an analysis older than the stale time still counts: %d >= %d", stale, n)
	}
}

// D143 on PostgreSQL: the matcher reads the affected ranges the OSV feed loaded, with the right bounds, and leaves out the withdrawn.
func TestFindCandidatesByPurlBase_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	pool := sys.Pool()
	suffix := uuid.NewString()[:8]
	base := "pkg:npm/matcher-test-" + suffix
	vuln := func(id, summary string, score float64) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO vulnerability (id, summary, description, cvss_best_score, cvss_best_vector) VALUES ($1, $2, 'long text', $3, 'CVSS:3.1/AV:N')`, id, summary, score); err != nil {
			t.Fatal(err)
		}
	}
	affected := func(vid, source, purl, rangeType, introduced, fixed, last string, versions []string, withdrawn bool) {
		t.Helper()
		var wd *time.Time
		if withdrawn {
			n := time.Now().UTC()
			wd = &n
		}
		if versions == nil {
			versions = []string{}
		}
		if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_affected
			(vulnerability_id, source_id, ecosystem, package_name, package_name_normalised, purl_base, range_type, introduced, fixed, last_affected, versions, withdrawn)
			VALUES ($1, $2, 'npm', 'x', 'x', $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), $8, $9)`,
			vid, source, purl, rangeType, introduced, fixed, last, versions, wd); err != nil {
			t.Fatal(err)
		}
	}
	idA, idB, idC, idD, idE := "CVE-9-"+suffix+"-A", "CVE-9-"+suffix+"-B", "CVE-9-"+suffix+"-C", "CVE-9-"+suffix+"-D", "CVE-9-"+suffix+"-E"
	vuln(idA, "fixed range", 9.8)
	vuln(idB, "last affected", 5.0)
	vuln(idC, "exact versions", 0)
	vuln(idD, "withdrawn", 9.0)
	vuln(idE, "another package", 9.0)
	affected(idA, "GHSA-"+suffix, base, "SEMVER", "1.0.0", "1.4.2", "", nil, false)
	affected(idB, idB, base, "ECOSYSTEM", "", "", "2.5.0", nil, false)
	affected(idC, idC, base, "VERSIONS", "", "", "", []string{"3.0.0", "3.0.1"}, false)
	affected(idD, idD, base, "SEMVER", "0", "9.9.9", "", nil, true)
	affected(idE, idE, base+"-other", "SEMVER", "0", "9.9.9", "", nil, false)

	// the app role is the one the worker runs as
	cands, err := appStore.FindCandidatesByPurlBase(ctx, []string{base})
	if err != nil {
		t.Fatalf("as the application role: %v", err)
	}
	by := map[string]matcher.Advisory{}
	for _, c := range cands {
		by[c.ID] = c
	}
	if len(by) != 3 || by[idD].ID != "" || by[idE].ID != "" {
		t.Fatalf("candidates: %v (a withdrawn advisory and another package must be left out)", by)
	}
	if a := by[idA]; a.Introduced != "1.0.0" || a.Fixed != "1.4.2" || a.Summary != "fixed range" || a.CVSSScore != 9.8 || a.CVSSVector == "" || len(a.Aliases) != 1 || a.Aliases[0] != "GHSA-"+suffix || a.PurlBase != base {
		t.Fatalf("A: %+v", a)
	}
	if a := by[idB]; a.LastAffected != "2.5.0" || a.Fixed != "" || a.Introduced != "" {
		t.Fatalf("B: %+v", a)
	}
	if a := by[idC]; a.RangeType != "VERSIONS" || len(a.Versions) != 2 {
		t.Fatalf("C: %+v", a)
	}

	// end to end: the matcher over the real table
	m := matcher.New(appStore)
	findings, err := m.MatchComponents(ctx, []domain.SBOMComponent{
		{Ref: "in", Name: "in", Version: "1.2.0", Purl: base + "@1.2.0", PurlBase: base},       // A (1.0.0 to 1.4.2); B has no start, so 1.2.0 is inside it too
		{Ref: "fixed", Name: "fixed", Version: "1.4.2", Purl: base + "@1.4.2", PurlBase: base}, // A is fixed here, B (up to 2.5.0) still holds
		{Ref: "exact", Name: "exact", Version: "3.0.1", Purl: base + "@3.0.1", PurlBase: base}, // only C
		{Ref: "past", Name: "past", Version: "4.0.0", Purl: base + "@4.0.0", PurlBase: base},   // nothing
		{Ref: "none", Name: "none", Version: "1.0.0", Purl: "pkg:npm/unknown@1.0.0", PurlBase: "pkg:npm/unknown"},
	})
	if err != nil {
		t.Fatal(err)
	}
	perVersion := map[string]map[string]bool{}
	for _, f := range findings {
		v := f.Location.Package.InstalledVersion
		if perVersion[v] == nil {
			perVersion[v] = map[string]bool{}
		}
		perVersion[v][f.RuleID] = true
	}
	if !perVersion["1.2.0"][idA] || !perVersion["1.2.0"][idB] || perVersion["1.4.2"][idA] || !perVersion["1.4.2"][idB] || !perVersion["3.0.1"][idC] || len(perVersion["3.0.1"]) != 1 || len(perVersion["4.0.0"]) != 0 {
		t.Fatalf("matches by version: %v", perVersion)
	}
	for _, f := range findings {
		if f.RuleID == idA && f.Severity != domain.SeverityCritical {
			t.Errorf("a CVSS score of 9.8 is critical: %v", f.Severity)
		}
	}
}

// The Parsers page says when each parser last worked: the last run that used it, how it ended, and the last time one completed. An analyzer's
// merge is not a parser's work, and another tenant's runs are not read.
func TestLastRunByParser_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	mk := func() *domain.Tenant {
		tn := &domain.Tenant{ID: uuid.New(), Slug: "lr-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
		if err := sys.CreateTenant(ctx, tn); err != nil {
			t.Fatal(err)
		}
		return tn
	}
	tn, other := mk(), mk()
	seedFindings(t, ctx, appStore, tn.ID, 0)
	seedFindings(t, ctx, appStore, other.ID, 0)
	now := time.Now().UTC()
	run := func(tenant uuid.UUID, format string, status domain.IngestRunStatus, ago time.Duration, errText string) uuid.UUID {
		app, _ := appStore.LookupApplication(ctx, tenant, "shop")
		asset, _ := appStore.LookupAsset(ctx, tenant, domain.AssetRepository, "github.com/acme/shop")
		r := &domain.IngestRun{ID: uuid.New(), TenantID: tenant, ApplicationID: app.ID, AssetID: asset.ID, Track: "main", ScannerFamily: format, Format: format,
			Status: status, Error: errText, CreatedAt: now.Add(-ago)}
		if err := appStore.CreateIngestRun(ctx, r); err != nil {
			t.Fatal(err)
		}
		if errText != "" { // the reason is written when a run ends, as Processor.Finish does
			r.Error = errText
			if err := appStore.UpdateIngestRun(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
		return r.ID
	}
	run(tn.ID, "builtin:sarif", domain.RunCompleted, 5*time.Hour, "")
	lastBad := run(tn.ID, "builtin:sarif", domain.RunFailed, time.Hour, "parse_error")
	run(tn.ID, "builtin:trivy", domain.RunFailed, 2*time.Hour, "sha256_mismatch") // never completed
	run(tn.ID, "sbom-analysis", domain.RunCompleted, time.Minute, "")             // an analyzer's merge
	run(other.ID, "builtin:semgrep", domain.RunCompleted, time.Minute, "")

	got, err := appStore.LastRunByParser(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	s := got["builtin:sarif"]
	if s.RunID != lastBad || s.Status != domain.RunFailed || s.Error != "parse_error" || s.LastSuccess == nil || s.LastSuccess.After(now.Add(-4*time.Hour)) {
		t.Fatalf("sarif: the last run failed and an earlier one completed: %+v", s)
	}
	if tr := got["builtin:trivy"]; tr.Status != domain.RunFailed || tr.LastSuccess != nil {
		t.Fatalf("trivy never completed: %+v", tr)
	}
	if _, ok := got["sbom-analysis"]; ok {
		t.Fatal("an analysis is not a parser's work")
	}
	if _, ok := got["builtin:semgrep"]; ok {
		t.Fatal("another tenant's run was read")
	}
}
