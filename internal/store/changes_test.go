package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// What changed in an application over a range: what appeared, what was closed (and how), what came back, what was open
// at the end, with exact counts and the range before it. The shape of the report Snyk calls "new and resolved issues".
func TestApplicationChanges_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "chg-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	day := func(n int) time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC).AddDate(0, 0, n) }

	cve := func(id string) *string { return &id }
	mk := func(name string, vuln *string, sev domain.Severity, state domain.FindingState, first time.Time, resolved *time.Time, res domain.Resolution) *domain.Finding {
		f := &domain.Finding{ID: uuid.New(), TenantID: tn.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
			RuleScannerFamily: "trivy", RuleID: name, Title: name, Category: domain.CategorySCA, Severity: sev, ToolSeverity: string(sev), RiskBand: sev,
			RiskScore: map[domain.Severity]int{domain.SeverityCritical: 900, domain.SeverityHigh: 600, domain.SeverityMedium: 300, domain.SeverityLow: 100}[sev],
			State:     state, FirstSeen: first, LastSeen: first, ResolvedAt: resolved, OccurrenceCount: 1, Version: 1, CreatedAt: first, UpdatedAt: first, VulnerabilityID: vuln}
		if resolved != nil {
			r := res
			f.Resolution = &r
		}
		return f
	}
	// The range is Nov 11 to Nov 20 (to is exclusive: Nov 21 00:00). The range before it is Nov 1 to Nov 10.
	from, to := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	fixedAt, notAffAt, prevFixed, oldFixed := day(14), day(15), day(5), day(-40)
	fs := []*domain.Finding{
		mk("old-open", cve("CVE-2020-0001"), domain.SeverityHigh, domain.StateOpen, day(-30), nil, ""),                               // before the range, still open
		mk("old-fixed-in", cve("CVE-2020-0002"), domain.SeverityHigh, domain.StateFixed, day(-30), &fixedAt, domain.ResolutionFixed), // open at start, fixed inside
		mk("old-long-gone", cve("CVE-2019-0003"), domain.SeverityLow, domain.StateFixed, day(-60), &oldFixed, domain.ResolutionFixed),
		mk("new-open", cve("CVE-2026-1111"), domain.SeverityCritical, domain.StateOpen, day(12), nil, ""), // new inside, still open
		mk("new-and-gone", cve("CVE-2026-2222"), domain.SeverityMedium, domain.StateFixed, day(13), &fixedAt, domain.ResolutionFixed),
		mk("new-notaffected", cve("CVE-2026-3333"), domain.SeverityMedium, domain.StateNotAffected, day(13), &notAffAt, domain.ResolutionNotAffected),
		mk("prev-new", cve("CVE-2026-0444"), domain.SeverityLow, domain.StateFixed, day(2), &prevFixed, domain.ResolutionFixed), // in the previous range only
		mk("after", cve("CVE-2026-9999"), domain.SeverityHigh, domain.StateOpen, day(25), nil, ""),                              // after the range
	}
	if err := appStore.UpsertFindings(ctx, tn.ID, fs); err != nil {
		t.Fatal(err)
	}
	// "old-open" was closed and came back inside the range.
	if err := appStore.RecordFindingEvents(ctx, tn.ID, []*domain.FindingEvent{
		{ID: uuid.New(), FindingID: fs[0].ID, At: day(16), Actor: "system:parser", Type: "reactivated"},
		{ID: uuid.New(), FindingID: fs[0].ID, At: day(-2), Actor: "system:parser", Type: "reactivated"}, // before the range: not counted
	}); err != nil {
		t.Fatal(err)
	}

	r, err := appStore.ApplicationChanges(ctx, tn.ID, app.ID, from, to)
	if err != nil {
		t.Fatal(err)
	}
	names := func(cs []store.FindingChange) map[string]bool {
		m := map[string]bool{}
		for _, c := range cs {
			m[c.RuleID] = true
		}
		return m
	}
	if n := names(r.New); len(r.New) != 3 || !n["new-open"] || !n["new-and-gone"] || !n["new-notaffected"] {
		t.Errorf("new in the range: %v", n)
	}
	if n := names(r.Closed); len(r.Closed) != 3 || !n["old-fixed-in"] || !n["new-and-gone"] || !n["new-notaffected"] {
		t.Errorf("closed in the range (any resolution): %v", n)
	}
	for _, c := range r.Closed {
		if c.RuleID == "new-notaffected" && c.Resolution != "not_affected" {
			t.Errorf("a closed finding says how it was closed: %+v", c)
		}
	}
	if n := names(r.Reopened); len(r.Reopened) != 1 || !n["old-open"] || !r.Reopened[0].At.Equal(day(16)) {
		t.Errorf("reopened in the range, once, with the time it came back: %+v", r.Reopened)
	}
	// Open at the end: old-open, new-open (the others were closed inside the range; "after" was not seen yet).
	if n := names(r.OpenAtEnd); len(r.OpenAtEnd) != 2 || !n["old-open"] || !n["new-open"] || r.OpenAtEnd[0].RuleID != "new-open" {
		t.Errorf("open at the end, worst first: %+v", r.OpenAtEnd)
	}
	want := struct{ new, closed, reopened, start, end int }{3, 3, 1, 2, 2}
	c := r.Counts
	if c.New != want.new || c.Closed != want.closed || c.Reopened != want.reopened || c.OpenAtStart != want.start || c.OpenAtEnd != want.end {
		t.Errorf("counts: %+v, want %+v", c, want)
	}
	if r.Previous.New != 1 || r.Previous.Closed != 1 {
		t.Errorf("the range before it (Nov 1 to Nov 10): %+v", r.Previous)
	}
	// The chart: one entry per day, new and closed on the days they happened.
	if len(r.Days) != 10 || r.Days[0].Day != "2026-11-11" || r.Days[9].Day != "2026-11-20" {
		t.Fatalf("ten days: %+v", r.Days)
	}
	byDay := map[string]int{}
	for _, d := range r.Days {
		byDay["new:"+d.Day], byDay["closed:"+d.Day] = d.New, d.Closed
	}
	if byDay["new:2026-11-13"] != 1 || byDay["new:2026-11-14"] != 2 || byDay["closed:2026-11-15"] != 2 || byDay["closed:2026-11-16"] != 1 {
		t.Errorf("per day: %v", byDay)
	}

	// Another tenant sees none of it.
	other := &domain.Tenant{ID: uuid.New(), Slug: "chg2-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, other); err != nil {
		t.Fatal(err)
	}
	if o, err := appStore.ApplicationChanges(ctx, other.ID, app.ID, from, to); err != nil || o.Counts.New != 0 || len(o.OpenAtEnd) != 0 {
		t.Errorf("tenant isolation: %+v %v", o, err)
	}
}

// An application with many findings must answer in a moment: the queries read only that application's rows by the
// (tenant, application) index, and the list queries are cut at ChangeLimit. Skipped with -short.
func TestApplicationChanges_LargeApplication_OnPostgreSQL(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds 10,000 findings")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 360*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "big-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	base := time.Now().UTC().AddDate(0, 0, -60)
	const total = 10000
	seedStart := time.Now()
	for start := 0; start < total; start += 5000 {
		batch := make([]*domain.Finding, 0, 5000)
		for i := start; i < start+5000; i++ {
			first := base.Add(time.Duration(i%1440) * time.Hour)
			f := &domain.Finding{ID: uuid.New(), TenantID: tn.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
				RuleScannerFamily: "trivy", RuleID: "CVE-2026-" + uuid.NewString()[:8], Title: "t", Category: domain.CategorySCA, Severity: domain.SeverityHigh, ToolSeverity: "HIGH", RiskBand: domain.SeverityHigh,
				RiskScore: i % 1000, State: domain.StateOpen, FirstSeen: first, LastSeen: first, OccurrenceCount: 1, Version: 1, CreatedAt: first, UpdatedAt: first}
			if i%3 == 0 {
				r := first.Add(48 * time.Hour)
				res := domain.ResolutionFixed
				f.State, f.ResolvedAt, f.Resolution = domain.StateFixed, &r, &res
			}
			batch = append(batch, f)
		}
		if err := appStore.UpsertFindings(ctx, tn.ID, batch); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("seeded %d findings in %v", total, time.Since(seedStart))
	to := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 1)
	began := time.Now()
	r, err := appStore.ApplicationChanges(ctx, tn.ID, app.ID, to.AddDate(0, 0, -30), to)
	took := time.Since(began)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("10,000 findings: answered in %v (new %d, closed %d, open at end %d)", took, r.Counts.New, r.Counts.Closed, r.Counts.OpenAtEnd)
	if !raceEnabled && took > 15*time.Second {
		t.Errorf("took %v", took)
	}
	if len(r.New) > 1000 || len(r.OpenAtEnd) > 1000 || !r.OpenMore {
		t.Errorf("a list is cut at 1000 and says so: new %d open %d more=%v", len(r.New), len(r.OpenAtEnd), r.OpenMore)
	}
	if r.Counts.OpenAtEnd < 3000 {
		t.Errorf("the count is exact beyond the cut: %d", r.Counts.OpenAtEnd)
	}
}

// The ledger reads a finding's closings and returns from its events, not from the row as it is now (D125): a finding
// closed before the range and reopened inside it was not open at the start; one closed inside and reopened after it was
// not open at the end; a manual reopen is a return; moving from fixed to risk_accepted is one closing; open to
// under_investigation is not a return.
func TestApplicationChanges_ClosedAndReopened_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "cyc-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	day := func(n int) time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC).AddDate(0, 0, n) }
	mk := func(name string, state domain.FindingState, first time.Time, resolved *time.Time) *domain.Finding {
		f := &domain.Finding{ID: uuid.New(), TenantID: tn.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
			RuleScannerFamily: "trivy", RuleID: name, Title: name, Category: domain.CategorySCA, Severity: domain.SeverityHigh, ToolSeverity: "HIGH", RiskBand: domain.SeverityHigh,
			RiskScore: 600, State: state, FirstSeen: first, LastSeen: first, ResolvedAt: resolved, OccurrenceCount: 1, Version: 1, CreatedAt: first, UpdatedAt: first}
		if resolved != nil {
			r := domain.ResolutionRiskAccepted
			f.Resolution = &r
		}
		return f
	}
	riskAt := day(13)
	s1, s2 := mk("closed-before-back-inside", domain.StateOpen, day(-30), nil), mk("closed-inside-back-after", domain.StateOpen, day(-30), nil)
	s3, s4 := mk("new-closed-manual-reopen", domain.StateOpen, day(12), nil), mk("fixed-then-risk-accepted", domain.StateRiskAccepted, day(-30), &riskAt)
	s5 := mk("investigating", domain.StateUnderInvestigation, day(-30), nil)
	if err := appStore.UpsertFindings(ctx, tn.ID, []*domain.Finding{s1, s2, s3, s4, s5}); err != nil {
		t.Fatal(err)
	}
	ev := func(f *domain.Finding, at time.Time, typ, to string) *domain.FindingEvent {
		e := &domain.FindingEvent{ID: uuid.New(), FindingID: f.ID, At: at, Actor: "system:parser", Type: typ}
		if to != "" {
			e.To = json.RawMessage(`"` + to + `"`)
		}
		return e
	}
	if err := appStore.RecordFindingEvents(ctx, tn.ID, []*domain.FindingEvent{
		ev(s1, day(9), "closed_by_rescan", ""), ev(s1, day(15), "reactivated", ""),
		ev(s2, day(12), "closed_by_rescan", ""), ev(s2, day(22), "reactivated", ""),
		ev(s3, day(13), "state_changed", "fixed"), ev(s3, day(15), "state_changed", "open"),
		ev(s4, day(12), "state_changed", "fixed"), ev(s4, day(13), "state_changed", "risk_accepted"),
		ev(s5, day(14), "state_changed", "under_investigation"),
	}); err != nil {
		t.Fatal(err)
	}
	from, to := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	r, err := appStore.ApplicationChanges(ctx, tn.ID, app.ID, from, to)
	if err != nil {
		t.Fatal(err)
	}
	names := func(cs []store.FindingChange) map[string]bool {
		m := map[string]bool{}
		for _, c := range cs {
			m[c.RuleID] = true
		}
		return m
	}
	if c := r.Counts; c.New != 1 || c.Closed != 3 || c.Reopened != 2 || c.OpenAtStart != 3 || c.OpenAtEnd != 3 {
		t.Errorf("counts %+v, want new 1, closed 3, reopened 2, open at start 3 (not s1), open at end 3 (not s2, s4)", c)
	}
	if n := names(r.Closed); len(r.Closed) != 3 || !n["closed-inside-back-after"] || !n["new-closed-manual-reopen"] || !n["fixed-then-risk-accepted"] {
		t.Errorf("closed: %v (fixed then risk-accepted is one closing; the one closed before the range is not here)", n)
	}
	if n := names(r.Reopened); len(r.Reopened) != 2 || !n["closed-before-back-inside"] || !n["new-closed-manual-reopen"] {
		t.Errorf("reopened: %v (a manual reopen is a return; open to under_investigation is not)", n)
	}
	if n := names(r.OpenAtEnd); len(r.OpenAtEnd) != 3 || !n["closed-before-back-inside"] || !n["new-closed-manual-reopen"] || !n["investigating"] {
		t.Errorf("open at the end: %v", n)
	}
	// The day chart closes the same findings as the count says.
	closedByDay := 0
	for _, d := range r.Days {
		closedByDay += d.Closed
	}
	if closedByDay != r.Counts.Closed {
		t.Errorf("the chart closes %d findings, the count says %d", closedByDay, r.Counts.Closed)
	}
}
