package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/query"
	"rampart/internal/workflow"
)

func (h *uploadHarness) page(q, sort string) []query.FindingResponse {
	h.t.Helper()
	path := "/api/v1/findings?limit=100&sort=" + sort
	if q != "" {
		path += "&q=" + strings.ReplaceAll(q, " ", "%20")
	}
	code, body := h.call("GET", path, nil, nil)
	if code != http.StatusOK {
		h.t.Fatalf("GET %s: %d %s", path, code, body)
	}
	var out struct {
		Items []query.FindingResponse `json:"items"`
	}
	_ = json.Unmarshal(body, &out)
	return out.Items
}

// The score, band and SLA are stored when a finding is ingested, so the explorer can sort and filter on them in
// SQL (D28). They used to be computed only when a finding was read, and stayed 0, 'low' and NULL in the database.
func TestScoring_StoredAtIngest(t *testing.T) {
	h := newUploadHarness(t)
	ingestRules(t, h, map[string]string{"rule.crit": "9.8", "rule.high": "7.5", "rule.med": "5.0", "rule.low": "2.0"}, "main")
	ids := findingIDs(t, h)
	ctx := context.Background()

	stored := map[string]*domain.Finding{}
	for rule, id := range ids {
		f, _, err := h.store.GetFinding(ctx, h.tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		stored[rule] = f
		if f.RiskScore == 0 || f.SLADue == nil || f.SLAStart == nil {
			t.Fatalf("%s: nothing stored: score %d, sla due %v", rule, f.RiskScore, f.SLADue)
		}
	}
	// Order by score is order by severity, and the bands follow the score.
	inOrder := stored["rule.crit"].RiskScore > stored["rule.high"].RiskScore && stored["rule.high"].RiskScore > stored["rule.med"].RiskScore && stored["rule.med"].RiskScore > stored["rule.low"].RiskScore
	if !inOrder {
		t.Fatalf("scores out of order: %d %d %d %d", stored["rule.crit"].RiskScore, stored["rule.high"].RiskScore, stored["rule.med"].RiskScore, stored["rule.low"].RiskScore)
	}
	// The SLA follows the band and the application's criticality (docs/06 section 4), from the original start.
	app, err := h.store.GetApplication(ctx, h.tenant, stored["rule.crit"].ApplicationID)
	if err != nil {
		t.Fatal(err)
	}
	policy := domain.DefaultSLAPolicy()
	for rule, f := range stored {
		want := policy.Due(f.RiskBand, strings.ToLower(app.BusinessCriticality), *f.SLAStart, nil)
		if !f.SLADue.Equal(want) {
			t.Fatalf("%s: SLA due %v, want %v (band %s, criticality %s)", rule, f.SLADue, want, f.RiskBand, app.BusinessCriticality)
		}
	}
	if !stored["rule.crit"].SLADue.Before(*stored["rule.low"].SLADue) {
		t.Fatal("a critical finding must be due before a low one")
	}

	// The explorer sorts and filters on the stored values.
	items := h.page("", "-score")
	for i := 1; i < len(items); i++ {
		if items[i-1].Finding.RiskScore < items[i].Finding.RiskScore {
			t.Fatal("-score is not in descending order")
		}
	}
	if items[0].Finding.RuleID != "rule.crit" {
		t.Fatalf("the highest score is first, got %s", items[0].Finding.RuleID)
	}
	band := string(stored["rule.crit"].RiskBand)
	if got := h.page("risk:"+band, "-score"); len(got) == 0 || got[0].Finding.RuleID != "rule.crit" {
		t.Fatalf("risk:%s returned %d findings", band, len(got))
	}
	if got := h.page("score:>=1", "-score"); len(got) != 4 {
		t.Fatalf("score:>=1 returned %d, want 4", len(got))
	}
	if got := h.page("score:>=9999", "-score"); len(got) != 0 {
		t.Fatalf("score:>=9999 returned %d", len(got))
	}
	// The API reports the stored due date, not a recomputed one.
	for _, it := range items {
		if it.SLADueDate == nil || !it.SLADueDate.Equal(*stored[it.Finding.RuleID].SLADue) {
			t.Fatalf("%s: the API says due %v, stored %v", it.Finding.RuleID, it.SLADueDate, stored[it.Finding.RuleID].SLADue)
		}
		if it.Risk.TotalScore != stored[it.Finding.RuleID].RiskScore {
			t.Fatalf("%s: the API explains %d, stored %d: they must be the same number", it.Finding.RuleID, it.Risk.TotalScore, stored[it.Finding.RuleID].RiskScore)
		}
	}

	// A rescan of the same report changes no score and no due date (the clock does not move).
	ingestRules(t, h, map[string]string{"rule.crit": "9.8", "rule.high": "7.5", "rule.med": "5.0", "rule.low": "2.0"}, "main")
	for rule, id := range ids {
		f, _, _ := h.store.GetFinding(ctx, h.tenant, id)
		if f.RiskScore != stored[rule].RiskScore || !f.SLADue.Equal(*stored[rule].SLADue) {
			t.Fatalf("%s: a rescan moved the score or the due date", rule)
		}
	}

	// A severity override re-scores the finding and moves its due date.
	triager := h.tokenFor(auth.RoleTriager, "sara@acme.example")
	crit := ids["rule.crit"].String()
	if code, body := h.callAs(triager, "PATCH", "/api/v1/findings/"+crit, map[string]any{"severity": "low", "severityReason": "internal tool"}, nil); code != http.StatusOK {
		t.Fatalf("override: %d %s", code, body)
	}
	after, _, _ := h.store.GetFinding(ctx, h.tenant, ids["rule.crit"])
	if after.RiskScore >= stored["rule.crit"].RiskScore || !after.SLADue.After(*stored["rule.crit"].SLADue) {
		t.Fatalf("an override to low must lower the score and move the due date out: score %d -> %d", stored["rule.crit"].RiskScore, after.RiskScore)
	}
}

// KEV and EPSS change a finding's score, band and due date when the feeds change (D28), and a KEV due date
// earlier than the matrix wins (docs/06 section 4).
func TestScoring_RescoreAfterTheFeedsChange(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	seedFindings(t, ctx, h.store, h.tenant, 0)
	app, _ := h.store.LookupApplication(ctx, h.tenant, "shop")
	asset, _ := h.store.LookupAsset(ctx, h.tenant, domain.AssetRepository, "github.com/acme/shop")
	cve := "CVE-2077-" + strings.ToUpper(uuid.NewString()[:6])
	now := time.Now().UTC()
	f := &domain.Finding{ID: uuid.New(), TenantID: h.tenant, FindingKey: "k-kev", DedupScope: "x", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
		RuleScannerFamily: "trivy", RuleID: cve, Title: "Vulnerable dependency", Category: domain.CategorySCA, Severity: domain.SeverityMedium, ToolSeverity: "medium",
		VulnerabilityID: &cve, State: domain.StateOpen, FirstSeen: now, LastSeen: now, OccurrenceCount: 1, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := h.scorer.ScoreBatch(ctx, h.tenant, app.ID, []*domain.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.UpsertFindings(ctx, h.tenant, []*domain.Finding{f}); err != nil {
		t.Fatal(err)
	}
	before, _, _ := h.store.GetFinding(ctx, h.tenant, f.ID)
	if before.KEV || before.RiskBand == domain.SeverityCritical {
		t.Fatalf("before the feeds: kev %v band %s", before.KEV, before.RiskBand)
	}

	// The vulnerability becomes known exploited, with a CISA due date in two days, and very likely to be exploited.
	due := now.Add(48 * time.Hour).Format("2006-01-02")
	kev := `{"vulnerabilities":[{"cveID":"` + cve + `","vulnerabilityName":"x","dateAdded":"` + now.Format("2006-01-02") + `","dueDate":"` + due + `"}]}`
	if _, err := h.syncer.SyncKEV(ctx, strings.NewReader(kev)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.syncer.SyncEPSS(ctx, strings.NewReader("cve,epss,percentile\n"+cve+",0.9,0.99\n")); err != nil {
		t.Fatal(err)
	}
	n, err := h.scorer.Rescore(ctx, h.tenant)
	if err != nil || n != 1 {
		t.Fatalf("rescore: %d %v", n, err)
	}
	after, _, _ := h.store.GetFinding(ctx, h.tenant, f.ID)
	if !after.KEV || after.EPSSBucket != "high" || after.RiskScore <= before.RiskScore+300-1 {
		t.Fatalf("after the feeds: kev %v epss %q score %d -> %d", after.KEV, after.EPSSBucket, before.RiskScore, after.RiskScore)
	}
	kevDue, _ := time.Parse("2006-01-02", due)
	if after.SLADue == nil || !after.SLADue.Equal(kevDue) {
		t.Fatalf("the CISA due date (%s) is earlier than the matrix and must win, got %v", due, after.SLADue)
	}
	// The explorer can now find it by what the feeds said.
	if got := h.page("kev:true", "-score"); len(got) != 1 {
		t.Fatalf("kev:true returned %d", len(got))
	}
	if n, err := h.scorer.Rescore(ctx, h.tenant); err != nil || n != 0 {
		t.Fatalf("a second rescore changes nothing: %d %v", n, err)
	}
	// Re-scoring is not a decision: the version an analyst holds stays valid.
	if after.Version != before.Version {
		t.Fatalf("version %d -> %d: a re-score must not bump it", before.Version, after.Version)
	}
}

func TestSLA_BreachPauseAndRestart(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	ingestRules(t, h, map[string]string{"rule.a": "9.8", "rule.b": "7.5"}, "main")
	ids := findingIDs(t, h)
	a, b := ids["rule.a"], ids["rule.b"]
	boss := h.tokenFor(auth.RoleAdmin, "boss@acme.example")
	viewer := h.tokenFor(auth.RoleViewer, "viewer@acme.example")

	// Two findings are overdue: their clock started 500 days ago, so the due date the policy gives is in the past.
	startedAt := time.Now().UTC().Add(-500 * 24 * time.Hour)
	policy := domain.DefaultSLAPolicy()
	var dueBefore time.Time
	for _, id := range []uuid.UUID{a, b} {
		f, _, _ := h.store.GetFinding(ctx, h.tenant, id)
		start := startedAt
		app, _ := h.store.GetApplication(ctx, h.tenant, f.ApplicationID)
		due := policy.Due(f.RiskBand, strings.ToLower(app.BusinessCriticality), start, nil)
		f.SLAStart, f.SLADue = &start, &due
		if id == a {
			dueBefore = due
		}
		if err := h.store.UpdateFindingRisk(ctx, h.tenant, []*domain.Finding{f}); err != nil {
			t.Fatal(err)
		}
	}
	// A risk acceptance stops the clock of a.
	code, body := h.callAs(boss, "POST", "/api/v1/risk-acceptances", map[string]any{"findingIds": []string{a.String()}, "justification": "behind the VPN", "expiresAt": days(30)}, nil)
	if code != http.StatusCreated {
		t.Fatalf("accept: %d %s", code, body)
	}
	acc := decodeOutcome(t, body).Acceptance.ID
	fa, _, _ := h.store.GetFinding(ctx, h.tenant, a)
	if fa.SLAPausedAt == nil {
		t.Fatal("accepting a risk must pause the SLA clock")
	}

	// The sweep marks b, not the paused a, and only once.
	n, err := h.scorer.MarkBreaches(ctx, h.tenant, time.Now().UTC())
	if err != nil || n != 1 {
		t.Fatalf("breaches: %d %v", n, err)
	}
	if n, _ := h.scorer.MarkBreaches(ctx, h.tenant, time.Now().UTC()); n != 0 {
		t.Fatalf("a breach is marked once, got %d more", n)
	}
	fb, _, _ := h.store.GetFinding(ctx, h.tenant, b)
	fa, _, _ = h.store.GetFinding(ctx, h.tenant, a)
	if fb.SLABreachedAt == nil || fa.SLABreachedAt != nil {
		t.Fatalf("breached: b %v, a %v (a is paused)", fb.SLABreachedAt, fa.SLABreachedAt)
	}
	_, ev := h.callAs(viewer, "GET", "/api/v1/findings/"+b.String()+"/events", nil, nil)
	if !strings.Contains(string(ev), "sla_breached") {
		t.Fatalf("the timeline must say it breached: %s", ev)
	}
	if got := h.page("sla:breached", "-score"); len(got) != 1 || got[0].Finding.ID != b {
		t.Fatalf("sla:breached returned %d findings", len(got))
	}

	// Revoking resumes the clock: the time spent accepted is not counted, so the due date moves out by it.
	pausedFor := time.Since(*fa.SLAPausedAt)
	if code, body := h.callAs(boss, "POST", "/api/v1/risk-acceptances/"+acc.String()+"/revoke", map[string]any{"note": "no longer true"}, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, body)
	}
	fa, _, _ = h.store.GetFinding(ctx, h.tenant, a)
	if fa.SLAPausedAt != nil || fa.SLADue == nil {
		t.Fatalf("after revoke: paused %v due %v", fa.SLAPausedAt, fa.SLADue)
	}
	moved := fa.SLADue.Sub(dueBefore)
	if moved < pausedFor || moved > pausedFor+time.Minute {
		t.Fatalf("the due date moved by %v, the time spent paused was about %v", moved, pausedFor)
	}

	// restartSlaOnExpiry starts the clock over instead.
	code, body = h.callAs(boss, "POST", "/api/v1/risk-acceptances", map[string]any{"findingIds": []string{a.String()}, "justification": "again", "expiresAt": days(10), "restartSlaOnExpiry": true}, nil)
	if code != http.StatusCreated {
		t.Fatalf("accept again: %d %s", code, body)
	}
	if n, err := workflow.New(h.store).ExpireDue(ctx, h.tenant, time.Now().Add(11*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("expiry: %d %v", n, err)
	}
	// The service in this test has no scorer, so only the restart marks are checked here.
	fa, _, _ = h.store.GetFinding(ctx, h.tenant, a)
	if fa.SLAPausedAt != nil || fa.SLABreachedAt != nil || fa.SLAStart == nil || fa.SLAStart.Before(time.Now().UTC().Add(-time.Hour)) {
		t.Fatalf("restart: paused %v breached %v start %v", fa.SLAPausedAt, fa.SLABreachedAt, fa.SLAStart)
	}
}

// A finding that comes back after it was fixed gets a new clock (restartOnReactivation, docs/06 section 4).
func TestSLA_ReactivationRestartsTheClock(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	ingestRules(t, h, map[string]string{"rule.keep": "9.8", "rule.back": "7.5"}, "main")
	ids := findingIDs(t, h)
	back := ids["rule.back"]
	first, _, _ := h.store.GetFinding(ctx, h.tenant, back)

	// It goes overdue, is marked breached, and is then fixed by a rescan that no longer reports it.
	past := time.Now().UTC().Add(-72 * time.Hour)
	f := *first
	f.SLADue = &past
	_ = h.store.UpdateFindingRisk(ctx, h.tenant, []*domain.Finding{&f})
	if _, err := h.scorer.MarkBreaches(ctx, h.tenant, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	ingestRules(t, h, map[string]string{"rule.keep": "9.8"}, "main")
	if g, _, _ := h.store.GetFinding(ctx, h.tenant, back); g.State != domain.StateFixed {
		t.Fatalf("expected fixed, got %s", g.State)
	}

	// It is reported again: a new clock.
	ingestRules(t, h, map[string]string{"rule.keep": "9.8", "rule.back": "7.5"}, "main")
	g, _, _ := h.store.GetFinding(ctx, h.tenant, back)
	if g.State != domain.StateOpen || g.SLABreachedAt != nil || g.SLAStart == nil || !g.SLAStart.After(first.SLAStart.Add(time.Second)) {
		t.Fatalf("reactivated: state %s breached %v start %v (was %v)", g.State, g.SLABreachedAt, g.SLAStart, first.SLAStart)
	}
	if g.SLADue == nil || !g.SLADue.After(time.Now()) {
		t.Fatalf("a restarted clock has a due date in the future, got %v", g.SLADue)
	}
}
