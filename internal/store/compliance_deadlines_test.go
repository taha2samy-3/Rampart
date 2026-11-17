package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/compliance"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// compliance.Control.Breaks (one finding, in Go: the finding page uses it) and the SQL of ControlCounts and
// ControlDeadlines (every finding of a tenant: the compliance page uses it) must give the same answer. If they drift, the
// finding page says a finding breaks a control that the compliance page does not count, or the other way round.
func TestControlBreaks_GoAndSQLAgree_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "brk-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")

	soon, late := time.Now().Add(72*time.Hour), time.Now().Add(-48*time.Hour)
	type fx struct {
		name   string
		cwes   []int
		cat    domain.FindingCategory
		family string
		rule   string
		band   domain.Severity
		state  domain.FindingState
		due    *time.Time
	}
	cases := []fx{
		{"xss high", []int{79}, domain.CategorySAST, "semgrep", "xss", domain.SeverityHigh, domain.StateOpen, &soon},
		{"xss low", []int{79}, domain.CategorySAST, "semgrep", "xss", domain.SeverityLow, domain.StateOpen, &late},
		{"sqli critical", []int{89, 564}, domain.CategorySAST, "semgrep", "sqli", domain.SeverityCritical, domain.StateAffected, &late},
		{"secret", nil, domain.CategorySecret, "gitleaks", "aws-key", domain.SeverityHigh, domain.StateOpen, nil},
		{"sca medium", nil, domain.CategorySCA, "trivy", "CVE-2021-23337", domain.SeverityMedium, domain.StateUnderInvestigation, &soon},
		{"iac rule", nil, domain.CategoryIaC, "checkov", "CKV_K8S_20", domain.SeverityMedium, domain.StateOpen, &soon},
		{"iac other", nil, domain.CategoryIaC, "checkov", "CKV_AWS_1", domain.SeverityLow, domain.StateOpen, nil},
		{"fixed xss", []int{79}, domain.CategorySAST, "semgrep", "xss", domain.SeverityHigh, domain.StateFixed, &late}, // not open: counts for nothing
	}
	var fs []*domain.Finding
	for _, c := range cases {
		f := &domain.Finding{ID: uuid.New(), TenantID: tn.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
			RuleScannerFamily: c.family, RuleID: c.rule, Title: c.name, Category: c.cat, Severity: c.band, ToolSeverity: string(c.band), RiskBand: c.band, CWEs: c.cwes,
			State: c.state, SLADue: c.due, FirstSeen: time.Now(), LastSeen: time.Now(), OccurrenceCount: 1, Version: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()}
		fs = append(fs, f)
	}
	if err := appStore.UpsertFindings(ctx, tn.ID, fs); err != nil {
		t.Fatal(err)
	}

	controls := []compliance.Control{
		{ID: "by-cwe", CWEs: []int{79, 80}},
		{ID: "by-cwe-high", CWEs: []int{79, 89}, MinSeverity: "high"},
		{ID: "by-category", Categories: []string{"secret", "sca"}},
		{ID: "by-rule", Rules: []compliance.RuleMatch{{ScannerFamily: "checkov", RuleID: "CKV_K8S_20"}}},
		{ID: "by-rule-prefix", Rules: []compliance.RuleMatch{{ScannerFamily: "checkov", RuleID: "CKV_*"}}},
		{ID: "wrong-family", Rules: []compliance.RuleMatch{{ScannerFamily: "trivy", RuleID: "CKV_K8S_20"}}},
		{ID: "category-min-medium", Categories: []string{"iac"}, MinSeverity: "medium"},
		{ID: "nothing", CWEs: []int{1}},
		{ID: "manual", Manual: true},
	}
	var matches []store.ControlMatch
	for _, c := range controls {
		if c.Manual {
			continue
		}
		m := store.ControlMatch{ID: c.ID, CWEs: c.CWEs, Categories: c.Categories, MinSeverity: c.MinSeverity}
		for _, r := range c.Rules {
			m.Rules = append(m.Rules, store.RuleMatch{ScannerFamily: r.ScannerFamily, RuleID: r.RuleID})
		}
		matches = append(matches, m)
	}
	counts, err := appStore.ControlCounts(ctx, tn.ID, []uuid.UUID{app.ID}, matches)
	if err != nil {
		t.Fatal(err)
	}
	deadlines, err := appStore.ControlDeadlines(ctx, tn.ID, []uuid.UUID{app.ID}, matches)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range controls {
		var wantOpen, wantOverdue, wantNone int
		var wantEarliest *time.Time
		for i, f := range fs {
			if cases[i].state != domain.StateOpen && cases[i].state != domain.StateAffected && cases[i].state != domain.StateUnderInvestigation {
				continue
			}
			if !c.Breaks(compliance.FindingFacts{CWEs: cases[i].cwes, Category: string(cases[i].cat), ScannerFamily: cases[i].family, RuleID: cases[i].rule, Band: string(cases[i].band)}) {
				continue
			}
			wantOpen++
			if f.SLADue == nil {
				wantNone++
			}
			if f.SLADue != nil {
				if f.SLADue.Before(time.Now()) {
					wantOverdue++
				}
				if wantEarliest == nil || f.SLADue.Before(*wantEarliest) {
					wantEarliest = f.SLADue
				}
			}
		}
		sqlOpen := 0
		for _, n := range counts[c.ID].Open {
			sqlOpen += n
		}
		if sqlOpen != wantOpen {
			t.Errorf("%s: SQL counts %d open findings, Go says %d", c.ID, sqlOpen, wantOpen)
		}
		d := deadlines[c.ID]
		if d.NoDeadline != wantNone {
			t.Errorf("%s: %d findings with no deadline, want %d", c.ID, d.NoDeadline, wantNone)
		}
		if d.Open != wantOpen || d.Overdue != wantOverdue {
			t.Errorf("%s: deadlines open %d overdue %d, want %d and %d", c.ID, d.Open, d.Overdue, wantOpen, wantOverdue)
		}
		if (d.Earliest == nil) != (wantEarliest == nil) || (wantEarliest != nil && d.Earliest.Sub(*wantEarliest).Abs() > time.Second) {
			t.Errorf("%s: earliest due %v, want %v", c.ID, d.Earliest, wantEarliest)
		}
	}
	// A finding that bears on several controls is one finding in the totals of the framework.
	totals, err := appStore.DistinctFindings(ctx, tn.ID, []uuid.UUID{app.ID}, matches)
	if err != nil {
		t.Fatal(err)
	}
	wantTotal, wantLate, sum := 0, 0, 0
	for i, f := range fs {
		if cases[i].state != domain.StateOpen && cases[i].state != domain.StateAffected && cases[i].state != domain.StateUnderInvestigation {
			continue
		}
		hits := 0
		for _, c := range controls {
			if !c.Manual && c.Breaks(compliance.FindingFacts{CWEs: cases[i].cwes, Category: string(cases[i].cat), ScannerFamily: cases[i].family, RuleID: cases[i].rule, Band: string(cases[i].band)}) {
				hits++
			}
		}
		if hits > 0 {
			wantTotal++
			if f.SLADue != nil && f.SLADue.Before(time.Now()) {
				wantLate++
			}
		}
	}
	for _, d := range deadlines {
		sum += d.Open
	}
	if totals.Open != wantTotal || totals.Overdue != wantLate || sum <= totals.Open {
		t.Errorf("distinct findings %+v, want open %d overdue %d (and fewer than the %d counted per control)", totals, wantTotal, wantLate, sum)
	}
	// A control with nothing against it has no deadline, and the manual control is not counted at all.
	if d := deadlines["nothing"]; d.Open != 0 || d.Earliest != nil {
		t.Errorf("nothing: %+v", d)
	}
	if (compliance.Control{ID: "m", Manual: true, CWEs: []int{79}}).Breaks(compliance.FindingFacts{CWEs: []int{79}}) {
		t.Error("a manual control is broken by no finding")
	}
}
