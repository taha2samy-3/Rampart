package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// The application page's chart: open findings per day and per band, a fixed finding leaving the count the day after.
func TestAppBandTrend_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "tr-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	now := time.Now().UTC()
	mk := func(band domain.Severity, first time.Time, resolved *time.Time) *domain.Finding {
		return &domain.Finding{ID: uuid.New(), TenantID: tn.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
			RuleScannerFamily: "semgrep", RuleID: "r", Title: "t", Category: domain.CategorySAST, Severity: band, ToolSeverity: string(band), RiskBand: band,
			State: domain.StateOpen, FirstSeen: first, LastSeen: now, ResolvedAt: resolved, OccurrenceCount: 1, Version: 1, CreatedAt: first, UpdatedAt: now}
	}
	fixedAt := now.Add(-72 * time.Hour)
	if err := appStore.UpsertFindings(ctx, tn.ID, []*domain.Finding{
		mk(domain.SeverityCritical, now.Add(-10*24*time.Hour), nil),
		mk(domain.SeverityHigh, now.Add(-10*24*time.Hour), &fixedAt),
	}); err != nil {
		t.Fatal(err)
	}
	pts, err := appStore.AppBandTrend(ctx, tn.ID, app.ID, 30)
	if err != nil || len(pts) != 30 {
		t.Fatalf("30 days: %d %v", len(pts), err)
	}
	first, mid, last := pts[0], pts[len(pts)-6], pts[len(pts)-1]
	if first.Bands["critical"] != 0 || mid.Bands["critical"] != 1 || mid.Bands["high"] != 1 || last.Bands["critical"] != 1 || last.Bands["high"] != 0 {
		t.Fatalf("first %v, five days ago %v, today %v", first.Bands, mid.Bands, last.Bands)
	}
	if pts[len(pts)-11].New != 2 {
		t.Fatalf("two findings first seen ten days ago: %+v", pts[len(pts)-11])
	}
	aging, err := appStore.AppAging(ctx, tn.ID, app.ID)
	if err != nil || aging.Under30 != 2 {
		// the fixed one keeps state open in this fixture; both are under 30 days old
		t.Fatalf("aging: %+v %v", aging, err)
	}
}
