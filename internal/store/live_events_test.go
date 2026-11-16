package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// D91: writers record live events through statement triggers, one row per application per statement, and a
// tenant replays only its own rows.
func TestLiveEvents_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "lv-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	other := &domain.Tenant{ID: uuid.New(), Slug: "lv-" + uuid.NewString()[:8], DisplayName: "O", CreatedAt: time.Now().UTC()}
	for _, x := range []*domain.Tenant{tn, other} {
		if err := sys.CreateTenant(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	start, err := sys.MaxLiveEventID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	asset, _ := appStore.LookupAsset(ctx, tn.ID, domain.AssetRepository, "github.com/acme/shop")
	now := time.Now().UTC()
	var batch []*domain.Finding
	for i := 0; i < 50; i++ {
		batch = append(batch, &domain.Finding{ID: uuid.New(), TenantID: tn.ID, FindingKey: uuid.NewString(), DedupScope: "shop:main", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
			RuleScannerFamily: "semgrep", RuleID: "r", Title: "t", Category: domain.CategorySAST, Severity: domain.SeverityLow, ToolSeverity: "low",
			State: domain.StateOpen, FirstSeen: now, LastSeen: now, OccurrenceCount: 1, Version: 1, CreatedAt: now, UpdatedAt: now})
	}
	before, _ := sys.MaxLiveEventID(ctx)
	if err := appStore.UpsertFindings(ctx, tn.ID, batch); err != nil {
		t.Fatal(err)
	}
	rows, err := sys.ListLiveEvents(ctx, before, 1000)
	if err != nil {
		t.Fatal(err)
	}
	findings := 0
	for _, e := range rows {
		if e.TenantID == tn.ID && e.Topic == "findings" {
			findings++
			if e.ApplicationID == nil || *e.ApplicationID != app.ID {
				t.Fatalf("the row names the application: %+v", e)
			}
		}
	}
	if findings == 0 || findings > 2 {
		t.Fatalf("50 findings in one statement are one row per application, not 50: %d", findings)
	}

	mine, err := appStore.ListTenantLiveEvents(ctx, tn.ID, start, 1000)
	if err != nil || len(mine) == 0 {
		t.Fatalf("the tenant replays its rows: %d %v", len(mine), err)
	}
	if theirs, _ := appStore.ListTenantLiveEvents(ctx, other.ID, start, 1000); len(theirs) != 0 {
		for _, e := range theirs {
			if e.TenantID != other.ID {
				t.Fatalf("row-level security: another tenant reads %+v", e)
			}
		}
	}
	if n, err := sys.PruneLiveEvents(ctx, time.Now().Add(time.Hour)); err != nil || n == 0 {
		t.Fatalf("prune: %d %v", n, err)
	}
}
