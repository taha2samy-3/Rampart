package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// D101: the application detail counts open findings by category and band, and says what each scanner family
// produced, from PostgreSQL as the application role.
func TestApplicationDetailCoverageData_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "cv-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 20) // semgrep, sast; every fifth one fixed
	app, err := appStore.LookupApplication(ctx, tn.ID, "shop")
	if err != nil || app == nil {
		t.Fatalf("app: %v", err)
	}
	d, err := appStore.ApplicationDetail(ctx, tn.ID, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	open := 0
	for _, n := range d.OpenByCategory["sast"] {
		open += n
	}
	if open != 16 || len(d.OpenByCategory) != 1 {
		t.Fatalf("want 16 open sast findings and no other category, got %v", d.OpenByCategory)
	}
	if cats := d.FamilyCategories["semgrep"]; len(cats) != 1 || cats[0] != "sast" {
		t.Fatalf("semgrep produced sast: %v", d.FamilyCategories)
	}
}
