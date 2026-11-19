package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// A person changes what the score knows about an application; one an Application resource manages is refused; a change
// that moves the score flags the application for a re-score, one that does not (the lifecycle) does not.
func TestUpdateApplicationContext_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "ctx-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, appStore, tn.ID, 0)
	app, _ := appStore.LookupApplication(ctx, tn.ID, "shop")
	flagged := func() bool {
		var f bool
		_ = sys.Pool().QueryRow(ctx, `SELECT rescore_needed FROM application WHERE id = $1`, app.ID).Scan(&f)
		return f
	}
	reset := func(managedBy string) {
		if _, err := sys.Pool().Exec(ctx, `UPDATE application SET managed_by = $2, rescore_needed = FALSE WHERE id = $1`, app.ID, managedBy); err != nil {
			t.Fatal(err)
		}
	}
	str := func(s string) *string { return &s }
	list := func(v ...string) *[]string { return &v }
	yes := true

	reset("none")
	before, _ := appStore.GetApplication(ctx, tn.ID, app.ID)
	got, err := appStore.UpdateApplicationContext(ctx, tn.ID, app.ID, domain.ApplicationContextUpdate{
		BusinessCriticality: str("critical"), InternetFacing: &yes, DataClassification: list("pci", "pii"), CompensatingControls: list("waf"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.BusinessCriticality != "critical" || !got.InternetFacing || !slices.Equal(got.DataClassification, []string{"pci", "pii"}) || !slices.Equal(got.CompensatingControls, []string{"waf"}) {
		t.Errorf("the change was not stored: %+v", got)
	}
	if got.Version != before.Version+1 {
		t.Errorf("version %d, want %d", got.Version, before.Version+1)
	}
	if !flagged() {
		t.Error("a change that moves the score must flag the application for a re-score")
	}

	reset("none")
	if _, err := appStore.UpdateApplicationContext(ctx, tn.ID, app.ID, domain.ApplicationContextUpdate{Lifecycle: str("development")}); err != nil {
		t.Fatal(err)
	}
	if flagged() {
		t.Error("the lifecycle does not move the score: no re-score")
	}
	if _, err := appStore.UpdateApplicationContext(ctx, tn.ID, app.ID, domain.ApplicationContextUpdate{InternetFacing: &yes}); err != nil {
		t.Fatal(err)
	}
	if flagged() {
		t.Error("the same value again does not move the score")
	}

	reset("crd")
	if _, err := appStore.UpdateApplicationContext(ctx, tn.ID, app.ID, domain.ApplicationContextUpdate{BusinessCriticality: str("low")}); !errors.Is(err, store.ErrManagedByResource) {
		t.Errorf("an application a resource manages must be refused: %v", err)
	}
	if now, _ := appStore.GetApplication(ctx, tn.ID, app.ID); now.BusinessCriticality != "critical" {
		t.Errorf("a refused change must change nothing: %q", now.BusinessCriticality)
	}

	reset("none")
	if _, err := appStore.UpdateApplicationContext(ctx, uuid.New(), app.ID, domain.ApplicationContextUpdate{Lifecycle: str("production")}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant's application is not found: %v", err)
	}
}
