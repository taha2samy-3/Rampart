package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/store"
)

func TestFinalizers_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "fin-" + uuid.NewString()[:8], DisplayName: "F", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	managed := func(slug string) string {
		var m string
		if err := sys.Pool().QueryRow(ctx, `SELECT managed_by FROM application WHERE tenant_id = $1 AND slug = $2`, tn.ID, slug).Scan(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	// An application from a resource is marked; deleting the resource lets it go and keeps it; applying again takes it back.
	app := domain.Application{ID: uuid.New(), TenantID: tn.ID, Slug: "shop", Name: "Shop", BusinessCriticality: "high", Lifecycle: "production", CreatedAt: time.Now().UTC()}
	if err := sys.SaveApplication(ctx, app); err != nil {
		t.Fatal(err)
	}
	if got := managed("shop"); got != "crd" {
		t.Fatalf("made by a resource: %s", got)
	}
	if err := sys.OrphanApplication(ctx, tn.ID, "shop"); err != nil {
		t.Fatal(err)
	}
	if got := managed("shop"); got != "none" {
		t.Fatalf("after the resource is deleted: %s", got)
	}
	if err := sys.OrphanApplication(ctx, tn.ID, "shop"); err != nil { // a retried finalizer is harmless
		t.Fatal(err)
	}
	if err := sys.SaveApplication(ctx, app); err != nil {
		t.Fatal(err)
	}
	if got := managed("shop"); got != "crd" {
		t.Fatalf("the resource came back: %s", got)
	}
	// One made in the UI is not taken over by a resource of the same name, and deleting that resource leaves it alone.
	ui := domain.Application{ID: uuid.New(), TenantID: tn.ID, Slug: "ui-app", Name: "UI", BusinessCriticality: "low", Lifecycle: "production", CreatedAt: time.Now().UTC()}
	if err := appStore.CreateApplication(ctx, &ui); err != nil {
		t.Fatal(err)
	}
	// CreateApplication is the ingest path and makes an unmanaged row (D55); nothing creates applications in the UI
	// yet, so the row is marked as the UI's by hand.
	if _, err := sys.Pool().Exec(ctx, `UPDATE application SET managed_by = 'ui' WHERE tenant_id = $1 AND slug = 'ui-app'`, tn.ID); err != nil {
		t.Fatal(err)
	}
	if err := sys.SaveApplication(ctx, ui); err != nil {
		t.Fatal(err)
	}
	if err := sys.OrphanApplication(ctx, tn.ID, "ui-app"); err != nil {
		t.Fatal(err)
	}
	if got := managed("ui-app"); got != "ui" {
		t.Fatalf("an application of the UI: %s", got)
	}

	// A scan source: deleting its resource disables it, revokes its tokens, removes its secret material, keeps the row.
	id, err := sys.SaveScanSource(ctx, tn.ID, "ci_x", "semgrep", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := sys.SaveScanSource(ctx, tn.ID, "ciAx", "semgrep", nil) // '_' in a name must not match a neighbour
	_ = other
	_, rec, _ := auth.GenerateToken(tn.ID, auth.RoleTriager, "ci", []string{"*"}, time.Hour)
	if err := appStore.SaveToken(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := sys.Pool().Exec(ctx, `UPDATE api_token SET scan_source_id = $2 WHERE id = $1`, rec.ID, id); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"scansource:ci_x:token", "scansource:ciAx:token"} {
		if err := sys.SaveSecretMaterial(ctx, tn.ID, key, []byte("ct")); err != nil {
			t.Fatal(err)
		}
	}
	n, err := sys.DisableScanSource(ctx, tn.ID, "ci_x")
	if err != nil || n != 1 {
		t.Fatalf("disable: %d %v", n, err)
	}
	var revoked bool
	_ = sys.Pool().QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM api_token WHERE id = $1`, rec.ID).Scan(&revoked)
	if !revoked {
		t.Fatal("the token of the source must be revoked")
	}
	if _, err := sys.GetSecretMaterial(ctx, tn.ID, "scansource:ci_x:token"); err == nil {
		t.Fatal("the secret material of the source must be removed")
	}
	if _, err := sys.GetSecretMaterial(ctx, tn.ID, "scansource:ciAx:token"); err != nil {
		t.Fatalf("a source with a similar name lost its secret: %v", err)
	}
	if _, err := appStore.EnsureScanSource(ctx, tn.ID, "ci_x"); !errors.Is(err, store.ErrSourceDisabled) {
		t.Fatalf("an upload to a disabled source: %v", err)
	}
	if _, err := appStore.EnsureScanSource(ctx, tn.ID, "ciAx"); err != nil {
		t.Fatalf("a source with a similar name was disabled: %v", err)
	}
	if n, err := sys.DisableScanSource(ctx, tn.ID, "ci_x"); err != nil || n != 0 { // again: nothing more to revoke
		t.Fatalf("second disable: %d %v", n, err)
	}
	if n, err := sys.DisableScanSource(ctx, tn.ID, "never-existed"); err != nil || n != 0 {
		t.Fatalf("a source that was never reconciled: %d %v", n, err)
	}
	if _, err := sys.SaveScanSource(ctx, tn.ID, "ci_x", "semgrep", nil); err != nil { // the resource returns
		t.Fatal(err)
	}
	if _, err := appStore.EnsureScanSource(ctx, tn.ID, "ci_x"); err != nil {
		t.Fatalf("applying the resource again must enable the source: %v", err)
	}

	// An SLA policy: deleting it asks for a recompute, and what is left (the built-in policy) applies.
	if err := sys.SaveSLAPolicy(ctx, tn.ID, apply.PolicyObject{Namespace: "ns", Name: "default", Spec: []byte(`{"matrix":{"critical":{"critical":1}}}`)}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := sys.GetSLAPolicySpec(ctx, tn.ID); !ok {
		t.Fatal("policy not stored")
	}
	if err := sys.ClearSLARecompute(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	if err := sys.DeleteSLAPolicy(ctx, tn.ID, "ns", "default"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := sys.GetSLAPolicySpec(ctx, tn.ID); ok {
		t.Fatal("a deleted policy must not stay in force")
	}
	need, _ := sys.TenantsNeedingSLARecompute(ctx)
	found := false
	for _, x := range need {
		found = found || x == tn.ID
	}
	if !found {
		t.Fatal("deleting a policy must ask for a recompute")
	}

	// The tenant has data now; purging removes the tenant and what belongs to it.
	has, err := sys.TenantHasData(ctx, tn.ID)
	if err != nil || !has {
		t.Fatalf("has data: %v %v", has, err)
	}
	empty := &domain.Tenant{ID: uuid.New(), Slug: "emp-" + uuid.NewString()[:8], DisplayName: "E", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, empty); err != nil {
		t.Fatal(err)
	}
	if has, _ := sys.TenantHasData(ctx, empty.ID); has {
		t.Fatal("an empty tenant has no data")
	}
	// An audit row must not stop the purge of its tenant.
	if err := appStore.RecordAudit(ctx, auth.AuditEvent{TenantID: tn.ID, Actor: "a", Action: "x", ResourceType: "t", ResourceID: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := sys.PurgeTenant(ctx, tn.ID); err != nil {
		t.Fatalf("purge: %v", err)
	}
	var left int
	_ = sys.Pool().QueryRow(ctx, `SELECT (SELECT count(*) FROM application WHERE tenant_id = $1) + (SELECT count(*) FROM scan_source WHERE tenant_id = $1)
		+ (SELECT count(*) FROM audit_event WHERE tenant_id = $1) + (SELECT count(*) FROM tenant WHERE id = $1)`, tn.ID).Scan(&left)
	if left != 0 {
		t.Fatalf("after the purge %d rows remain", left)
	}
}
