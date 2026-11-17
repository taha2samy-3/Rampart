package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// Tests Dependency-Track synchronization and portfolio discovery on real PostgreSQL with tenant RLS (Milestone 3.4).
func TestDTrackSync_PostgresScenarios(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)

	tenantA := newTenant(t, ctx, sys, "dtrack-tenant-a")
	tenantB := newTenant(t, ctx, sys, "dtrack-tenant-b")

	srcA, err := sys.SaveScanSource(ctx, tenantA, "dtrack-source-a", "dependency-track", nil)
	if err != nil {
		t.Fatalf("saving scan source A: %v", err)
	}
	srcB, err := sys.SaveScanSource(ctx, tenantB, "dtrack-source-b", "dependency-track", nil)
	if err != nil {
		t.Fatalf("saving scan source B: %v", err)
	}

	projectUUID := "dtrack-proj-12345"

	// 1. Initial enqueue for Tenant A starts sync
	shouldStartA1, err := app.EnqueueDTrackSync(ctx, tenantA, srcA, projectUUID)
	if err != nil || !shouldStartA1 {
		t.Fatalf("initial enqueue should start sync: %t, err=%v", shouldStartA1, err)
	}

	// 2. Second event during running sync marks dirty and does not start second sync
	shouldStartA2, err := app.EnqueueDTrackSync(ctx, tenantA, srcA, projectUUID)
	if err != nil || shouldStartA2 {
		t.Fatalf("concurrent event should debounce (not start): %t, err=%v", shouldStartA2, err)
	}

	// 3. Tenant B with same project UUID starts independently (tenant RLS isolation)
	shouldStartB, err := app.EnqueueDTrackSync(ctx, tenantB, srcB, projectUUID)
	if err != nil || !shouldStartB {
		t.Fatalf("tenant B enqueue should start independently: %t, err=%v", shouldStartB, err)
	}

	// 4. Complete first sync on Tenant A: dirty flag was set, so it triggers trailing pass
	hasTrailingA1, err := app.CompleteDTrackSync(ctx, tenantA, projectUUID, nil)
	if err != nil || !hasTrailingA1 {
		t.Fatalf("completion with dirty flag should indicate trailing sync: %t, err=%v", hasTrailingA1, err)
	}

	// 5. Complete second sync on Tenant A: dirty was cleared, transitions to idle
	hasTrailingA2, err := app.CompleteDTrackSync(ctx, tenantA, projectUUID, nil)
	if err != nil || hasTrailingA2 {
		t.Fatalf("second completion should not have trailing sync: %t, err=%v", hasTrailingA2, err)
	}

	// 6. Verify Tenant A record state is idle
	recA, err := app.GetDTrackSync(ctx, tenantA, projectUUID)
	if err != nil {
		t.Fatalf("fetching tenant A sync record: %v", err)
	}
	if recA.State != domain.DTrackSyncStateIdle {
		t.Errorf("tenant A state = %v, want idle", recA.State)
	}

	// 7. Verify Tenant B is still in syncing state (unaffected by Tenant A)
	recB, err := app.GetDTrackSync(ctx, tenantB, projectUUID)
	if err != nil {
		t.Fatalf("fetching tenant B sync record: %v", err)
	}
	if recB.State != domain.DTrackSyncStateSyncing {
		t.Errorf("tenant B state = %v, want syncing", recB.State)
	}
}

func TestDTrackProject_MappingAndUnmappedScenarios(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)

	tenantA := newTenant(t, ctx, sys, "dtrack-map-a")
	tenantB := newTenant(t, ctx, sys, "dtrack-map-b")

	srcA, err := sys.SaveScanSource(ctx, tenantA, "dtrack-source-a", "dependency-track", nil)
	if err != nil {
		t.Fatalf("saving scan source A: %v", err)
	}
	srcB, err := sys.SaveScanSource(ctx, tenantB, "dtrack-source-b", "dependency-track", nil)
	if err != nil {
		t.Fatalf("saving scan source B: %v", err)
	}

	appID := uuid.New()
	appRec := domain.Application{ID: appID, TenantID: tenantA, Slug: "payment-gateway", Name: "Payment Gateway"}
	if err := sys.SaveApplication(ctx, appRec); err != nil {
		t.Fatalf("saving application: %v", err)
	}

	now := time.Now().UTC()

	// 1. Insert mapped project for Tenant A
	mappedProj := domain.DTrackProjectRecord{
		TenantID:      tenantA,
		SourceID:      srcA,
		ProjectUUID:   "p-mapped-1",
		Name:          "payment-service",
		Version:       "1.2.0",
		Active:        true,
		LastBomImport: &now,
		ApplicationID: &appID,
		MappingRule:   "property:rampart.application",
	}
	if err := app.UpsertDTrackProject(ctx, mappedProj); err != nil {
		t.Fatalf("upserting mapped project: %v", err)
	}

	// 2. Insert unmapped project for Tenant A
	unmappedProj := domain.DTrackProjectRecord{
		TenantID:       tenantA,
		SourceID:       srcA,
		ProjectUUID:    "p-unmapped-2",
		Name:           "orphan-service",
		Version:        "0.1.0",
		Active:         true,
		LastBomImport:  &now,
		ApplicationID:  nil,
		UnmappedReason: "no matching rule found",
	}
	if err := app.UpsertDTrackProject(ctx, unmappedProj); err != nil {
		t.Fatalf("upserting unmapped project: %v", err)
	}

	// 3. ListUnmappedDTrackProjects on Tenant A should return exactly the unmapped project
	unmappedA, err := app.ListUnmappedDTrackProjects(ctx, tenantA, srcA)
	if err != nil {
		t.Fatalf("listing unmapped projects for tenant A: %v", err)
	}
	if len(unmappedA) != 1 || unmappedA[0].ProjectUUID != "p-unmapped-2" {
		t.Fatalf("expected 1 unmapped project p-unmapped-2, got %+v", unmappedA)
	}
	if unmappedA[0].UnmappedReason != "no matching rule found" {
		t.Errorf("unmapped reason = %q", unmappedA[0].UnmappedReason)
	}

	// 4. Cross-tenant isolation: Tenant B querying its source sees 0 projects
	unmappedB, err := app.ListUnmappedDTrackProjects(ctx, tenantB, srcB)
	if err != nil {
		t.Fatalf("listing unmapped projects for tenant B: %v", err)
	}
	if len(unmappedB) != 0 {
		t.Fatalf("tenant B should see 0 unmapped projects, got %d", len(unmappedB))
	}
}

// The mapping of a Dependency-Track project, on PostgreSQL: a person's mapping is read back and survives the rules, a
// project mapped by a rule can be mapped again, and the mapped and unmapped lists are each other's complement.
func TestDTrackProjectMapping_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	app, sys := setupStores(t, ctx)
	tenant := newTenant(t, ctx, sys, "dtrack-map-"+uuid.NewString()[:6])
	other := newTenant(t, ctx, sys, "dtrack-map-other-"+uuid.NewString()[:6])
	src, err := sys.SaveScanSource(ctx, tenant, "dt", "dependency-track", nil)
	if err != nil {
		t.Fatal(err)
	}
	mkApp := func(slug string) uuid.UUID {
		a := &domain.Application{ID: uuid.New(), TenantID: tenant, Slug: slug, Name: slug, BusinessCriticality: "medium", Lifecycle: "production", CreatedAt: time.Now().UTC()}
		if err := app.CreateApplication(ctx, a); err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	demo, own := mkApp("demo"), mkApp("flare")

	rec := func(uuidStr, name string, appID *uuid.UUID, rule, reason string) domain.DTrackProjectRecord {
		return domain.DTrackProjectRecord{TenantID: tenant, SourceID: src, ProjectUUID: uuidStr, Name: name, Version: "1", Active: true,
			ApplicationID: appID, MappingRule: rule, UnmappedReason: reason}
	}
	for _, r := range []domain.DTrackProjectRecord{
		rec("p-default", "flare-reminders", &demo, "defaultApplication", ""), // the default rule took it
		rec("p-prop", "payments", &demo, "property:rampart.application", ""),
		rec("p-none", "orphan", nil, "", "no matching rule found for project orphan"),
	} {
		if err := app.UpsertDTrackProject(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	got, err := app.GetDTrackProject(ctx, tenant, "p-default")
	if err != nil || got == nil || got.MappingRule != "defaultApplication" || got.ApplicationID == nil || *got.ApplicationID != demo || got.SourceID != src {
		t.Fatalf("GetDTrackProject: %+v %v", got, err)
	}
	if none, err := app.GetDTrackProject(ctx, tenant, "p-missing"); err != nil || none != nil {
		t.Fatalf("an unknown project is nil, nil: %+v %v", none, err)
	}
	if hidden, _ := app.GetDTrackProject(ctx, other, "p-default"); hidden != nil {
		t.Fatal("another tenant must not read the project")
	}

	mapped, _ := app.ListMappedDTrackProjects(ctx, tenant, src)
	unmapped, _ := app.ListUnmappedDTrackProjects(ctx, tenant, src)
	if len(mapped) != 2 || len(unmapped) != 1 || unmapped[0].ProjectUUID != "p-none" {
		t.Fatalf("mapped %d, unmapped %d: the two lists are complements", len(mapped), len(unmapped))
	}
	if o, _ := app.ListMappedDTrackProjects(ctx, other, src); len(o) != 0 {
		t.Errorf("another tenant's mapped list: %d", len(o))
	}

	// A person moves the project the default rule took.
	if err := app.MapDTrackProject(ctx, tenant, "p-default", own); err != nil {
		t.Fatalf("a mapped project can be mapped again: %v", err)
	}
	got, _ = app.GetDTrackProject(ctx, tenant, "p-default")
	if got.MappingRule != domain.DTrackManualMapping || *got.ApplicationID != own {
		t.Fatalf("after the person: %+v", got)
	}
	// The next portfolio sync, where the rules still say the default application, must not undo it.
	if err := app.UpsertDTrackProject(ctx, rec("p-default", "flare-reminders", &demo, "defaultApplication", "")); err != nil {
		t.Fatal(err)
	}
	if got, _ = app.GetDTrackProject(ctx, tenant, "p-default"); *got.ApplicationID != own || got.MappingRule != domain.DTrackManualMapping {
		t.Fatalf("a person's mapping survives the rules: %+v", got)
	}
}
