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

