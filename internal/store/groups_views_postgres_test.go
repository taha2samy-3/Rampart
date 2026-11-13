package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

func TestGroupsAndViews_PostgresRLS(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)

	tenantA := newTenant(t, ctx, sys, "groups-tenant-a")
	tenantB := newTenant(t, ctx, sys, "groups-tenant-b")

	// 1. Finding Groups Scenarios
	grpA := &domain.FindingGroup{
		TenantID:    tenantA,
		Name:        "Log4j Remediation Sprint",
		Description: "All Log4Shell occurrences across services",
		Owner:       "alice@example.com",
	}
	if err := app.CreateFindingGroup(ctx, grpA); err != nil {
		t.Fatalf("creating group A: %v", err)
	}

	finding1 := uuid.New()
	finding2 := uuid.New()
	if err := app.AddGroupMembers(ctx, tenantA, grpA.ID, []uuid.UUID{finding1, finding2}); err != nil {
		t.Fatalf("adding members to group A: %v", err)
	}

	// Verify group A details and member count
	fetchedA, err := app.GetFindingGroup(ctx, tenantA, grpA.ID)
	if err != nil {
		t.Fatalf("getting group A: %v", err)
	}
	if fetchedA.MemberCount != 2 {
		t.Errorf("expected member count 2, got %d", fetchedA.MemberCount)
	}

	membersA, err := app.ListGroupFindings(ctx, tenantA, grpA.ID)
	if err != nil {
		t.Fatalf("listing group findings: %v", err)
	}
	if len(membersA) != 2 {
		t.Errorf("expected 2 members, got %d", len(membersA))
	}

	// Tenant B cannot see Tenant A's group (RLS isolation)
	_, err = app.GetFindingGroup(ctx, tenantB, grpA.ID)
	if !errorsIsNotFound(err) {
		t.Errorf("tenant B should get not found for tenant A's group, got: %v", err)
	}

	groupsB, err := app.ListFindingGroups(ctx, tenantB)
	if err != nil {
		t.Fatalf("listing groups for tenant B: %v", err)
	}
	if len(groupsB) != 0 {
		t.Errorf("tenant B should see 0 groups, got %d", len(groupsB))
	}

	// Remove member
	if err := app.RemoveGroupMembers(ctx, tenantA, grpA.ID, []uuid.UUID{finding1}); err != nil {
		t.Fatalf("removing member: %v", err)
	}
	fetchedAAfterRemove, err := app.GetFindingGroup(ctx, tenantA, grpA.ID)
	if err != nil || fetchedAAfterRemove.MemberCount != 1 {
		t.Errorf("expected member count 1 after remove, got %d", fetchedAAfterRemove.MemberCount)
	}

	// 2. Saved Views Scenarios
	viewA := &domain.SavedView{
		TenantID: tenantA,
		Owner:    "alice@example.com",
		Name:     "Critical SCA in Production",
		Query:    "severity:critical category:sca env:production",
		Scope:    "tenant",
	}
	if err := app.CreateSavedView(ctx, viewA); err != nil {
		t.Fatalf("creating saved view: %v", err)
	}

	fetchedViewA, err := app.GetSavedView(ctx, tenantA, viewA.ID)
	if err != nil {
		t.Fatalf("getting saved view: %v", err)
	}
	if fetchedViewA.Name != "Critical SCA in Production" {
		t.Errorf("view name = %s", fetchedViewA.Name)
	}

	// Tenant B cannot see Tenant A's saved view
	_, err = app.GetSavedView(ctx, tenantB, viewA.ID)
	if !errorsIsNotFound(err) {
		t.Errorf("tenant B should get not found for view A, got: %v", err)
	}

	// Delete saved view
	if err := app.DeleteSavedView(ctx, tenantA, viewA.ID); err != nil {
		t.Fatalf("deleting saved view: %v", err)
	}
	_, err = app.GetSavedView(ctx, tenantA, viewA.ID)
	if !errorsIsNotFound(err) {
		t.Errorf("expected not found after delete, got %v", err)
	}
}

func errorsIsNotFound(err error) bool {
	return err == store.ErrNotFound
}
