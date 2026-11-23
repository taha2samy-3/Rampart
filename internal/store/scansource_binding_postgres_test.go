package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

func TestScanSourceBinding_PostgresScenarios(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)

	t1 := newTenant(t, ctx, sys, "binding-tenant-a")
	t2 := newTenant(t, ctx, sys, "binding-tenant-b")

	// 1. Create an Application in tenant 1
	app1 := &domain.Application{
		ID:                  domain.NewID(),
		TenantID:            t1,
		Slug:                "payments-service",
		Name:                "payments-service",
		Branch:              "main",
		BusinessCriticality: "high",
		Lifecycle:           "production",
		Version:             1,
		CreatedAt:           time.Now().UTC(),
	}
	if err := app.CreateApplication(ctx, app1); err != nil {
		t.Fatalf("failed to create application in t1: %v", err)
	}

	// 2. Save a ScanSource bound to app1 with multiple categories and federation
	src1 := &domain.ScanSource{
		ID:             domain.NewID(),
		TenantID:       t1,
		Name:           "payments-ci",
		ApplicationID:  app1.ID,
		ApplicationRef: domain.ApplicationRef{Name: app1.Name},
		Categories:     []string{"sast", "secret"},
		Type:           "upload",
		ScannerFamily:  "semgrep",
		Auth: domain.AuthSpec{
			Federation: &domain.FederationSpec{
				Issuer: "https://token.actions.githubusercontent.com",
				BoundClaims: map[string]string{
					"repository": "acme/payments",
					"ref":        "refs/heads/main",
				},
			},
		},
		IngestionPolicy: &domain.IngestionPolicy{
			MinimumSeverity: "medium",
		},
	}

	savedID, err := app.SaveScanSourceRecord(ctx, src1)
	if err != nil {
		t.Fatalf("SaveScanSourceRecord failed: %v", err)
	}
	if savedID != src1.ID {
		t.Fatalf("expected savedID %s, got %s", src1.ID, savedID)
	}

	// 3. Retrieve via GetScanSource and verify all fields
	gotSrc, err := app.GetScanSource(ctx, t1, savedID)
	if err != nil {
		t.Fatalf("GetScanSource failed: %v", err)
	}
	if gotSrc.Name != "payments-ci" {
		t.Errorf("expected name 'payments-ci', got %q", gotSrc.Name)
	}
	if gotSrc.ApplicationID != app1.ID {
		t.Errorf("expected ApplicationID %s, got %s", app1.ID, gotSrc.ApplicationID)
	}
	if gotSrc.ApplicationRef.Name != "payments-service" {
		t.Errorf("expected ApplicationRef.Name 'payments-service', got %q", gotSrc.ApplicationRef.Name)
	}
	if len(gotSrc.Categories) != 2 || gotSrc.Categories[0] != "sast" || gotSrc.Categories[1] != "secret" {
		t.Errorf("expected categories [sast secret], got %v", gotSrc.Categories)
	}
	if gotSrc.Auth.Federation == nil || gotSrc.Auth.Federation.BoundClaims["repository"] != "acme/payments" {
		t.Errorf("expected federation claims with repository=acme/payments, got %+v", gotSrc.Auth.Federation)
	}
	if gotSrc.IngestionPolicy == nil || gotSrc.IngestionPolicy.MinimumSeverity != "medium" {
		t.Errorf("expected ingestion policy with minimumSeverity=medium, got %+v", gotSrc.IngestionPolicy)
	}

	// 4. Test RLS Isolation: tenant 2 cannot view tenant 1's ScanSource
	_, err = app.GetScanSource(ctx, t2, savedID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound when t2 queries t1's scan source, got %v", err)
	}

	// 5. Foreign Key Constraint: ScanSource with non-existent ApplicationID must fail
	badSrc := &domain.ScanSource{
		ID:            domain.NewID(),
		TenantID:      t1,
		Name:          "bad-app-source",
		ApplicationID: uuid.MustParse("00000000-0000-0000-0000-000000000999"),
		Categories:    []string{"all"},
		Type:          "upload",
	}
	_, err = app.SaveScanSourceRecord(ctx, badSrc)
	if err == nil {
		t.Fatal("expected foreign key violation error for non-existent application_id, got nil")
	}

	// 6. Test PermitsCategory helper
	if !gotSrc.PermitsCategory(domain.CategorySAST) {
		t.Error("expected SAST to be permitted")
	}
	if !gotSrc.PermitsCategory(domain.CategorySecret) {
		t.Error("expected Secret to be permitted")
	}
	if gotSrc.PermitsCategory(domain.CategorySCA) {
		t.Error("expected SCA to be forbidden")
	}
	if gotSrc.PermitsCategory(domain.CategoryContainer) {
		t.Error("expected Container to be forbidden")
	}
}
