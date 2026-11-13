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

func TestFederation_PostgresScenarios(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)

	t1 := newTenant(t, ctx, sys, "federation-a")
	t2 := newTenant(t, ctx, sys, "federation-b")

	// 1. Create scan sources
	s1, err := app.SaveScanSource(ctx, t1, "gh-source", "semgrep", nil)
	if err != nil {
		t.Fatalf("failed to create scan source in t1: %v", err)
	}
	s2, err := app.SaveScanSource(ctx, t2, "gh-source-b", "semgrep", nil)
	if err != nil {
		t.Fatalf("failed to create scan source in t2: %v", err)
	}

	// 2. Save trust rules for t1
	rulesT1 := []domain.TrustRule{
		{
			Issuer:            "https://token.actions.githubusercontent.com",
			Provider:          "github",
			RepositoryID:      "123456",
			RepositoryOwnerID: "654321",
			Repository:        "acme/backend",
		},
	}
	if err := app.SaveTrustRules(ctx, t1, s1, rulesT1); err != nil {
		t.Fatalf("SaveTrustRules failed: %v", err)
	}

	// 3. Save trust rules for t2
	rulesT2 := []domain.TrustRule{
		{
			Issuer:            "https://token.actions.githubusercontent.com",
			Provider:          "github",
			RepositoryID:      "999999",
			RepositoryOwnerID: "888888",
			Repository:        "other/app",
		},
	}
	if err := app.SaveTrustRules(ctx, t2, s2, rulesT2); err != nil {
		t.Fatalf("SaveTrustRules failed for t2: %v", err)
	}

	// 4. Test RLS Isolation: t1 only sees its own trust rules
	gotT1, err := app.ListTrustRules(ctx, t1)
	if err != nil {
		t.Fatalf("ListTrustRules t1 failed: %v", err)
	}
	if len(gotT1) != 1 || gotT1[0].Rule.RepositoryID != "123456" {
		t.Fatalf("t1 trust rules incorrect, got %+v", gotT1)
	}

	gotT2, err := app.ListTrustRules(ctx, t2)
	if err != nil {
		t.Fatalf("ListTrustRules t2 failed: %v", err)
	}
	if len(gotT2) != 1 || gotT2[0].Rule.RepositoryID != "999999" {
		t.Fatalf("t2 trust rules incorrect, got %+v", gotT2)
	}

	// Filter by issuer
	byIssuer, err := app.ListTrustRulesByIssuer(ctx, t1, "https://token.actions.githubusercontent.com")
	if err != nil {
		t.Fatalf("ListTrustRulesByIssuer failed: %v", err)
	}
	if len(byIssuer) != 1 {
		t.Fatalf("expected 1 rule by issuer, got %d", len(byIssuer))
	}

	byWrongIssuer, err := app.ListTrustRulesByIssuer(ctx, t1, "https://unknown.issuer")
	if err != nil {
		t.Fatalf("ListTrustRulesByIssuer wrong failed: %v", err)
	}
	if len(byWrongIssuer) != 0 {
		t.Fatalf("expected 0 rules by unknown issuer, got %d", len(byWrongIssuer))
	}

	// 5. Test JTI Replay Prevention (shared global table)
	jti := uuid.New().String()
	exp := time.Now().Add(10 * time.Minute)
	if err := app.RecordFederationJTI(ctx, "https://token.actions.githubusercontent.com", jti, exp); err != nil {
		t.Fatalf("first RecordFederationJTI failed: %v", err)
	}

	// Second insert with same issuer and jti must fail with ErrJTIReplay
	err = app.RecordFederationJTI(ctx, "https://token.actions.githubusercontent.com", jti, exp)
	if err == nil {
		t.Fatal("expected replay error on duplicate (issuer, jti), got nil")
	}
	if !errors.Is(err, store.ErrJTIReplay) {
		t.Fatalf("expected ErrJTIReplay, got %v", err)
	}

	// Different issuer with same jti is allowed (RFC 7519 jti is unique per issuer)
	if err := app.RecordFederationJTI(ctx, "https://gitlab.com", jti, exp); err != nil {
		t.Fatalf("same jti with different issuer should succeed, got: %v", err)
	}

	// 6. Test Cascade on ScanSource Deletion
	if _, err := sys.Pool().Exec(ctx, `DELETE FROM scan_source WHERE id = $1`, s1); err != nil {
		t.Fatalf("DELETE scan_source failed: %v", err)
	}
	afterDelete, err := app.ListTrustRules(ctx, t1)
	if err != nil {
		t.Fatalf("ListTrustRules after delete failed: %v", err)
	}
	if len(afterDelete) != 0 {
		t.Fatalf("expected 0 trust rules after scan source deleted, got %d", len(afterDelete))
	}

	// 7. Test PurgeExpiredFederationJTIs
	expiredJTI := uuid.New().String()
	if err := app.RecordFederationJTI(ctx, "https://token.actions.githubusercontent.com", expiredJTI, time.Now().Add(-5*time.Minute)); err != nil {
		t.Fatalf("failed to insert expired JTI: %v", err)
	}
	purged, err := app.PurgeExpiredFederationJTIs(ctx, time.Now())
	if err != nil {
		t.Fatalf("PurgeExpiredFederationJTIs failed: %v", err)
	}
	if purged < 1 {
		t.Fatalf("expected at least 1 purged JTI, got %d", purged)
	}
}
