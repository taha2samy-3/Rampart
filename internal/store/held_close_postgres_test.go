package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

// Tests the mass-close guard scenarios on real PostgreSQL with RLS (docs/21 Section 3.2):
// - 60% of 40 findings held (24 > 20 and 24/40 = 60% > 50%)
// - HeldClose table tenant isolation
// - A finding that came back between runs is NOT closed on confirm
// - Confirm closes exactly the remaining absent findings
// - Discard closes none and marks the held close discarded
func TestHeldClose_PostgresScenarios(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)
	tenant := newTenant(t, ctx, sys, "mass-close")

	appID := uuid.New()
	appRec := domain.Application{ID: appID, TenantID: tenant, Slug: "payments-api", Name: "Payments API"}
	if err := sys.SaveApplication(ctx, appRec); err != nil {
		t.Fatalf("SaveApplication failed: %v", err)
	}

	asset := &domain.Asset{ID: uuid.New(), TenantID: tenant, ApplicationID: &appID, Type: domain.AssetRepository, Key: "payments-repo", Active: true}
	if err := app.CreateAsset(ctx, asset); err != nil {
		t.Fatalf("CreateAsset failed: %v", err)
	}

	srcID, err := sys.SaveScanSource(ctx, tenant, "ci-trivy", "trivy", nil)
	if err != nil {
		t.Fatalf("SaveScanSource failed: %v", err)
	}

	scope := ingest.CloseScope{
		TenantID:      tenant,
		ScanSourceID:  srcID,
		ScannerFamily: "trivy",
		AssetID:       asset.ID,
		Track:         "main",
	}

	eng := ingest.NewEngine(app)

	// Step 1: Create 40 findings in Run 1
	run1ID := uuid.New()
	run1 := &domain.IngestRun{
		ID:            run1ID,
		TenantID:      tenant,
		ScanSourceID:  srcID,
		ApplicationID: appID,
		AssetID:       asset.ID,
		Track:         "main",
		Status:        domain.RunCompleted,
		ScannerFamily: "trivy",
		CreatedAt:     time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := app.CreateIngestRun(ctx, run1); err != nil {
		t.Fatalf("CreateIngestRun failed: %v", err)
	}

	records := make([]ingest.StagedRecord, 40)
	for i := 0; i < 40; i++ {
		key := fmt.Sprintf("vuln-%02d", i+1)
		records[i] = ingest.StagedRecord{
			FindingKey:   key,
			Category:     domain.CategorySAST,
			RuleID:       fmt.Sprintf("RULE-%04d", 1000+i),
			Title:        fmt.Sprintf("Vulnerability %02d", i+1),
			Severity:     domain.SeverityHigh,
			ToolSeverity: "HIGH",
			ContentHash:  fmt.Sprintf("hash-%02d", i+1),
			SeenAt:       run1.CreatedAt,
			Location:     domain.Location{Code: &domain.CodeLocation{FilePath: key + ".go", StartLine: 1}},
		}
	}

	res1, err := eng.MergeBatch(ctx, scope, run1ID, appID, records)
	if err != nil || res1.Created != 40 {
		t.Fatalf("run1 merge failed: created %d, err %v", res1.Created, err)
	}

	// Verify all 40 are open
	active, err := app.GetActiveScopeFindings(ctx, tenant, asset.ID, "main")
	if err != nil || len(active) != 40 {
		t.Fatalf("expected 40 active findings, got %d (err: %v)", len(active), err)
	}

	// Step 2: Run 2 reports only 16 of the 40 findings (24 absent = 60% > 50%, and 24 > 20)
	run2ID := uuid.New()
	run2 := &domain.IngestRun{
		ID:            run2ID,
		TenantID:      tenant,
		ScanSourceID:  srcID,
		ApplicationID: appID,
		AssetID:       asset.ID,
		Track:         "main",
		Status:        domain.RunCompleted,
		ScannerFamily: "trivy",
		CreatedAt:     time.Now().UTC().Add(-1 * time.Hour),
	}
	if err := app.CreateIngestRun(ctx, run2); err != nil {
		t.Fatalf("CreateIngestRun 2 failed: %v", err)
	}

	res2, err := eng.MergeBatch(ctx, scope, run2ID, appID, records[:16])
	if err != nil {
		t.Fatalf("run2 merge failed: %v", err)
	}
	if res2.Untouched != 16 {
		t.Fatalf("expected 16 untouched in run2, got %d", res2.Untouched)
	}

	// Run close step with guard enabled
	closeRes, err := eng.CloseScopeStepWithGuard(ctx, scope, run2ID, true)
	if err != nil {
		t.Fatalf("CloseScopeStepWithGuard failed: %v", err)
	}
	if !closeRes.HeldForConfirmation {
		t.Fatalf("expected close step to be held for confirmation (60%% of 40 > 50%% and 24 > 20)")
	}
	if closeRes.Closed != 0 {
		t.Fatalf("expected 0 closed findings when held, got %d", closeRes.Closed)
	}
	if len(closeRes.HeldFindingIDs) != 24 {
		t.Fatalf("expected 24 held finding IDs, got %d", len(closeRes.HeldFindingIDs))
	}

	// Step 3: Record HeldClose row
	hc := &domain.HeldClose{
		ID:          domain.NewID(),
		TenantID:    tenant,
		IngestRunID: run2ID,
		Scope:       scope,
		FindingIDs:  closeRes.HeldFindingIDs,
		CreatedAt:   time.Now().UTC().Add(-45 * time.Minute),
	}
	if err := app.CreateHeldClose(ctx, tenant, hc); err != nil {
		t.Fatalf("CreateHeldClose failed: %v", err)
	}

	// Verify Tenant Isolation on held_close table
	otherTenant := newTenant(t, ctx, sys, "other-corp")
	otherHC, err := app.GetHeldClose(ctx, otherTenant, hc.ID)
	if err != nil {
		t.Fatalf("GetHeldClose for other tenant returned error: %v", err)
	}
	if otherHC != nil {
		t.Fatalf("tenant isolation broken: other tenant can see held close %v", otherHC)
	}
	otherList, err := app.ListHeldCloses(ctx, otherTenant, "")
	if err != nil || len(otherList) != 0 {
		t.Fatalf("other tenant list returned %d items, want 0", len(otherList))
	}

	// Step 4: Simulate a finding that came back between run2 and confirmation!
	// Let fidComeBack be the first held finding ID. Run 2.5 reports it present!
	fidComeBack := closeRes.HeldFindingIDs[0]
	var comeBackKey string
	for _, f := range active {
		if f.ID == fidComeBack {
			comeBackKey = f.FindingKey
			break
		}
	}
	if comeBackKey == "" {
		t.Fatalf("could not find finding key for %s", fidComeBack)
	}

	run2_5ID := uuid.New()
	run2_5 := &domain.IngestRun{
		ID:            run2_5ID,
		TenantID:      tenant,
		ScanSourceID:  srcID,
		ApplicationID: appID,
		AssetID:       asset.ID,
		Track:         "main",
		Status:        domain.RunCompleted,
		ScannerFamily: "trivy",
		CreatedAt:     time.Now().UTC().Add(-10 * time.Minute), // after run2
	}
	if err := app.CreateIngestRun(ctx, run2_5); err != nil {
		t.Fatalf("CreateIngestRun 2.5 failed: %v", err)
	}

	// Report fidComeBack again in run 2.5
	_, err = eng.MergeBatch(ctx, scope, run2_5ID, appID, []ingest.StagedRecord{
		{
			FindingKey:   comeBackKey,
			Category:     domain.CategorySCA,
			RuleID:       "CVE-2026-9999",
			Title:        "Reappeared Vuln",
			Severity:     domain.SeverityHigh,
			ToolSeverity: "HIGH",
			ContentHash:  "hash-new",
			SeenAt:       run2_5.CreatedAt,
		},
	})
	if err != nil {
		t.Fatalf("merge run 2.5 failed: %v", err)
	}

	// Step 5: Confirm the held close
	closedCount, err := app.ApplyHeldClose(ctx, tenant, hc.ID, "user:lead@corp.com")
	if err != nil {
		t.Fatalf("ApplyHeldClose failed: %v", err)
	}

	// Exactly 23 findings must close, because fidComeBack came back!
	if closedCount != 23 {
		t.Fatalf("expected exactly 23 closed findings (1 came back), got %d", closedCount)
	}

	// Verify fidComeBack remained OPEN
	allFindings, _ := app.GetFindingsByKeys(ctx, tenant, []string{comeBackKey})
	if f, ok := allFindings[comeBackKey]; !ok || f.State != domain.StateOpen {
		t.Fatalf("finding that came back must stay StateOpen, got %+v", f)
	}

	// Verify the held close is marked confirmed
	gotHC, err := app.GetHeldClose(ctx, tenant, hc.ID)
	if err != nil || gotHC == nil {
		t.Fatalf("GetHeldClose failed: %v", err)
	}
	if gotHC.Decision != domain.HeldCloseDecisionConfirmed {
		t.Fatalf("expected decision 'confirmed', got %q", gotHC.Decision)
	}
	if gotHC.DecidedBy != "user:lead@corp.com" {
		t.Fatalf("expected decidedBy 'user:lead@corp.com', got %q", gotHC.DecidedBy)
	}
	if gotHC.DecidedAt == nil {
		t.Fatalf("expected decidedAt to be set")
	}

	// Cannot apply an already decided held close
	if _, err := app.ApplyHeldClose(ctx, tenant, hc.ID, "user:lead@corp.com"); err == nil {
		t.Fatalf("re-applying decided held close must fail")
	}

	// Step 6: Test Discard scenario
	hcDiscard := &domain.HeldClose{
		ID:          domain.NewID(),
		TenantID:    tenant,
		IngestRunID: run2ID,
		Scope:       scope,
		FindingIDs:  []uuid.UUID{fidComeBack},
		CreatedAt:   time.Now().UTC(),
	}
	if err := app.CreateHeldClose(ctx, tenant, hcDiscard); err != nil {
		t.Fatalf("CreateHeldClose discard failed: %v", err)
	}

	if err := app.DecideHeldClose(ctx, tenant, hcDiscard.ID, domain.HeldCloseDecisionDiscarded, "user:secops@corp.com"); err != nil {
		t.Fatalf("DecideHeldClose discard failed: %v", err)
	}

	gotDiscarded, _ := app.GetHeldClose(ctx, tenant, hcDiscard.ID)
	if gotDiscarded.Decision != domain.HeldCloseDecisionDiscarded {
		t.Fatalf("expected decision 'discarded', got %q", gotDiscarded.Decision)
	}

	// Finding must still be open
	fStillOpen, _ := app.GetFindingsByKeys(ctx, tenant, []string{comeBackKey})
	if fStillOpen[comeBackKey].State != domain.StateOpen {
		t.Fatalf("discarded close must not alter finding state")
	}
}
