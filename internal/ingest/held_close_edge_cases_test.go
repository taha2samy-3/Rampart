package ingest_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

// TestHeldClose_BoundaryConditions tests the exact boundary thresholds for mass-close guard (docs/21 §3.2).
// - Less than 20 findings missing NEVER triggers mass close even if 100% are missing.
// - Less than 50% missing NEVER triggers mass close even if > 20 are missing.
// - At least 20 findings missing AND at least 50% missing triggers mass close.
func TestHeldClose_BoundaryConditions(t *testing.T) {
	ctx := context.Background()

	t.Run("19 missing out of 20 (95% missing, but < 20) does not hold", func(t *testing.T) {
		mStore := ingest.NewMemoryStore()
		tenantID := uuid.New()
		assetID := uuid.New()
		appID := uuid.New()
		srcID := uuid.New()

		scope := ingest.CloseScope{
			TenantID:      tenantID,
			ScanSourceID:  srcID,
			ScannerFamily: "trivy",
			AssetID:       assetID,
			Track:         "main",
		}

		eng := ingest.NewEngine(mStore)

		// Create 20 findings
		run1ID := uuid.New()
		records := make([]ingest.StagedRecord, 20)
		for i := 0; i < 20; i++ {
			records[i] = ingest.StagedRecord{
				FindingKey:   fmt.Sprintf("vuln-%d", i),
				RuleID:       fmt.Sprintf("RULE-%d", i),
				Title:        fmt.Sprintf("Title %d", i),
				Severity:     domain.SeverityHigh,
				ToolSeverity: "HIGH",
				SeenAt:       time.Now().Add(-1 * time.Hour),
			}
		}
		_, err := eng.MergeBatch(ctx, scope, run1ID, appID, records)
		if err != nil {
			t.Fatal(err)
		}

		// Run 2 reports only 1 finding (19 missing = 95% > 50%, but 19 < 20)
		run2ID := uuid.New()
		records2 := []ingest.StagedRecord{records[0]}
		res2, err := eng.MergeBatch(ctx, scope, run2ID, appID, records2)
		if err != nil {
			t.Fatal(err)
		}

		closeRes, err := eng.CloseScopeStepWithGuard(ctx, scope, run2ID, true)
		if err != nil {
			t.Fatal(err)
		}

		if closeRes.HeldForConfirmation {
			t.Fatalf("19 missing findings must NOT be held (min threshold is 20), got held")
		}
		if closeRes.Closed != 19 {
			t.Fatalf("expected 19 findings closed directly, got %d", closeRes.Closed)
		}
		_ = res2
	})

	t.Run("20 missing out of 100 (20% missing, < 50%) does not hold", func(t *testing.T) {
		mStore := ingest.NewMemoryStore()
		tenantID := uuid.New()
		assetID := uuid.New()
		appID := uuid.New()
		srcID := uuid.New()

		scope := ingest.CloseScope{
			TenantID:      tenantID,
			ScanSourceID:  srcID,
			ScannerFamily: "trivy",
			AssetID:       assetID,
			Track:         "main",
		}

		eng := ingest.NewEngine(mStore)

		// Create 100 findings
		run1ID := uuid.New()
		records := make([]ingest.StagedRecord, 100)
		for i := 0; i < 100; i++ {
			records[i] = ingest.StagedRecord{
				FindingKey:   fmt.Sprintf("vuln-%d", i),
				RuleID:       fmt.Sprintf("RULE-%d", i),
				Title:        fmt.Sprintf("Title %d", i),
				Severity:     domain.SeverityHigh,
				ToolSeverity: "HIGH",
				SeenAt:       time.Now().Add(-1 * time.Hour),
			}
		}
		_, err := eng.MergeBatch(ctx, scope, run1ID, appID, records)
		if err != nil {
			t.Fatal(err)
		}

		// Run 2 reports 80 findings (20 missing = 20% < 50%, even though count is 20)
		run2ID := uuid.New()
		records2 := records[:80]
		_, err = eng.MergeBatch(ctx, scope, run2ID, appID, records2)
		if err != nil {
			t.Fatal(err)
		}

		closeRes, err := eng.CloseScopeStepWithGuard(ctx, scope, run2ID, true)
		if err != nil {
			t.Fatal(err)
		}

		if closeRes.HeldForConfirmation {
			t.Fatalf("20%% missing must NOT be held (ratio threshold is 50%%), got held")
		}
		if closeRes.Closed != 20 {
			t.Fatalf("expected 20 findings closed directly, got %d", closeRes.Closed)
		}
	})

	t.Run("exactly 20 missing out of 40 (closedCount == minFindings 20) does NOT hold because it requires > 20", func(t *testing.T) {
		mStore := ingest.NewMemoryStore()
		tenantID := uuid.New()
		assetID := uuid.New()
		appID := uuid.New()
		srcID := uuid.New()

		scope := ingest.CloseScope{
			TenantID:      tenantID,
			ScanSourceID:  srcID,
			ScannerFamily: "trivy",
			AssetID:       assetID,
			Track:         "main",
		}

		eng := ingest.NewEngine(mStore)

		// Create 40 findings
		run1ID := uuid.New()
		records := make([]ingest.StagedRecord, 40)
		for i := 0; i < 40; i++ {
			records[i] = ingest.StagedRecord{
				FindingKey:   fmt.Sprintf("vuln-%d", i),
				RuleID:       fmt.Sprintf("RULE-%d", i),
				Title:        fmt.Sprintf("Title %d", i),
				Severity:     domain.SeverityHigh,
				ToolSeverity: "HIGH",
				SeenAt:       time.Now().Add(-1 * time.Hour),
			}
		}
		_, err := eng.MergeBatch(ctx, scope, run1ID, appID, records)
		if err != nil {
			t.Fatal(err)
		}

		// Run 2 reports 20 findings (20 missing out of 40: 20 is not > 20)
		run2ID := uuid.New()
		records2 := records[:20]
		_, err = eng.MergeBatch(ctx, scope, run2ID, appID, records2)
		if err != nil {
			t.Fatal(err)
		}

		closeRes, err := eng.CloseScopeStepWithGuard(ctx, scope, run2ID, true)
		if err != nil {
			t.Fatal(err)
		}

		if closeRes.HeldForConfirmation {
			t.Fatalf("expected 20 missing findings not to be held (must be strictly > 20), got held")
		}
		if closeRes.Closed != 20 {
			t.Fatalf("expected 20 findings closed directly, got %d", closeRes.Closed)
		}
	})

	t.Run("21 missing out of 40 (21 > 20 and 21/40 = 52.5% > 50%) triggers held close", func(t *testing.T) {
		mStore := ingest.NewMemoryStore()
		tenantID := uuid.New()
		assetID := uuid.New()
		appID := uuid.New()
		srcID := uuid.New()

		scope := ingest.CloseScope{
			TenantID:      tenantID,
			ScanSourceID:  srcID,
			ScannerFamily: "trivy",
			AssetID:       assetID,
			Track:         "main",
		}

		eng := ingest.NewEngine(mStore)

		// Create 40 findings
		run1ID := uuid.New()
		records := make([]ingest.StagedRecord, 40)
		for i := 0; i < 40; i++ {
			records[i] = ingest.StagedRecord{
				FindingKey:   fmt.Sprintf("vuln-%d", i),
				RuleID:       fmt.Sprintf("RULE-%d", i),
				Title:        fmt.Sprintf("Title %d", i),
				Severity:     domain.SeverityHigh,
				ToolSeverity: "HIGH",
				SeenAt:       time.Now().Add(-1 * time.Hour),
			}
		}
		_, err := eng.MergeBatch(ctx, scope, run1ID, appID, records)
		if err != nil {
			t.Fatal(err)
		}

		// Run 2 reports 19 findings (21 missing out of 40: 21 > 20 and 21/40 = 52.5% > 50%)
		run2ID := uuid.New()
		records2 := records[:19]
		_, err = eng.MergeBatch(ctx, scope, run2ID, appID, records2)
		if err != nil {
			t.Fatal(err)
		}

		closeRes, err := eng.CloseScopeStepWithGuard(ctx, scope, run2ID, true)
		if err != nil {
			t.Fatal(err)
		}

		if !closeRes.HeldForConfirmation {
			t.Fatalf("expected 21/40 (52.5%%) missing findings to trigger held close, got false")
		}
		if len(closeRes.HeldFindingIDs) != 21 {
			t.Fatalf("expected 21 held finding IDs, got %d", len(closeRes.HeldFindingIDs))
		}
		if closeRes.Closed != 0 {
			t.Fatalf("expected 0 findings closed immediately when held, got %d", closeRes.Closed)
		}
	})
}
