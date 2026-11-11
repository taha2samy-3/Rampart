package ingest_test

import (
	"context"
	"testing"
	"time"

	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/normalize"
)

func TestMergeEngineLifecycleAndReimport(t *testing.T) {
	ctx := context.Background()
	store := ingest.NewMemoryStore()
	engine := ingest.NewEngine(store)

	tenantID := domain.NewID()
	assetID := domain.NewID()
	appID := domain.NewID()
	sourceID := domain.NewID()
	scope := ingest.CloseScope{
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: "semgrep",
		AssetID:       assetID,
		Track:         "main",
	}

	findingKey := "test-fingerprint-sql-injection"
	rec1 := ingest.StagedRecord{
		FindingKey:   findingKey,
		Category:     domain.CategorySAST,
		RuleID:       "rules.sql_injection",
		Title:        "SQL Injection in auth",
		Description:  "Raw query without parameterization",
		ToolSeverity: "error",
		Severity:     domain.SeverityHigh,
		ContentHash:  normalize.ComputeContentHash("SQL Injection in auth", "Raw query without parameterization", "error", "", "", "src/auth.go"),
		Location: domain.Location{
			Code: &domain.CodeLocation{FilePath: "src/auth.go", StartLine: 40},
		},
		SeenAt: time.Now().UTC(),
	}

	// -------------------------------------------------------------
	// 1. Initial Scan (Run 1) -> Finding must be CREATED
	// -------------------------------------------------------------
	run1ID := domain.NewID()
	out1, err := engine.MergeBatch(ctx, scope, run1ID, appID, []ingest.StagedRecord{rec1})
	if err != nil {
		t.Fatalf("run 1 merge failed: %v", err)
	}
	if out1.Created != 1 || out1.Untouched != 0 || out1.Updated != 0 {
		t.Fatalf("expected 1 created finding in run 1, got %+v", out1)
	}

	// -------------------------------------------------------------
	// 2. Rescan with identical report (Run 2) -> Finding must be UNTOUCHED
	// -------------------------------------------------------------
	run2ID := domain.NewID()
	out2, err := engine.MergeBatch(ctx, scope, run2ID, appID, []ingest.StagedRecord{rec1})
	if err != nil {
		t.Fatalf("run 2 merge failed: %v", err)
	}
	if out2.Untouched != 1 || out2.Created != 0 {
		t.Fatalf("expected 1 untouched finding in run 2, got %+v", out2)
	}

	// -------------------------------------------------------------
	// 3. Rescan with updated description (Run 3) -> Finding must be UPDATED
	// -------------------------------------------------------------
	run3ID := domain.NewID()
	rec3 := rec1
	rec3.Description = "Raw query with string formatting concatenation"
	rec3.ContentHash = normalize.ComputeContentHash(rec3.Title, rec3.Description, rec3.ToolSeverity, "", "", "src/auth.go")

	out3, err := engine.MergeBatch(ctx, scope, run3ID, appID, []ingest.StagedRecord{rec3})
	if err != nil {
		t.Fatalf("run 3 merge failed: %v", err)
	}
	if out3.Updated != 1 {
		t.Fatalf("expected 1 updated finding in run 3, got %+v", out3)
	}

	// -------------------------------------------------------------
	// 4. Rescan where finding is fixed / missing (Run 4) -> Must AUTO-CLOSE (D13)
	// -------------------------------------------------------------
	run4ID := domain.NewID()
	// Report is empty (developer fixed the issue!)
	_, err = engine.MergeBatch(ctx, scope, run4ID, appID, []ingest.StagedRecord{})
	if err != nil {
		t.Fatalf("run 4 merge failed: %v", err)
	}

	closedCount, err := engine.CloseScopeStep(ctx, scope, run4ID)
	if err != nil {
		t.Fatalf("close step failed: %v", err)
	}
	if closedCount != 1 {
		t.Fatalf("expected 1 finding auto-closed in run 4, got %d", closedCount)
	}

	// Verify finding state is now fixed
	findings, _ := store.GetFindingsByKeys(ctx, tenantID, []string{findingKey})
	if f, ok := findings[findingKey]; !ok || f.State != domain.StateFixed {
		t.Fatalf("expected finding state 'fixed', got %v", f.State)
	}

	// -------------------------------------------------------------
	// 5. Rescan where finding reappears (Run 5) -> Must REACTIVATE to 'open' (D13)
	// -------------------------------------------------------------
	run5ID := domain.NewID()
	out5, err := engine.MergeBatch(ctx, scope, run5ID, appID, []ingest.StagedRecord{rec1})
	if err != nil {
		t.Fatalf("run 5 merge failed: %v", err)
	}
	if out5.Reactivated != 1 {
		t.Fatalf("expected 1 reactivated finding in run 5, got %+v", out5)
	}

	findings5, _ := store.GetFindingsByKeys(ctx, tenantID, []string{findingKey})
	f5 := findings5[findingKey]
	if f5.State != domain.StateOpen {
		t.Errorf("expected reactivated state 'open', got %s", f5.State)
	}
	if f5.ReopenedCount != 1 {
		t.Errorf("expected reopened_count 1, got %d", f5.ReopenedCount)
	}
}

func TestNotAffectedStatePreservedAcrossRescan(t *testing.T) {
	ctx := context.Background()
	store := ingest.NewMemoryStore()
	engine := ingest.NewEngine(store)

	tenantID := domain.NewID()
	assetID := domain.NewID()
	appID := domain.NewID()
	sourceID := domain.NewID()
	scope := ingest.CloseScope{
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: "trivy",
		AssetID:       assetID,
		Track:         "prod",
	}

	findingKey := "test-sca-fp"
	rec := ingest.StagedRecord{
		FindingKey:   findingKey,
		Category:     domain.CategorySCA,
		RuleID:       "CVE-2021-99999",
		Title:        "Vulnerability in lodash",
		ToolSeverity: "HIGH",
		Severity:     domain.SeverityHigh,
		ContentHash:  "hash-1",
		SeenAt:       time.Now().UTC(),
	}

	// 1. Initial Scan
	run1ID := domain.NewID()
	_, _ = engine.MergeBatch(ctx, scope, run1ID, appID, []ingest.StagedRecord{rec})

	// 2. Security analyst marks finding as False Positive (not_affected)
	findings, _ := store.GetFindingsByKeys(ctx, tenantID, []string{findingKey})
	f := findings[findingKey]
	f.State = domain.StateNotAffected
	f.StateReason = "code_not_reachable"
	_ = store.UpsertFindings(ctx, tenantID, []*domain.Finding{f})

	// 3. Rescan sees the vulnerability again
	run2ID := domain.NewID()
	out2, _ := engine.MergeBatch(ctx, scope, run2ID, appID, []ingest.StagedRecord{rec})
	if out2.Untouched != 1 {
		t.Errorf("expected untouched finding, got %+v", out2)
	}

	// Verify state is STILL not_affected (D18: False positive decision is preserved!)
	findingsRescan, _ := store.GetFindingsByKeys(ctx, tenantID, []string{findingKey})
	fRescan := findingsRescan[findingKey]
	if fRescan.State != domain.StateNotAffected {
		t.Errorf("expected state to remain 'not_affected', got %s", fRescan.State)
	}
}

func TestMassCloseGuard(t *testing.T) {
	ctx := context.Background()
	store := ingest.NewMemoryStore()
	engine := ingest.NewEngine(store)

	tenantID := domain.NewID()
	assetID := domain.NewID()
	appID := domain.NewID()
	sourceID := domain.NewID()
	scope := ingest.CloseScope{
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: "trivy",
		AssetID:       assetID,
		Track:         "main",
	}

	// Seed 10 findings in initial scan
	run1ID := domain.NewID()
	var records []ingest.StagedRecord
	for i := 0; i < 10; i++ {
		records = append(records, ingest.StagedRecord{
			FindingKey:  domain.NewID().String(),
			Category:    domain.CategorySCA,
			RuleID:      "vuln-test",
			Title:       "Test Vuln",
			Severity:    domain.SeverityHigh,
			ContentHash: "hash",
			SeenAt:      time.Now().UTC(),
		})
	}
	_, _ = engine.MergeBatch(ctx, scope, run1ID, appID, records)

	// Rescan with an empty report where all 10 would be closed
	run2ID := domain.NewID()
	closeRes, err := engine.CloseScopeStepWithGuard(ctx, scope, run2ID, true)
	if err != nil {
		t.Fatalf("close step error: %v", err)
	}

	// Must be held for confirmation because 10/10 > 50%
	if !closeRes.HeldForConfirmation {
		t.Errorf("expected mass close guard to hold run for confirmation")
	}
	if closeRes.Closed != 0 {
		t.Errorf("expected 0 closed findings when held, got %d", closeRes.Closed)
	}
}

func TestCodeChangeRecheckOnNotAffected(t *testing.T) {
	ctx := context.Background()
	store := ingest.NewMemoryStore()
	engine := ingest.NewEngine(store)

	tenantID := domain.NewID()
	assetID := domain.NewID()
	appID := domain.NewID()
	sourceID := domain.NewID()
	scope := ingest.CloseScope{
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: "semgrep",
		AssetID:       assetID,
		Track:         "main",
	}

	findingKey := "test-code-change-key"
	rec := ingest.StagedRecord{
		FindingKey:  findingKey,
		Category:    domain.CategorySAST,
		RuleID:      "rule.xss",
		Title:       "XSS in template",
		Severity:    domain.SeverityHigh,
		ContentHash: "initial-content-hash",
		SeenAt:      time.Now().UTC(),
	}

	// 1. Initial scan
	_, _ = engine.MergeBatch(ctx, scope, domain.NewID(), appID, []ingest.StagedRecord{rec})

	// 2. Marked not_affected
	findings, _ := store.GetFindingsByKeys(ctx, tenantID, []string{findingKey})
	f := findings[findingKey]
	f.State = domain.StateNotAffected
	_ = store.UpsertFindings(ctx, tenantID, []*domain.Finding{f})

	// 3. Rescan where content changed (developer edited the code at the finding location)
	recChanged := rec
	recChanged.ContentHash = "new-modified-content-hash"
	_, _ = engine.MergeBatch(ctx, scope, domain.NewID(), appID, []ingest.StagedRecord{recChanged})

	// 4. Assert flagged for re-review per D18 line 358
	findingsRescan, _ := store.GetFindingsByKeys(ctx, tenantID, []string{findingKey})
	fRescan := findingsRescan[findingKey]
	if fRescan.StateReason != "code_changed_recheck_needed" {
		t.Errorf("expected state_reason 'code_changed_recheck_needed', got %q", fRescan.StateReason)
	}
}

func TestMinimumSeverityAndEphemeral(t *testing.T) {
	ctx := context.Background()
	store := ingest.NewMemoryStore()
	engine := ingest.NewEngine(store)

	tenantID := domain.NewID()
	assetID := domain.NewID()
	appID := domain.NewID()
	sourceID := domain.NewID()
	scope := ingest.CloseScope{
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: "trivy",
		AssetID:       assetID,
		Track:         "main",
	}

	recLow := ingest.StagedRecord{
		FindingKey: "low-finding-key",
		Severity:   domain.SeverityLow,
		SeenAt:     time.Now().UTC(),
	}

	// 1. Test MinimumSeverity: Low is below High threshold -> not created
	out, _ := engine.MergeBatchWithOptions(ctx, scope, domain.NewID(), appID, []ingest.StagedRecord{recLow}, ingest.MergeOptions{
		MinimumSeverity: domain.SeverityHigh,
	})
	if out.Created != 0 {
		t.Errorf("expected 0 created for below-threshold severity, got %d", out.Created)
	}

	// 2. Test Ephemeral Run (PR branch): computes outcome but does not persist
	recHigh := ingest.StagedRecord{
		FindingKey: "pr-finding-key",
		Severity:   domain.SeverityHigh,
		SeenAt:     time.Now().UTC(),
	}
	outPR, _ := engine.MergeBatchWithOptions(ctx, scope, domain.NewID(), appID, []ingest.StagedRecord{recHigh}, ingest.MergeOptions{
		IsEphemeral: true,
	})
	if outPR.Created != 1 {
		t.Errorf("expected outcome.Created 1, got %d", outPR.Created)
	}
	// Assert NOT in store
	findings, _ := store.GetFindingsByKeys(ctx, tenantID, []string{"pr-finding-key"})
	if len(findings) != 0 {
		t.Errorf("expected ephemeral finding not to be persisted in store")
	}
}

func TestConcurrentAndOutOfOrderRuns(t *testing.T) {
	ctx := context.Background()
	store := ingest.NewMemoryStore()
	engine := ingest.NewEngine(store)

	tenantID := domain.NewID()
	assetID := domain.NewID()
	appID := domain.NewID()
	sourceID := domain.NewID()
	scope := ingest.CloseScope{
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: "semgrep",
		AssetID:       assetID,
		Track:         "main",
	}

	tNewer := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	tOlder := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)

	rec1 := ingest.StagedRecord{
		FindingKey:  "key-1",
		RuleID:      "rule-1",
		Title:       "Vuln 1",
		Severity:    domain.SeverityHigh,
		ContentHash: "hash-1",
		SeenAt:      tNewer,
	}

	// 1. Newer run arrives first
	out1, err := engine.MergeBatchWithOptions(ctx, scope, domain.NewID(), appID, []ingest.StagedRecord{rec1}, ingest.MergeOptions{
		ScanFinished: tNewer,
	})
	if err != nil {
		t.Fatalf("newer run failed: %v", err)
	}
	if out1.Created != 1 {
		t.Fatalf("expected 1 created finding, got %+v", out1)
	}

	// 2. Older run arrives out-of-order late -> Must be marked stale (D13 line 204)
	recOlder := rec1
	recOlder.SeenAt = tOlder
	recOlder.Title = "Old Vuln Title"
	recOlder.ContentHash = "hash-old"

	_, err = engine.MergeBatchWithOptions(ctx, scope, domain.NewID(), appID, []ingest.StagedRecord{recOlder}, ingest.MergeOptions{
		ScanFinished: tOlder,
	})
	if err != ingest.ErrRunStale {
		t.Errorf("expected ErrRunStale for out-of-order older run, got %v", err)
	}

	// Verify existing finding was NOT overwritten by the stale run
	findings, _ := store.GetFindingsByKeys(ctx, tenantID, []string{"key-1"})
	if f := findings["key-1"]; f.Title != "Vuln 1" {
		t.Errorf("expected finding title to remain 'Vuln 1', got %q", f.Title)
	}

	// 3. Concurrent runs on different scopes (goroutines testing thread-safety with -race)
	done := make(chan bool)
	for i := 0; i < 5; i++ {
		go func(workerID int) {
			workerScope := ingest.CloseScope{
				TenantID:      tenantID,
				ScanSourceID:  sourceID,
				ScannerFamily: "semgrep",
				AssetID:       domain.NewID(), // unique asset per worker
				Track:         "main",
			}
			workerRec := ingest.StagedRecord{
				FindingKey:  domain.NewID().String(),
				RuleID:      "rule-concurrent",
				Title:       "Concurrent Vuln",
				Severity:    domain.SeverityMedium,
				ContentHash: "hash-c",
				SeenAt:      time.Now().UTC(),
			}
			_, _ = engine.MergeBatch(ctx, workerScope, domain.NewID(), appID, []ingest.StagedRecord{workerRec})
			done <- true
		}(i)
	}

	for i := 0; i < 5; i++ {
		<-done
	}
}

func BenchmarkIngestMerge(b *testing.B) {
	ctx := context.Background()
	store := ingest.NewMemoryStore()
	engine := ingest.NewEngine(store)

	tenantID := domain.NewID()
	assetID := domain.NewID()
	appID := domain.NewID()
	sourceID := domain.NewID()
	scope := ingest.CloseScope{
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: "sarif",
		AssetID:       assetID,
		Track:         "main",
	}

	const batchSize = 1000
	records := make([]ingest.StagedRecord, batchSize)
	for i := 0; i < batchSize; i++ {
		records[i] = ingest.StagedRecord{
			FindingKey:  domain.NewID().String(),
			RuleID:      "benchmark-rule",
			Title:       "Benchmark Finding",
			Severity:    domain.SeverityHigh,
			ContentHash: "hash-bench",
			SeenAt:      time.Now().UTC(),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runID := domain.NewID()
		_, err := engine.MergeBatch(ctx, scope, runID, appID, records)
		if err != nil {
			b.Fatalf("benchmark merge failed: %v", err)
		}
	}
}
