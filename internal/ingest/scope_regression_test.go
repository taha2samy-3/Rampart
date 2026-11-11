package ingest_test

import (
	"context"
	"testing"
	"time"

	"rampart/internal/domain"
	"rampart/internal/ingest"
)

func rec(key string) ingest.StagedRecord {
	return ingest.StagedRecord{
		FindingKey: key, Category: domain.CategorySAST, RuleID: "r", Title: key,
		ToolSeverity: "error", Severity: domain.SeverityHigh, ContentHash: "h-" + key,
		Location: domain.Location{Code: &domain.CodeLocation{FilePath: "a.go", StartLine: 1}},
		SeenAt:   time.Now().UTC(),
	}
}

// D13: the close scope is (source, family, asset, track). Scanning asset B must
// not mark asset A's occurrences absent or close A's findings.
func TestCloseStepIsolatedPerAssetAndTrack(t *testing.T) {
	ctx := context.Background()
	store := ingest.NewMemoryStore()
	eng := ingest.NewEngine(store)
	tenant, src, app := domain.NewID(), domain.NewID(), domain.NewID()
	scopeA := ingest.CloseScope{TenantID: tenant, ScanSourceID: src, ScannerFamily: "semgrep", AssetID: domain.NewID(), Track: "main"}
	scopeB := scopeA
	scopeB.AssetID = domain.NewID()

	if _, err := eng.MergeBatch(ctx, scopeA, domain.NewID(), app, []ingest.StagedRecord{rec("a1")}); err != nil {
		t.Fatal(err)
	}
	runB := domain.NewID()
	if _, err := eng.MergeBatch(ctx, scopeB, runB, app, []ingest.StagedRecord{rec("b1")}); err != nil {
		t.Fatal(err)
	}
	closed, err := eng.CloseScopeStep(ctx, scopeB, runB)
	if err != nil || closed != 0 {
		t.Fatalf("closing scope B must close nothing, got %d, %v", closed, err)
	}
	fs, _ := store.GetFindingsByKeys(ctx, tenant, []string{"a1"})
	if fs["a1"].State != domain.StateOpen {
		t.Fatalf("asset A finding must stay open, got %s", fs["a1"].State)
	}
	occs, _ := store.GetActiveScopeOccurrences(ctx, scopeA)
	for _, o := range occs {
		if !o.Present {
			t.Fatal("asset A occurrence flipped to absent by a scan of asset B")
		}
	}
}

// D18: reactivation restores the disposition held before the scanner closed it.
func TestReactivationRestoresPreviousState(t *testing.T) {
	ctx := context.Background()
	store := ingest.NewMemoryStore()
	eng := ingest.NewEngine(store)
	tenant, app := domain.NewID(), domain.NewID()
	scope := ingest.CloseScope{TenantID: tenant, ScanSourceID: domain.NewID(), ScannerFamily: "semgrep", AssetID: domain.NewID(), Track: "main"}

	if _, err := eng.MergeBatch(ctx, scope, domain.NewID(), app, []ingest.StagedRecord{rec("k")}); err != nil {
		t.Fatal(err)
	}
	fs, _ := store.GetFindingsByKeys(ctx, tenant, []string{"k"})
	f := fs["k"]
	f.State = domain.StateAffected // analyst confirmed it
	_ = store.UpsertFindings(ctx, tenant, []*domain.Finding{f})

	empty := domain.NewID()
	if _, err := eng.CloseScopeStep(ctx, scope, empty); err != nil { // rescan without k
		t.Fatal(err)
	}
	out, err := eng.MergeBatch(ctx, scope, domain.NewID(), app, []ingest.StagedRecord{rec("k")})
	if err != nil || out.Reactivated != 1 {
		t.Fatalf("expected 1 reactivated, got %+v, %v", out, err)
	}
	fs, _ = store.GetFindingsByKeys(ctx, tenant, []string{"k"})
	if fs["k"].State != domain.StateAffected {
		t.Fatalf("expected state restored to affected, got %s", fs["k"].State)
	}
}
