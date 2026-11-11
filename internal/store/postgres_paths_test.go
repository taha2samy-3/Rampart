package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// Exercises store paths the main RLS test does not: close persistence,
// scope/result recording, ordering check and future-dated events.
func TestPostgresStore_CloseScopeAndRunBookkeeping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, sys := setupStores(t, ctx)

	tn := &domain.Tenant{ID: uuid.New(), Slug: "paths-" + uuid.NewString()[:8], DisplayName: "P"}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	app := &domain.Application{ID: uuid.New(), TenantID: tn.ID, Slug: "a", Name: "A", BusinessCriticality: "high", Lifecycle: "production"}
	if err := s.CreateApplication(ctx, app); err != nil {
		t.Fatal(err)
	}
	asset := &domain.Asset{ID: uuid.New(), TenantID: tn.ID, ApplicationID: &app.ID, Type: domain.AssetRepository, Key: "r", Active: true}
	if err := s.CreateAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	src := uuid.New()
	now := time.Now().UTC()
	// No store API creates scan_source yet; insert it under the tenant context.
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tn.ID.String())
	if _, err := tx.Exec(ctx, `INSERT INTO scan_source (id, tenant_id, name, type, scanner_family) VALUES ($1,$2,'s','upload','semgrep')`, src, tn.ID); err != nil {
		t.Fatalf("scan_source: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	run := &domain.IngestRun{ID: uuid.New(), TenantID: tn.ID, ScanSourceID: src, ApplicationID: app.ID, AssetID: asset.ID,
		Track: "main", ScannerFamily: "semgrep", Format: "sarif", Status: domain.RunCompleted, ScanFinished: now}

	t.Run("CreateIngestRun", func(t *testing.T) {
		// ingest_run.scan_source_id references scan_source; no API creates one yet.
		if err := s.CreateIngestRun(ctx, run); err != nil {
			t.Fatalf("CreateIngestRun: %v", err)
		}
	})

	t.Run("RecordRunScope", func(t *testing.T) {
		sc := &domain.IngestRunScope{IngestRunID: run.ID, TenantID: tn.ID, ScanSourceID: src, ScannerFamily: "semgrep", AssetID: asset.ID, Track: "main"}
		if err := s.RecordRunScope(ctx, sc); err != nil {
			t.Fatalf("RecordRunScope: %v", err)
		}
		if err := s.RecordRunScope(ctx, sc); err != nil { // idempotent
			t.Fatalf("RecordRunScope twice: %v", err)
		}
	})

	t.Run("RecordRunResult", func(t *testing.T) {
		r := &domain.IngestRunResult{TenantID: tn.ID, IngestRunID: run.ID, FindingKey: "k", Severity: domain.SeverityHigh, Category: domain.CategorySAST}
		if err := s.RecordRunResult(ctx, r); err != nil {
			t.Fatalf("RecordRunResult: %v", err)
		}
	})

	t.Run("CheckScopeOrdering detects stale runs under RLS", func(t *testing.T) {
		scope := store.CloseScope{TenantID: tn.ID, ScanSourceID: src, ScannerFamily: "semgrep", AssetID: asset.ID, Track: "main"}
		stale, err := s.CheckScopeOrdering(scope, now.Add(-time.Hour))
		if err != nil || !stale {
			t.Fatalf("older scan must be stale, got stale=%v err=%v", stale, err)
		}
		stale, _ = s.CheckScopeOrdering(scope, now.Add(time.Hour))
		if stale {
			t.Fatal("newer scan must not be stale")
		}
	})

	f := &domain.Finding{ID: uuid.New(), TenantID: tn.ID, FindingKey: "fk", DedupScope: "asset", AssetID: asset.ID, ApplicationID: app.ID,
		Track: "main", Category: domain.CategorySAST, RuleScannerFamily: "semgrep", RuleID: "r", Title: "t", Severity: domain.SeverityHigh,
		ToolSeverity: "error", State: domain.StateOpen, Detection: domain.DetectionPresent, ContentHash: "h", FirstSeen: now, LastSeen: now,
		ReopenedCount: 2, OccurrenceCount: 1, Version: 1}

	t.Run("close persists resolution and keeps reopened_count", func(t *testing.T) {
		if err := s.UpsertFindings(ctx, tn.ID, []*domain.Finding{f}); err != nil {
			t.Fatal(err)
		}
		active, err := s.GetActiveScopeFindings(ctx, tn.ID, asset.ID, "main")
		if err != nil || len(active) != 1 {
			t.Fatalf("active: %v %v", len(active), err)
		}
		c := active[0]
		res, at := domain.ResolutionFixed, time.Now().UTC()
		c.PreviousState, c.State, c.Detection, c.Resolution, c.ResolvedAt = c.State, domain.StateFixed, domain.DetectionAbsent, &res, &at
		if err := s.UpsertFindings(ctx, tn.ID, []*domain.Finding{c}); err != nil {
			t.Fatal(err)
		}
		got, _, err := s.GetFinding(ctx, tn.ID, f.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Resolution == nil || got.ResolvedAt == nil {
			t.Errorf("resolution/resolved_at not persisted: %v %v", got.Resolution, got.ResolvedAt)
		}
		if got.ReopenedCount != 2 {
			t.Errorf("reopened_count reset by close: got %d want 2", got.ReopenedCount)
		}
		if got.PreviousState != domain.StateOpen {
			t.Errorf("previous_state: got %q", got.PreviousState)
		}
	})

	t.Run("finding_event accepts a date beyond the first partition", func(t *testing.T) {
		ev := &domain.FindingEvent{FindingID: f.ID, At: time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC), Actor: "system:parser", Type: "created"}
		if err := s.RecordFindingEvents(ctx, tn.ID, []*domain.FindingEvent{ev}); err != nil {
			t.Fatalf("event in 2027: %v", err)
		}
	})
}
