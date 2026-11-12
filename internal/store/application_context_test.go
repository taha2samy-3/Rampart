package store_test

import (
	"context"
	"slices"
	"testing"

	"rampart/internal/domain"
)

// The Application resource, written as rampart_system like the operator writes it, is the truth for the context the score uses (D55): a change to criticality or data
// classification reaches the stored score of existing findings; a rescan never overwrites it; a row made in the
// UI is never touched; an application ingest created is adopted by a resource of the same name.
func TestApplicationContext_ReachesTheScore(t *testing.T) {
	ctx := context.Background()
	h := newUploadHarness(t)
	h.formatHint = "semgrep"
	repo := domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main"}
	h.waitRun(h.uploadAndComplete(semgrepReport(semgrepResult("rule.a", "a.go", 3)), repo))

	f := findingByRule(t, h, "rule.a")
	var slug, managedBy string
	if err := h.pool.QueryRow(ctx, `SELECT slug, managed_by FROM application WHERE id = $1`, f.ApplicationID).Scan(&slug, &managedBy); err != nil {
		t.Fatal(err)
	}
	if managedBy != "none" {
		t.Fatalf("an application made by ingest must be unmanaged, so a resource can adopt it: %q", managedBy)
	}
	before := f.RiskScore

	// The resource raises criticality and declares personal data.
	app, err := domain.ApplicationSpec{BusinessCriticality: "critical", DataClassification: []string{"pii"}, CompensatingControls: []string{"waf"}}.
		ToApplication(f.ApplicationID, h.tenant, slug)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.sys.SaveApplication(ctx, app); err != nil {
		t.Fatal(err)
	}
	stored, err := h.store.GetApplication(ctx, h.tenant, f.ApplicationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.BusinessCriticality != "critical" || !slices.Equal(stored.DataClassification, []string{"pii"}) || !slices.Equal(stored.CompensatingControls, []string{"waf"}) {
		t.Fatalf("the resource was not stored: %+v", stored)
	}
	if err := h.pool.QueryRow(ctx, `SELECT managed_by FROM application WHERE id = $1`, f.ApplicationID).Scan(&managedBy); err != nil || managedBy != "crd" {
		t.Fatalf("not adopted: %q %v", managedBy, err)
	}

	// The change flags the tenant, and the recompute moves the stored score: +100 critical (was medium, 0) and +80 pii.
	flagged, err := h.sys.TenantsNeedingSLARecompute(ctx)
	if err != nil || !slices.Contains(flagged, h.tenant) {
		t.Fatalf("the tenant was not flagged for a recompute: %v %v", flagged, err)
	}
	if _, err := h.scorer.RecomputeSLA(ctx, h.tenant); err != nil {
		t.Fatal(err)
	}
	after := findingByRule(t, h, "rule.a").RiskScore
	if after-before != 180 {
		t.Fatalf("stored score %d -> %d, want +180 (critical +100, personal data +80; the WAF does not count on SAST)", before, after)
	}

	// A rescan does not undo what the resource set.
	h.waitRun(h.uploadAndComplete(semgrepReport(semgrepResult("rule.a", "a.go", 3)), repo))
	if again, _ := h.store.GetApplication(ctx, h.tenant, f.ApplicationID); again.BusinessCriticality != "critical" {
		t.Fatalf("a rescan overwrote the criticality: %q", again.BusinessCriticality)
	}

	// The same values again flag nothing.
	if err := h.store.ClearSLARecompute(ctx, h.tenant); err != nil {
		t.Fatal(err)
	}
	if err := h.sys.SaveApplication(ctx, app); err != nil {
		t.Fatal(err)
	}
	if flagged, _ := h.sys.TenantsNeedingSLARecompute(ctx); slices.Contains(flagged, h.tenant) {
		t.Fatal("an unchanged resource flagged a recompute")
	}

	// A row the UI owns is not touched by a resource.
	mustExec(t, h.pool, `UPDATE application SET managed_by = 'ui' WHERE id = $1`, f.ApplicationID)
	low := app
	low.BusinessCriticality = "low"
	if err := h.sys.SaveApplication(ctx, low); err != nil {
		t.Fatal(err)
	}
	if again, _ := h.store.GetApplication(ctx, h.tenant, f.ApplicationID); again.BusinessCriticality != "critical" {
		t.Fatalf("a resource changed a UI application: %q", again.BusinessCriticality)
	}
}
