package store_test

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

func appIDOf(t *testing.T, h *uploadHarness, rule string) uuid.UUID {
	t.Helper()
	return findingByRule(t, h, rule).ApplicationID
}

func slugOf(t *testing.T, h *uploadHarness, id uuid.UUID) string {
	t.Helper()
	var slug string
	if err := h.pool.QueryRow(context.Background(), `SELECT slug FROM application WHERE id = $1`, id).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	return slug
}

// Application selectors (D10 step (b), D56): a repository a selector claims lands in that application on its
// first scan; one that was scanned before the selector existed moves out of Unassigned with its findings; an
// asset keeps its application once it has a real one; and the link between an asset and its application is
// stored at all (it was not: the second CreateAsset hit the conflict and dropped it).
func TestSelectors_AttachAssets(t *testing.T) {
	ctx := context.Background()
	h := newUploadHarness(t)
	h.formatHint = "semgrep"
	save := func(slug string, spec domain.ApplicationSpec) {
		t.Helper()
		app, err := spec.ToApplication(domain.NewID(), h.tenant, slug)
		if err != nil {
			t.Fatal(err)
		}
		if existing, _ := h.store.LookupApplication(ctx, h.tenant, slug); existing != nil {
			app.ID = existing.ID
		}
		if err := h.sys.SaveApplication(ctx, app); err != nil {
			t.Fatal(err)
		}
	}
	scan := func(repo, rule string) {
		t.Helper()
		h.waitRun(h.uploadAndComplete(semgrepReport(semgrepResult(rule, "a.go", 3)), domain.UploadContext{Repository: repo, Branch: "main"}))
	}

	// 1. A selector declared before the first scan.
	save("payments", domain.ApplicationSpec{BusinessCriticality: "critical", Selectors: domain.Selectors{
		Repositories: []domain.RepositorySelector{{URL: "https://github.com/acme/payments-*"}}}})
	scan("git@github.com:acme/payments-api.git", "rule.pay")
	if got := slugOf(t, h, appIDOf(t, h, "rule.pay")); got != "payments" {
		t.Fatalf("a repository the selector claims landed in %q", got)
	}
	var linked *uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT application_id FROM asset WHERE tenant_id = $1 AND key = 'https://github.com/acme/payments-api'`, h.tenant).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked == nil || slugOf(t, h, *linked) != "payments" {
		t.Fatalf("the asset's application was not stored: %v", linked)
	}

	// 2. A repository scanned before any selector claims it waits in Unassigned...
	scan("https://github.com/acme/shop", "rule.shop")
	before := findingByRule(t, h, "rule.shop")
	if got := slugOf(t, h, before.ApplicationID); got != "unassigned" {
		t.Fatalf("an unclaimed repository landed in %q", got)
	}
	// ...and moves, with its finding, when a resource claims it; the new application is flagged for a re-score.
	save("shop", domain.ApplicationSpec{BusinessCriticality: "critical", Selectors: domain.Selectors{
		Repositories: []domain.RepositorySelector{{URL: "https://github.com/ACME/shop.git"}}}})
	after := findingByRule(t, h, "rule.shop")
	if got := slugOf(t, h, after.ApplicationID); got != "shop" {
		t.Fatalf("the finding did not move with its asset: %q", got)
	}
	if flagged, _ := h.sys.TenantsNeedingSLARecompute(ctx); !slices.Contains(flagged, h.tenant) {
		t.Fatal("moving findings into an application must flag a re-score")
	}
	if _, err := h.scorer.RecomputeSLA(ctx, h.tenant); err != nil {
		t.Fatal(err)
	}
	if rescored := findingByRule(t, h, "rule.shop"); rescored.RiskScore-before.RiskScore != 100 {
		t.Fatalf("score %d -> %d: a critical application adds 100", before.RiskScore, rescored.RiskScore)
	}

	// 3. An asset in a real application stays there, even when a broader selector appears later.
	save("everything-acme", domain.ApplicationSpec{Selectors: domain.Selectors{
		Repositories: []domain.RepositorySelector{{URL: "https://github.com/acme/*"}}}})
	scan("https://github.com/acme/shop", "rule.shop")
	if got := slugOf(t, h, appIDOf(t, h, "rule.shop")); got != "shop" {
		t.Fatalf("an asset left its application for a broader selector: %q", got)
	}
	// No finding points at an application its asset left (the invariant of D36).
	var orphans int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM finding f JOIN asset a ON a.id = f.asset_id
		WHERE f.tenant_id = $1 AND a.application_id IS NOT NULL AND a.application_id <> f.application_id`, h.tenant).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("findings disagree with their asset's application: %d %v", orphans, err)
	}
}
