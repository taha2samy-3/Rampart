package store_test

import (
	"context"
	"testing"

	"rampart/internal/domain"
)

func TestHierarchyAndRollup(t *testing.T) {
	ctx := context.Background()
	h := newUploadHarness(t)

	// 1. Ensure hierarchy path: ["fintech", "payments"]
	leaf, err := h.store.EnsureHierarchyPath(ctx, h.tenant, []string{"fintech", "payments"})
	if err != nil {
		t.Fatalf("EnsureHierarchyPath failed: %v", err)
	}
	if leaf == nil || leaf.Path != "fintech.payments" {
		t.Fatalf("unexpected leaf node: %+v", leaf)
	}

	// 2. List hierarchy nodes: should contain fintech and fintech.payments
	nodes, err := h.store.ListHierarchyNodes(ctx, h.tenant)
	if err != nil {
		t.Fatalf("ListHierarchyNodes failed: %v", err)
	}
	if len(nodes) < 2 {
		t.Fatalf("expected at least 2 hierarchy nodes, got %d", len(nodes))
	}

	// 3. Save application attached to hierarchy path
	app := domain.Application{
		ID:                  domain.NewID(),
		TenantID:            h.tenant,
		Slug:                "payments-service",
		Name:                "Payments Service",
		BusinessCriticality: "high",
		HierarchyNodeID:     &leaf.ID,
		HierarchyPath:       leaf.Path,
		Selectors: domain.Selectors{
			Repositories: []domain.RepositorySelector{{URL: "github.com/acme/payments"}},
		},
	}
	if err := h.store.SaveApplication(ctx, app); err != nil {
		t.Fatalf("SaveApplication failed: %v", err)
	}

	// 4. Upload findings for the application
	h.formatHint = "semgrep"
	h.waitRun(h.uploadAndComplete(semgrepReport(semgrepResult("rule.sqli", "main.go", 10)), domain.UploadContext{
		Repository: "github.com/acme/payments",
		Branch:     "main",
	}))

	// 5. HierarchyRollups should aggregate findings under fintech and fintech.payments
	rollups, err := h.store.HierarchyRollups(ctx, h.tenant)
	if err != nil {
		t.Fatalf("HierarchyRollups failed: %v", err)
	}
	if len(rollups) < 2 {
		t.Fatalf("expected at least 2 rollups, got %d", len(rollups))
	}

	var paymentsRollup *domain.HierarchyRollup
	for i := range rollups {
		if rollups[i].Path == "fintech.payments" {
			paymentsRollup = &rollups[i]
			break
		}
	}
	if paymentsRollup == nil {
		t.Fatal("fintech.payments rollup not found")
	}
	if paymentsRollup.AppCount < 1 {
		t.Fatalf("expected app_count >= 1, got %d", paymentsRollup.AppCount)
	}
	totalOpen := paymentsRollup.Open["critical"] + paymentsRollup.Open["high"] + paymentsRollup.Open["medium"] + paymentsRollup.Open["low"]
	if totalOpen < 1 {
		t.Fatalf("expected open findings in rollup, got %+v", paymentsRollup.Open)
	}
	if paymentsRollup.PostureScore <= 0 || paymentsRollup.PostureScore > 1000 {
		t.Fatalf("posture score out of bounds: %d", paymentsRollup.PostureScore)
	}
}
