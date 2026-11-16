package operator_test

import (
	"context"
	"testing"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/operator"
)

func TestParserCRReconciliation(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	op := operator.NewOperator(store, nil, nil, nil)

	// Set up tenant
	if _, err := op.ReconcileTenant(ctx, &operator.TenantCR{
		Metadata: operator.Metadata{Name: "acme"},
		Spec:     operator.TenantSpec{DisplayName: "Acme", Namespaces: []string{"acme-ns"}},
	}); err != nil {
		t.Fatal(err)
	}

	// Reconcile a declarative CycloneDX 1.6 Parser CR
	parserSpec := map[string]any{
		"version":     "1.6.0",
		"description": "CycloneDX 1.6 Declarative Mapping Parser",
		"family":      "cyclonedx",
		"category":    "sca",
		"detect": map[string]any{
			"filenames": []any{"*cyclonedx*.json", "*.cdx.json", "sbom*.json"},
			"probes": []any{
				map[string]any{"jsonHasKeys": []any{"bomFormat"}},
			},
		},
		"input": map[string]any{
			"format":  "json",
			"records": "$.vulnerabilities[*]",
		},
		"map": map[string]any{
			"ruleId":      "rec.id",
			"title":       "rec.id",
			"description": "rec.description",
			"severity":    "'medium'",
			"vulnIds":     "[rec.id]",
			"location": map[string]any{
				"package": map[string]any{
					"purl": "size(rec.affects) > 0 ? rec.affects[0].ref : ''",
				},
			},
		},
		"limits": map[string]any{
			"maxRecords": 500000,
			"maxDepth":   64,
		},
	}

	st, err := op.ReconcileParser(ctx, &operator.PolicyCR{
		Metadata: operator.Metadata{Name: "cyclonedx-1-6", Namespace: "acme-ns", Generation: 1},
		Spec:     parserSpec,
	})
	if err != nil {
		t.Fatalf("unexpected error reconciling parser: %v", err)
	}
	ready := st.GetCondition("Ready")
	if ready.Status != "True" {
		t.Fatalf("expected Ready=True, got %+v", ready)
	}
	if ready.Reason != "Installed" {
		t.Errorf("expected Reason=Installed, got %q", ready.Reason)
	}

	// Verify tenant packages list includes it
	tn, _ := store.GetTenantByNamespace(ctx, "acme-ns")
	pkgs, ok := any(store).(domain.IntegrationPackages)
	if !ok {
		t.Fatal("store does not support domain.IntegrationPackages")
	}
	list, err := pkgs.ListIntegrationPackages(ctx, tn.ID)
	if err != nil {
		t.Fatalf("failed to list packages: %v", err)
	}
	if len(list) != 1 || list[0].Name != "cyclonedx-1-6" {
		t.Fatalf("expected package cyclonedx-1-6, got %+v", list)
	}
	if list[0].Kind != "parser" || list[0].Runtime != "mapping" || list[0].Version != "1.6.0" {
		t.Errorf("unexpected package record fields: %+v", list[0])
	}
}
