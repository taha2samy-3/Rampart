package operator_test

import (
	"context"
	"strings"
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

func TestClusterParserCRReconciliation(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	op := operator.NewOperator(store, nil, nil, nil)

	clusterParserSpec := map[string]any{
		"version":     "2.1.0",
		"family":      "sarif",
		"category":    "sast",
		"runtime":     "native",
		"native":      "sarif",
		"description": "Cluster-wide native SARIF reader",
	}

	st, err := op.ReconcileClusterParser(ctx, &operator.PolicyCR{
		Metadata: operator.Metadata{Name: "sarif", Generation: 1},
		Spec:     clusterParserSpec,
	})
	if err != nil {
		t.Fatalf("unexpected error reconciling cluster parser: %v", err)
	}
	ready := st.GetCondition("Ready")
	if ready.Status != "True" {
		t.Fatalf("expected Ready=True, got %+v", ready)
	}
	if ready.Reason != "Reconciled" {
		t.Errorf("expected Reason=Reconciled, got %q", ready.Reason)
	}
}

func TestWasmClusterParserStatus(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	op := operator.NewOperator(store, nil, nil, nil)

	wasmSpec := map[string]any{
		"version":  "1.0.0",
		"family":   "custom",
		"category": "sast",
		"runtime":  "wasm",
		"source": map[string]any{
			"oci": "ghcr.io/rampart-aspm/parsers/custom:v1",
		},
	}

	st, err := op.ReconcileClusterParser(ctx, &operator.PolicyCR{
		Metadata: operator.Metadata{Name: "custom", Generation: 1},
		Spec:     wasmSpec,
	})
	if err != nil {
		t.Fatalf("unexpected error reconciling wasm cluster parser: %v", err)
	}

	ready := st.GetCondition("Ready")
	if ready.Status != "True" {
		t.Fatalf("expected Ready=True, got %+v", ready)
	}

	// Nothing pulls source.oci, so the status must not say it was pulled or verified (docs/34 F15).
	synced := st.GetCondition("ArtifactSynced")
	if synced == nil || synced.Status != "Unknown" || synced.Reason != "NotPulled" {
		t.Fatalf("expected ArtifactSynced=Unknown/NotPulled, got %+v", synced)
	}
	if strings.Contains(strings.ToLower(synced.Message), "verified") || synced.Reason == "Pulled" {
		t.Errorf("the status claims a pull or a verification that does not happen: %+v", synced)
	}
}

// A tenant's Parser is data. A script or a module in the server is for the cluster-scoped kinds that the administrator
// installs (docs/34 F14): the namespaced kind is stored with the reason and is not applied.
func TestTenantParserCannotUseCodeRuntimes(t *testing.T) {
	for _, runtime := range []string{"lua", "wasm", "native"} {
		ctx := context.Background()
		store := apply.NewMemoryConfigStore()
		op := operator.NewOperator(store, nil, nil, nil)
		st, err := op.ReconcileParser(ctx, &operator.PolicyCR{
			Metadata: operator.Metadata{Name: "mine", Namespace: "acme-ns", Generation: 1},
			Spec: map[string]any{
				"version": "1.0.0", "family": "mine", "category": "sast", "runtime": runtime, "script": "function parse(i, e) end",
				"source": map[string]any{"oci": "ghcr.io/x/y:v1"}, "native": "sarif",
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", runtime, err)
		}
		if ready := st.GetCondition("Ready"); ready == nil || ready.Status == "True" {
			t.Errorf("a tenant Parser with runtime %s must not be Ready: %+v", runtime, ready)
		}
	}
}
