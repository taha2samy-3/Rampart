package apply_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
)

func TestApplyAnalyzersOfAllFourKinds(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	ap := apply.NewApplier(store)
	if _, err := ap.ApplyDocument(ctx, []byte(`{"apiVersion":"rampart.aspm.dev/v1alpha1","kind":"Tenant","metadata":{"name":"acme"},"spec":{"displayName":"Acme","namespaces":["acme-ns"]}}`)); err != nil {
		t.Fatal(err)
	}
	tn, _ := store.GetTenantBySlug(ctx, "acme")
	docs := map[string]string{
		"clusterexternalanalyzer": "kind: ClusterExternalAnalyzer\nmetadata: {name: sonatype}\nspec: {service: {name: sonatype, namespace: tools, port: 50051}}",
		"externalanalyzer":        "kind: ExternalAnalyzer\nmetadata: {name: mine, namespace: acme-ns}\nspec: {service: {name: mine, port: 50051}}",
		"clustersbomanalyzer":     "kind: ClusterSBOMAnalyzer\nmetadata: {name: native-matcher}\nspec: {engine: hybrid}",
		"sbomanalyzer":            "kind: SBOMAnalyzer\nmetadata: {name: tuned, namespace: acme-ns}\nspec: {engine: osv}",
	}
	for k, d := range docs {
		out, err := ap.ApplyDocument(ctx, []byte("apiVersion: rampart.aspm.dev/v1alpha1\n"+d))
		if err != nil || !strings.HasPrefix(out, k+".rampart.aspm.dev/") {
			t.Fatalf("%s: %q %v", k, out, err)
		}
	}
	list, _ := store.ListAnalyzers(ctx, tn.ID)
	if len(list) != 4 {
		t.Fatalf("four analyzers are stored: %+v", list)
	}
	for _, a := range list {
		if a.Error != "" || (a.Kind != domain.AnalyzerKindExternal && a.Kind != domain.AnalyzerKindSBOM) {
			t.Errorf("stored wrongly: %+v", a)
		}
	}
}

func TestApplyRefusesAnAnalyzerTheServerCannotUseAndStoresItWithTheReason(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	ap := apply.NewApplier(store)
	_, _ = ap.ApplyDocument(ctx, []byte(`{"apiVersion":"rampart.aspm.dev/v1alpha1","kind":"Tenant","metadata":{"name":"acme"},"spec":{"displayName":"Acme","namespaces":["acme-ns"]}}`))
	tn, _ := store.GetTenantBySlug(ctx, "acme")
	for _, d := range []string{
		"kind: ExternalAnalyzer\nmetadata: {name: ssrf, namespace: acme-ns}\nspec: {endpoint: '169.254.169.254:80'}",
		"kind: ClusterExternalAnalyzer\nmetadata: {name: web}\nspec: {protocol: http, endpoint: 'a:1'}",
		"kind: ClusterSBOMAnalyzer\nmetadata: {name: bad}\nspec: {engine: magic}",
		"kind: ExternalAnalyzer\nmetadata: {name: elsewhere, namespace: acme-ns}\nspec: {service: {name: a, namespace: rampart-system, port: 1}}",
	} {
		if _, err := ap.ApplyDocument(ctx, []byte("apiVersion: rampart.aspm.dev/v1alpha1\n"+d)); err == nil || !strings.Contains(err.Error(), "not applied") {
			t.Errorf("a refused analyzer must be reported as stored and not applied, got %v for %s", err, d)
		}
	}
	list, _ := store.ListAnalyzers(ctx, tn.ID)
	if len(list) != 4 {
		t.Fatalf("a refused analyzer is still listed, so the screen can say why: %+v", list)
	}
	for _, a := range list {
		if a.Error == "" {
			t.Errorf("%s was stored as valid", a.Name)
		}
	}
}
