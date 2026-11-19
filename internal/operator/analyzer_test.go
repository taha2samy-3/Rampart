package operator_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/operator"
)

func analyzerFixture(t *testing.T) (*operator.Operator, *apply.MemoryConfigStore, domain.Tenant) {
	t.Helper()
	store := apply.NewMemoryConfigStore()
	op := operator.NewOperator(store, nil, nil, nil)
	if _, err := op.ReconcileTenant(context.Background(), &operator.TenantCR{
		Metadata: operator.Metadata{Name: "acme"}, Spec: operator.TenantSpec{DisplayName: "Acme", Namespaces: []string{"acme-ns"}},
	}); err != nil {
		t.Fatal(err)
	}
	tn, err := store.GetTenantBySlug(context.Background(), "acme")
	if err != nil || tn == nil {
		t.Fatalf("tenant: %v %v", tn, err)
	}
	return op, store, *tn
}

func TestAllFourAnalyzerKindsAreReconciledAndListed(t *testing.T) {
	ctx := context.Background()
	op, store, tn := analyzerFixture(t)
	svc := map[string]any{"service": map[string]any{"name": "sonatype", "namespace": "tools", "port": 50051}}
	steps := []struct {
		name string
		run  func() (*operator.PolicyStatus, error)
	}{
		{"cluster external", func() (*operator.PolicyStatus, error) {
			return op.ReconcileClusterExternalAnalyzer(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "sonatype", Generation: 1}, Spec: svc})
		}},
		{"tenant external", func() (*operator.PolicyStatus, error) {
			return op.ReconcileExternalAnalyzer(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "mine", Namespace: "acme-ns", Generation: 1}, Spec: svc})
		}},
		{"cluster sbom", func() (*operator.PolicyStatus, error) {
			return op.ReconcileClusterSBOMAnalyzer(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "native-matcher", Generation: 1}, Spec: map[string]any{"engine": "hybrid"}})
		}},
		{"tenant sbom", func() (*operator.PolicyStatus, error) {
			return op.ReconcileSBOMAnalyzer(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "tuned", Namespace: "acme-ns", Generation: 1}, Spec: map[string]any{"engine": "osv", "rules": map[string]any{"minConfidence": 0.9}}})
		}},
	}
	for _, s := range steps {
		st, err := s.run()
		if err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if r := st.GetCondition("Ready"); r.Status != "True" || !strings.Contains(r.Message, "Analyzers tab") {
			t.Errorf("%s: want Ready=True that says where it is listed, got %+v", s.name, r)
		}
	}
	list, err := store.ListAnalyzers(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range list {
		got = append(got, a.Origin+"/"+a.Kind+"/"+a.Namespace+"/"+a.Name)
	}
	want := []string{"cluster/external_analyzer//sonatype", "cluster/sbom_analyzer//native-matcher", "tenant/external_analyzer/acme-ns/mine", "tenant/sbom_analyzer/acme-ns/tuned"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("listed %v, want %v", got, want)
	}
	// another tenant sees the cluster's and none of acme's
	other := domain.NewID()
	list, _ = store.ListAnalyzers(ctx, other)
	if len(list) != 2 || list[0].Origin != "cluster" || list[1].Origin != "cluster" {
		t.Fatalf("a tenant sees the cluster's analyzers and only its own: %+v", list)
	}
}

func TestAnAnalyzerTheServerCannotUseIsRefusedWithItsReason(t *testing.T) {
	ctx := context.Background()
	op, _, _ := analyzerFixture(t)
	for _, c := range []struct {
		name string
		run  func() (*operator.PolicyStatus, error)
		why  string
	}{
		{"http", func() (*operator.PolicyStatus, error) {
			return op.ReconcileClusterExternalAnalyzer(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "h", Generation: 1}, Spec: map[string]any{"protocol": "http", "endpoint": "a:1"}})
		}, "no HTTP client"},
		{"tenant endpoint", func() (*operator.PolicyStatus, error) {
			return op.ReconcileExternalAnalyzer(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "e", Namespace: "acme-ns", Generation: 1}, Spec: map[string]any{"endpoint": "169.254.169.254:80"}})
		}, "not an endpoint"},
		{"no address", func() (*operator.PolicyStatus, error) {
			return op.ReconcileClusterExternalAnalyzer(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "n", Generation: 1}, Spec: map[string]any{}})
		}, "no address"},
		{"engine", func() (*operator.PolicyStatus, error) {
			return op.ReconcileClusterSBOMAnalyzer(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "x", Generation: 1}, Spec: map[string]any{"engine": "magic"}})
		}, "none of hybrid"},
		{"confidence", func() (*operator.PolicyStatus, error) {
			return op.ReconcileSBOMAnalyzer(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "c", Namespace: "acme-ns", Generation: 1}, Spec: map[string]any{"rules": map[string]any{"minConfidence": 2}}})
		}, "outside 0 to 1"},
		{"unknown namespace", func() (*operator.PolicyStatus, error) {
			return op.ReconcileExternalAnalyzer(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "u", Namespace: "nobody-ns", Generation: 1}, Spec: map[string]any{"service": map[string]any{"name": "a", "port": 1}}})
		}, "no tenant lists namespace"},
	} {
		st, err := c.run()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		r := st.GetCondition("Ready")
		if r.Status != "False" || !strings.Contains(r.Message, c.why) {
			t.Errorf("%s: want Ready=False saying %q, got %+v", c.name, c.why, r)
		}
	}
}
