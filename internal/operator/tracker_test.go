package operator_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/operator"
)

func TestExternalTrackers_ReconciledListedAndIsolated(t *testing.T) {
	ctx := context.Background()
	op, store, tn := analyzerFixture(t)
	svc := map[string]any{"service": map[string]any{"name": "jira-tracker", "namespace": "tools", "port": 50051}}

	stCluster, err := op.ReconcileClusterExternalTracker(ctx, &operator.PolicyCR{
		Metadata: operator.Metadata{Name: "jira", Generation: 1},
		Spec:     svc,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := stCluster.GetCondition("Ready"); r == nil || r.Status != "True" || !strings.Contains(r.Message, "Ticketing tab") {
		t.Fatalf("expected Ready=True mentioning Ticketing tab, got %+v", r)
	}

	// A namespaced tracker may name a Service only in its own namespace.
	stOther, err := op.ReconcileExternalTracker(ctx, &operator.PolicyCR{
		Metadata: operator.Metadata{Name: "other-ns", Namespace: "acme-ns", Generation: 1},
		Spec:     svc,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := stOther.GetCondition("Ready"); r == nil || r.Status != "False" || !strings.Contains(r.Message, "own namespace") {
		t.Fatalf("expected refusal of a Service in another namespace, got %+v", r)
	}

	stTenant, err := op.ReconcileExternalTracker(ctx, &operator.PolicyCR{
		Metadata: operator.Metadata{Name: "mine", Namespace: "acme-ns", Generation: 1},
		Spec:     map[string]any{"service": map[string]any{"name": "jira-tracker", "namespace": "acme-ns", "port": 50051}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := stTenant.GetCondition("Ready"); r == nil || r.Status != "True" {
		t.Fatalf("expected Ready=True for tenant tracker, got %+v", r)
	}

	// SSRF safeguard: namespaced ExternalTracker rejecting raw endpoint
	stBad, err := op.ReconcileExternalTracker(ctx, &operator.PolicyCR{
		Metadata: operator.Metadata{Name: "ssrf", Namespace: "acme-ns", Generation: 1},
		Spec:     map[string]any{"endpoint": "169.254.169.254:50051"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := stBad.GetCondition("Ready"); r == nil || r.Status != "False" || r.Reason != "InvalidSpec" {
		t.Fatalf("expected InvalidSpec refusal for tenant raw endpoint, got %+v", r)
	}

	list, err := store.ListTrackers(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 4 {
		t.Fatalf("expected 4 tracker records (1 cluster + 1 valid tenant + 2 refused tenant), got %d", len(list))
	}

	other := domain.NewID()
	otherList, _ := store.ListTrackers(ctx, other)
	if len(otherList) != 1 || otherList[0].Origin != "cluster" || otherList[0].Name != "jira" {
		t.Fatalf("another tenant must only see cluster tracker, got %+v", otherList)
	}
}
