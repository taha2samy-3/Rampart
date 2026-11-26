package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
)

func TestTrackers_StoredListedAndEventsIsolated_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	a, b := newAnalyzerTenant(t, ctx, sys), newAnalyzerTenant(t, ctx, sys)

	svc := []byte(`{"service":{"name":"jira-tracker","namespace":"tools","port":50051}}`)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(sys.SaveClusterPolicy(ctx, domain.TrackerKindExternal, apply.PolicyObject{Name: "jira", Spec: svc, Generation: 1}))
	must(sys.SaveTenantPolicy(ctx, a, domain.TrackerKindExternal, apply.PolicyObject{Namespace: "a-ns", Name: "mine", Spec: svc, Generation: 1}))
	must(sys.SaveClusterPolicy(ctx, domain.TrackerKindExternal, apply.PolicyObject{Name: "bad", Spec: []byte(`{"protocol":"http"}`), Error: "protocol must be grpc", Generation: 1}))

	listA, err := appStore.ListTrackers(ctx, a)
	must(err)
	if len(listA) != 3 {
		t.Fatalf("tenant A should see cluster + own + refused cluster = 3 trackers, got %+v", listA)
	}
	listB, err := appStore.ListTrackers(ctx, b)
	must(err)
	if len(listB) != 2 {
		t.Fatalf("tenant B should see only cluster trackers (2), got %+v", listB)
	}

	gotCluster, found, err := appStore.GetTracker(ctx, b, "cluster", "", "jira")
	must(err)
	if !found || gotCluster.Name != "jira" || gotCluster.Origin != "cluster" {
		t.Fatalf("GetTracker cluster mismatch: found=%v obj=%+v", found, gotCluster)
	}
	if _, foundB, _ := appStore.GetTracker(ctx, b, "tenant", "a-ns", "mine"); foundB {
		t.Fatal("tenant B must not read tenant A's tracker")
	}

	must(appStore.RecordTrackerEvent(ctx, a, domain.TrackerEvent{
		Scope: "cluster", Name: "jira", Event: "test", Outcome: "succeeded", Message: "ready",
		Detail: map[string]string{"provider": "jira"}, Duration: 12 * time.Millisecond, Actor: "alice",
	}))
	must(appStore.RecordTrackerEvent(ctx, b, domain.TrackerEvent{
		Scope: "cluster", Name: "jira", Event: "test", Outcome: "failed", Message: "b failure",
	}))

	evsA, err := appStore.ListTrackerEvents(ctx, a, "cluster", "", "jira", 10)
	must(err)
	if len(evsA) != 1 || !strings.Contains(evsA[0].Message, "ready") {
		t.Fatalf("tenant A events mismatch: %+v", evsA)
	}
	evsB, err := appStore.ListTrackerEvents(ctx, b, "cluster", "", "jira", 10)
	must(err)
	if len(evsB) != 1 || evsB[0].Outcome != "failed" {
		t.Fatalf("tenant B events mismatch: %+v", evsB)
	}
}
