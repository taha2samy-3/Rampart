package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// D102: a tenant's ComplianceFramework is stored in policy_object (kind compliance) and seen only by its tenant
// (RLS); a ClusterComplianceFramework is stored in cluster_policy and seen by every tenant; a refused edit keeps
// the last valid spec and reports why; the frameworks never ask for an SLA recompute.
func TestComplianceFrameworkStorage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sysStore := setupStores(t, ctx)
	suffix := uuid.NewString()[:8]
	tenantA := &domain.Tenant{ID: uuid.New(), Slug: "cf-a-" + suffix, DisplayName: "A", CreatedAt: time.Now().UTC()}
	tenantB := &domain.Tenant{ID: uuid.New(), Slug: "cf-b-" + suffix, DisplayName: "B", CreatedAt: time.Now().UTC()}
	for _, tn := range []*domain.Tenant{tenantA, tenantB} {
		if err := sysStore.CreateTenant(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}

	valid := []byte(`{"displayName": "ACME", "version": "1", "controls": [{"id": "C-1", "name": "n", "manual": true}]}`)
	edited := []byte(`{"displayName": "ACME", "version": "2", "controls": []}`)
	if err := sysStore.SaveTenantPolicy(ctx, tenantA.ID, "compliance", apply.PolicyObject{Namespace: "ns-a", Name: "acme", Spec: valid, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	if err := sysStore.SaveTenantPolicy(ctx, tenantA.ID, "compliance", apply.PolicyObject{Namespace: "ns-a", Name: "acme", Spec: edited, Generation: 2, Error: "a framework needs at least one control"}); err != nil {
		t.Fatal(err)
	}
	neverValid := apply.PolicyObject{Namespace: "ns-a", Name: "broken", Spec: edited, Generation: 1, Error: "refused"}
	if err := sysStore.SaveTenantPolicy(ctx, tenantA.ID, "compliance", neverValid); err != nil {
		t.Fatal(err)
	}
	clusterName := "cf-cluster-" + suffix
	if err := sysStore.SaveClusterPolicy(ctx, "compliance", apply.PolicyObject{Name: clusterName, Spec: valid, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sysStore.DeleteClusterPolicy(context.Background(), "compliance", clusterName) })

	// Only this test's rows: other tests may have stored cluster frameworks in the shared database.
	mine := func(tenant uuid.UUID) []store.StoredFramework {
		t.Helper()
		all, err := appStore.ListComplianceFrameworks(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		var out []store.StoredFramework
		for _, f := range all {
			if f.Origin == "tenant" || f.Name == clusterName {
				out = append(out, f)
			}
		}
		return out
	}
	gotA := mine(tenantA.ID)
	if len(gotA) != 3 {
		t.Fatalf("tenant A sees %d frameworks, want 3: %+v", len(gotA), gotA)
	}
	cl, acme, broken := gotA[0], gotA[1], gotA[2] // origin, then name
	if cl.Origin != "cluster" || cl.Name != clusterName || cl.Error != "" || len(cl.Spec) == 0 {
		t.Fatalf("cluster framework: %+v", cl)
	}
	if acme.Origin != "tenant" || acme.Name != "acme" || acme.Error != "a framework needs at least one control" {
		t.Fatalf("refused edit: %+v", acme)
	}
	var inForce struct{ Version string }
	if err := json.Unmarshal(acme.Spec, &inForce); err != nil || inForce.Version != "1" {
		t.Fatalf("the last valid spec must stay in force, got %s", acme.Spec)
	}
	if broken.Name != "broken" || broken.Spec != nil || broken.Error != "refused" {
		t.Fatalf("never-valid framework: %+v", broken)
	}
	if acme.UpdatedAt.IsZero() {
		t.Fatal("updated_at is not read")
	}

	gotB := mine(tenantB.ID)
	if len(gotB) != 1 || gotB[0].Origin != "cluster" || gotB[0].Name != clusterName {
		t.Fatalf("tenant B must see only the cluster framework: %+v", gotB)
	}

	// A framework moves no score.
	flagged, err := sysStore.TenantsNeedingSLARecompute(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(flagged, tenantA.ID) {
		t.Fatal("a compliance framework must not ask for an SLA recompute")
	}

	if err := sysStore.DeleteTenantPolicy(ctx, tenantA.ID, "compliance", "ns-a", "acme"); err != nil {
		t.Fatal(err)
	}
	if got := mine(tenantA.ID); len(got) != 2 || got[1].Name != "broken" {
		t.Fatalf("after delete: %+v", got)
	}
	if err := sysStore.DeleteClusterPolicy(ctx, "compliance", clusterName); err != nil {
		t.Fatal(err)
	}
	if got := mine(tenantB.ID); len(got) != 0 {
		t.Fatalf("after deleting the cluster framework: %+v", got)
	}
}

// D102: Application.complianceScope is saved from the resource and read back for every application of the tenant.
func TestApplicationComplianceScopes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sysStore := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "cs-" + uuid.NewString()[:8], DisplayName: "CS", CreatedAt: time.Now().UTC()}
	if err := sysStore.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	other := &domain.Tenant{ID: uuid.New(), Slug: "cs-o-" + uuid.NewString()[:8], DisplayName: "Other", CreatedAt: time.Now().UTC()}
	if err := sysStore.CreateTenant(ctx, other); err != nil {
		t.Fatal(err)
	}
	mk := func(tenant uuid.UUID, slug string, scopes []string) domain.Application {
		app, err := domain.ApplicationSpec{ComplianceScope: scopes}.ToApplication(uuid.New(), tenant, slug)
		if err != nil {
			t.Fatal(err)
		}
		if err := appStore.SaveApplication(ctx, app); err != nil {
			t.Fatal(err)
		}
		return app
	}
	pay := mk(tn.ID, "payments", []string{"pci", "sox"})
	blog := mk(tn.ID, "blog", nil)
	mk(other.ID, "elsewhere", []string{"pci"})

	got, err := appStore.ApplicationComplianceScopes(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || fmt.Sprint(got[pay.ID]) != "[pci sox]" || got[blog.ID] == nil || len(got[blog.ID]) != 0 {
		t.Fatalf("scopes: %v", got)
	}

	// An edit of the resource replaces the scopes; the row reads them back.
	pay.ComplianceScope = []string{"iso:27001"}
	if err := appStore.SaveApplication(ctx, pay); err != nil {
		t.Fatal(err)
	}
	read, err := appStore.GetApplicationBySlug(ctx, tn.ID, "payments")
	if err != nil || read == nil || fmt.Sprint(read.ComplianceScope) != "[iso:27001]" {
		t.Fatalf("read back: %+v %v", read, err)
	}
}
