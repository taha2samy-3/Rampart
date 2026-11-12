package apply_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/config/apply"
)

func TestApplyDeclarativeResources(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	applier := apply.NewApplier(store)

	// 1. Apply Tenant
	tenantJSON := []byte(`{
		"apiVersion": "rampart.aspm.dev/v1alpha1",
		"kind": "Tenant",
		"metadata": {
			"name": "acme"
		},
		"spec": {
			"displayName": "Acme Corporation",
			"namespaces": ["acme"]
		}
	}`)

	msg, err := applier.ApplyDocument(ctx, tenantJSON)
	if err != nil {
		t.Fatalf("failed to apply tenant: %v", err)
	}
	if !strings.Contains(msg, "tenant.rampart.aspm.dev/acme configured") {
		t.Errorf("unexpected tenant response: %s", msg)
	}

	// 2. Apply Application
	appJSON := []byte(`{
		"apiVersion": "rampart.aspm.dev/v1alpha1",
		"kind": "Application",
		"metadata": {
			"name": "checkout-service",
			"namespace": "acme"
		},
		"spec": {
			"displayName": "Checkout Microservice",
			"businessCriticality": "critical",
			"internetFacing": true
		}
	}`)

	msgApp, err := applier.ApplyDocument(ctx, appJSON)
	if err != nil {
		t.Fatalf("failed to apply application: %v", err)
	}
	if !strings.Contains(msgApp, "checkout-service configured") {
		t.Errorf("unexpected app response: %s", msgApp)
	}

	// 3. Apply ScanSource
	sourceJSON := []byte(`{
		"apiVersion": "rampart.aspm.dev/v1alpha1",
		"kind": "ScanSource",
		"metadata": {
			"name": "ci-semgrep",
			"namespace": "acme"
		},
		"spec": {
			"scannerFamily": "semgrep",
			"type": "reportUpload"
		}
	}`)

	msgSource, err := applier.ApplyDocument(ctx, sourceJSON)
	if err != nil {
		t.Fatalf("failed to apply scan source: %v", err)
	}
	if !strings.Contains(msgSource, "ci-semgrep configured") {
		t.Errorf("unexpected source response: %s", msgSource)
	}
}

func TestApplySLAPolicy(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	applier := apply.NewApplier(store)
	if _, err := applier.ApplyDocument(ctx, []byte(`{"kind":"Tenant","metadata":{"name":"acme"},"spec":{"namespaces":["team-a"]}}`)); err != nil {
		t.Fatal(err)
	}
	tn, _ := store.GetTenantBySlug(ctx, "acme")

	if _, err := applier.ApplyDocument(ctx, []byte(`{"kind":"SLAPolicy","metadata":{"name":"default","namespace":"team-a"},"spec":{"caps":{"maxDays":30}}}`)); err != nil {
		t.Fatalf("a valid policy: %v", err)
	}
	if p, ok := store.SLAPolicy(tn.ID, "team-a", "default"); !ok || p.Error != "" {
		t.Fatalf("stored: %+v %v", p, ok)
	}

	// An invalid one is stored with its reason, and the command fails so a pipeline notices.
	_, err := applier.ApplyDocument(ctx, []byte(`{"kind":"SLAPolicy","metadata":{"name":"default","namespace":"team-a"},"spec":{"startFrom":"verified"}}`))
	if err == nil || !strings.Contains(err.Error(), "not supported yet") {
		t.Fatalf("an invalid policy must fail with its reason, got %v", err)
	}
	if p, _ := store.SLAPolicy(tn.ID, "team-a", "default"); p.Error == "" {
		t.Fatal("the reason must be stored")
	}

	// No tenant owns the namespace.
	if _, err := applier.ApplyDocument(ctx, []byte(`{"kind":"SLAPolicy","metadata":{"name":"x","namespace":"nobody"},"spec":{}}`)); err == nil || !strings.Contains(err.Error(), "TenantNotFound") {
		t.Fatalf("no tenant: %v", err)
	}
}
