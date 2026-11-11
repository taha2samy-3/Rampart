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
