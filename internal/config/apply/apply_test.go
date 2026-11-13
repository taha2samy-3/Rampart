package apply_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
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

func TestApplyScanSource_WithTrustRules(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	applier := apply.NewApplier(store)

	if _, err := applier.ApplyDocument(ctx, []byte(`{"kind":"Tenant","metadata":{"name":"acme"},"spec":{"namespaces":["acme"]}}`)); err != nil {
		t.Fatal(err)
	}
	tn, _ := store.GetTenantBySlug(ctx, "acme")

	// 1. Valid TrustRule with both IDs
	validSource := []byte(`{
		"apiVersion": "rampart.aspm.dev/v1alpha1",
		"kind": "ScanSource",
		"metadata": {"name": "gh-source", "namespace": "acme"},
		"spec": {
			"scannerFamily": "semgrep",
			"type": "reportUpload",
			"trustRules": [
				{
					"issuer": "https://token.actions.githubusercontent.com",
					"provider": "github",
					"repositoryId": "123456",
					"repositoryOwnerId": "654321",
					"repository": "acme/repo"
				}
			]
		}
	}`)
	msg, err := applier.ApplyDocument(ctx, validSource)
	if err != nil {
		t.Fatalf("apply valid scan source with trust rules failed: %v", err)
	}
	if !strings.Contains(msg, "gh-source configured") {
		t.Fatalf("unexpected message: %s", msg)
	}

	rules, err := store.ListTrustRules(ctx, tn.ID)
	if err != nil || len(rules) != 1 {
		t.Fatalf("expected 1 stored trust rule, got %d (err: %v)", len(rules), err)
	}
	if rules[0].Rule.RepositoryID != "123456" || rules[0].Rule.RepositoryOwnerID != "654321" {
		t.Fatalf("unexpected stored rule: %+v", rules[0].Rule)
	}

	// 2. Invalid TrustRule missing repositoryOwnerId is rejected
	invalidSource := []byte(`{
		"apiVersion": "rampart.aspm.dev/v1alpha1",
		"kind": "ScanSource",
		"metadata": {"name": "gh-invalid", "namespace": "acme"},
		"spec": {
			"scannerFamily": "semgrep",
			"type": "reportUpload",
			"trustRules": [
				{
					"issuer": "https://token.actions.githubusercontent.com",
					"provider": "github",
					"repositoryId": "123456"
				}
			]
		}
	}`)
	_, err = applier.ApplyDocument(ctx, invalidSource)
	if err == nil {
		t.Fatal("expected error for trust rule missing repositoryOwnerId, got nil")
	}
	if !strings.Contains(err.Error(), "both repositoryId and repositoryOwnerId") {
		t.Fatalf("unexpected error message: %v", err)
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

func TestApplyIdentityProvider(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	applier := apply.NewApplier(store)

	// Create tenant
	if _, err := applier.ApplyDocument(ctx, []byte(`{"kind":"Tenant","metadata":{"name":"acme"},"spec":{"namespaces":["acme-ns"]}}`)); err != nil {
		t.Fatal(err)
	}
	tn, _ := store.GetTenantBySlug(ctx, "acme")

	// Apply IdentityProvider
	idpYAML := []byte(`{
		"apiVersion": "rampart.aspm.dev/v1alpha1",
		"kind": "IdentityProvider",
		"metadata": {
			"name": "okta-corp",
			"namespace": "acme-ns"
		},
		"spec": {
			"displayName": "Okta Corporate",
			"type": "oidc",
			"login": {
				"emailDomains": ["acme.org"]
			},
			"oidc": {
				"issuer": "https://auth.acme.org",
				"clientId": "client-id-xyz"
			}
		}
	}`)
	msg, err := applier.ApplyDocument(ctx, idpYAML)
	if err != nil {
		t.Fatalf("failed to apply identity provider: %v", err)
	}
	if !strings.Contains(msg, "identityprovider.rampart.aspm.dev/okta-corp configured") {
		t.Errorf("unexpected idp response: %s", msg)
	}

	saved, err := store.GetIdentityProvider(ctx, &tn.ID, "okta-corp")
	if err != nil || saved == nil {
		t.Fatalf("idp not found in store: %v", err)
	}
	if saved.DisplayName != "Okta Corporate" || saved.Spec.OIDC.Issuer != "https://auth.acme.org" {
		t.Errorf("mismatched idp fields: %+v", saved)
	}

	// Apply ClusterIdentityProvider
	clusterIdpYAML := []byte(`{
		"apiVersion": "rampart.aspm.dev/v1alpha1",
		"kind": "ClusterIdentityProvider",
		"metadata": {
			"name": "cluster-github"
		},
		"spec": {
			"displayName": "GitHub Enterprise",
			"type": "oidc",
			"allowedTenants": ["acme"],
			"oidc": {
				"issuer": "https://github.com/login/oauth",
				"clientId": "gh-client-id"
			}
		}
	}`)
	msgCluster, err := applier.ApplyDocument(ctx, clusterIdpYAML)
	if err != nil {
		t.Fatalf("failed to apply cluster identity provider: %v", err)
	}
	if !strings.Contains(msgCluster, "clusteridentityprovider.rampart.aspm.dev/cluster-github configured") {
		t.Errorf("unexpected cluster idp response: %s", msgCluster)
	}

	savedCluster, err := store.GetIdentityProvider(ctx, nil, "cluster-github")
	if err != nil || savedCluster == nil {
		t.Fatalf("cluster idp not found in store: %v", err)
	}
	if !savedCluster.IsTenantAllowed("acme") {
		t.Errorf("acme tenant should be allowed")
	}
}

func TestApplyIdentityProvider_PreservesApprovedDomains(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	applier := apply.NewApplier(store)

	if _, err := applier.ApplyDocument(ctx, []byte(`{"kind":"Tenant","metadata":{"name":"acme"},"spec":{"namespaces":["acme-ns"]}}`)); err != nil {
		t.Fatal(err)
	}
	tn, _ := store.GetTenantBySlug(ctx, "acme")

	// 1. Initial apply
	initialYAML := []byte(`{
		"apiVersion": "rampart.aspm.dev/v1alpha1",
		"kind": "IdentityProvider",
		"metadata": {"name": "okta", "namespace": "acme-ns"},
		"spec": {
			"type": "oidc",
			"login": {"emailDomains": ["acme.org"]},
			"oidc": {"issuer": "https://auth.acme.org", "clientId": "id1"}
		}
	}`)
	if _, err := applier.ApplyDocument(ctx, initialYAML); err != nil {
		t.Fatal(err)
	}

	// 2. Approve acme.org domain
	idp, err := store.GetIdentityProvider(ctx, &tn.ID, "okta")
	if err != nil || idp == nil {
		t.Fatal(err)
	}
	idp.Status.Domains[0].Approved = true
	_ = store.SaveIdentityProvider(ctx, &tn.ID, *idp)

	// 3. Re-apply with additional domain "subsidiary.com"
	updateYAML := []byte(`{
		"apiVersion": "rampart.aspm.dev/v1alpha1",
		"kind": "IdentityProvider",
		"metadata": {"name": "okta", "namespace": "acme-ns"},
		"spec": {
			"displayName": "Okta v2",
			"type": "oidc",
			"login": {"emailDomains": ["acme.org", "subsidiary.com"]},
			"oidc": {"issuer": "https://auth.acme.org", "clientId": "id1"}
		}
	}`)
	if _, err := applier.ApplyDocument(ctx, updateYAML); err != nil {
		t.Fatal(err)
	}

	// 4. Verify acme.org is still approved, and subsidiary.com is unapproved
	updated, err := store.GetIdentityProvider(ctx, &tn.ID, "okta")
	if err != nil || updated == nil {
		t.Fatal(err)
	}
	if updated.DisplayName != "Okta v2" {
		t.Errorf("expected updated display name, got %s", updated.DisplayName)
	}
	if len(updated.Status.Domains) != 2 {
		t.Fatalf("expected 2 domains, got %+v", updated.Status.Domains)
	}
	for _, d := range updated.Status.Domains {
		if d.Domain == "acme.org" && !d.Approved {
			t.Errorf("acme.org approval must NOT be overwritten on re-apply (D27)")
		}
		if d.Domain == "subsidiary.com" && d.Approved {
			t.Errorf("new domain subsidiary.com must start as unapproved")
		}
	}
}

func TestApply_Connector(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	applier := apply.NewApplier(store)

	if _, err := applier.ApplyDocument(ctx, []byte(`{"kind":"Tenant","metadata":{"name":"acme"},"spec":{"namespaces":["acme-ns"]}}`)); err != nil {
		t.Fatal(err)
	}
	tn, _ := store.GetTenantBySlug(ctx, "acme")

	// 1. Apply Jira connector
	jiraYAML := []byte(`{
		"apiVersion": "rampart.aspm.dev/v1alpha1",
		"kind": "Connector",
		"metadata": {"name": "jira-sec", "namespace": "acme-ns"},
		"spec": {
			"type": "jira",
			"jira": {
				"url": "https://acme.atlassian.net",
				"credentialsSecretRef": {"name": "jira-creds", "key": "token"},
				"defaultProject": "SEC",
				"issueType": "Bug"
			}
		}
	}`)
	msg, err := applier.ApplyDocument(ctx, jiraYAML)
	if err != nil {
		t.Fatalf("unexpected error applying connector: %v", err)
	}
	if !strings.Contains(msg, "connector.rampart.aspm.dev/jira-sec configured") {
		t.Errorf("unexpected success message: %s", msg)
	}

	conn, err := store.GetConnector(ctx, tn.ID, "jira-sec")
	if err != nil || conn == nil {
		t.Fatalf("expected connector in store, got err: %v, conn: %v", err, conn)
	}
	if conn.Type != domain.ConnectorTypeJira || conn.Spec.Jira.DefaultProject != "SEC" {
		t.Errorf("unexpected connector in store: %+v", conn)
	}
	if conn.Status.WebhookURL != "/hooks/jira/jira-sec" {
		t.Errorf("unexpected status webhook URL: %s", conn.Status.WebhookURL)
	}
}
