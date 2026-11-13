package operator_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/operator"
	"rampart/internal/secrets"
)

type memorySecretStore struct {
	secrets map[string][]byte
}

func newMemorySecretStore() *memorySecretStore {
	return &memorySecretStore{secrets: make(map[string][]byte)}
}

func (m *memorySecretStore) SaveSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string, encryptedValue []byte) error {
	k := tenantID.String() + ":" + key
	m.secrets[k] = encryptedValue
	return nil
}

func TestTenantReconciler(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	op := operator.NewOperator(store, nil, nil, nil)

	cr := &operator.TenantCR{
		Metadata: operator.Metadata{Name: "acme-corp", Generation: 1},
		Spec: operator.TenantSpec{
			DisplayName: "Acme Corporation",
		},
	}

	status, err := op.ReconcileTenant(ctx, cr)
	if err != nil {
		t.Fatalf("ReconcileTenant failed: %v", err)
	}

	if status.TenantID == "" {
		t.Errorf("expected tenantId to be populated")
	}

	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "True" || cond.Reason != "Reconciled" {
		t.Errorf("expected Ready condition True/Reconciled, got %+v", cond)
	}

	// Verify in store
	saved, err := store.GetTenantBySlug(ctx, "acme-corp")
	if err != nil || saved == nil {
		t.Fatalf("tenant not found in store: %v", err)
	}
	if saved.DisplayName != "Acme Corporation" {
		t.Errorf("expected display name Acme Corporation, got %s", saved.DisplayName)
	}
}

func TestApplicationReconciler_MissingTenant(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	op := operator.NewOperator(store, nil, nil, nil)

	appCR := &operator.ApplicationCR{
		Metadata: operator.Metadata{Name: "payments-api", Namespace: "non-existent-tenant"},
		Spec: operator.ApplicationSpec{
			DisplayName: "Payments API",
		},
	}

	status, err := op.ReconcileApplication(ctx, appCR)
	if err != nil {
		t.Fatalf("unexpected error on missing tenant reconciliation: %v", err)
	}

	// D17 line 331: A namespaced CR in a namespace that has no Tenant gets Ready=False, reason TenantNotFound
	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "False" || cond.Reason != "TenantNotFound" {
		t.Errorf("expected Ready=False/TenantNotFound, got %+v", cond)
	}
}

func TestApplicationReconciler_Success(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	op := operator.NewOperator(store, nil, nil, nil)

	// First create tenant
	tenantCR := &operator.TenantCR{
		Metadata: operator.Metadata{Name: "fintech"},
		Spec:     operator.TenantSpec{DisplayName: "Fintech Tenant", Namespaces: []string{"fintech"}},
	}
	_, _ = op.ReconcileTenant(ctx, tenantCR)

	// Now reconcile application in that tenant
	appCR := &operator.ApplicationCR{
		Metadata: operator.Metadata{Name: "core-ledger", Namespace: "fintech", Generation: 2},
		Spec: operator.ApplicationSpec{
			DisplayName:         "Core Ledger Service",
			BusinessCriticality: "critical",
			InternetFacing:      false,
			Owners:              []string{"ledger-team@internal"},
		},
	}

	status, err := op.ReconcileApplication(ctx, appCR)
	if err != nil {
		t.Fatalf("ReconcileApplication failed: %v", err)
	}

	if status.ApplicationID == "" {
		t.Errorf("expected applicationId in status")
	}

	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "True" || cond.Reason != "Reconciled" {
		t.Errorf("expected Ready=True/Reconciled, got %+v", cond)
	}
}

func TestScanSourceReconciler_SecretSync(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	mockSecrets := operator.NewMockSecretProvider()
	secStore := newMemorySecretStore()
	op := operator.NewOperator(store, mockSecrets, secStore, nil)

	// Create tenant
	tenantCR := &operator.TenantCR{
		Metadata: operator.Metadata{Name: "security-team"},
		Spec:     operator.TenantSpec{DisplayName: "Security Team", Namespaces: []string{"security-team"}},
	}
	tStatus, _ := op.ReconcileTenant(ctx, tenantCR)

	// 1. Missing secret
	srcCR := &operator.ScanSourceCR{
		Metadata: operator.Metadata{Name: "github-actions", Namespace: "security-team"},
		Spec: operator.ScanSourceSpec{
			ScannerFamily: "semgrep",
			SecretRef: &operator.SecretRef{
				Name: "gh-token-secret",
				Key:  "token",
			},
		},
	}

	status, _ := op.ReconcileScanSource(ctx, srcCR)
	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "False" || cond.Reason != "SecretNotFound" {
		t.Errorf("expected SecretNotFound condition, got %+v", cond)
	}

	// 2. Secret provided in mock secret provider
	mockSecrets.Secrets["security-team/gh-token-secret:token"] = []byte("super-secret-gh-pat")
	status, err := op.ReconcileScanSource(ctx, srcCR)
	if err != nil {
		t.Fatalf("ReconcileScanSource failed: %v", err)
	}

	cond = status.GetCondition("Ready")
	if cond == nil || cond.Status != "True" || cond.Reason != "Reconciled" {
		t.Errorf("expected Ready=True/Reconciled, got %+v", cond)
	}

	// Verify secret was synced to secret material store
	secKey := tStatus.TenantID + ":scansource:github-actions:token"
	if string(secStore.secrets[secKey]) != "super-secret-gh-pat" {
		t.Errorf("expected synced secret %q, got %q", "super-secret-gh-pat", string(secStore.secrets[secKey]))
	}
}

type captureSecretStore struct{ saved map[string][]byte }

func (c *captureSecretStore) SaveSecretMaterial(_ context.Context, _ uuid.UUID, key string, v []byte) error {
	if c.saved == nil {
		c.saved = map[string][]byte{}
	}
	c.saved[key] = v
	return nil
}

// D1: only ciphertext reaches the store.
func TestEncryptingSecretStoreNeverStoresPlaintext(t *testing.T) {
	c, _ := secrets.NewCipher(bytes.Repeat([]byte{3}, 32))
	inner := &captureSecretStore{}
	st := &operator.EncryptingSecretStore{Inner: inner, Cipher: c}
	tenant := uuid.New()
	if err := st.SaveSecretMaterial(context.Background(), tenant, "k", []byte("hunter2")); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(inner.saved["k"], []byte("hunter2")) {
		t.Fatal("plaintext reached the store")
	}
	if pt, err := c.Decrypt(tenant, "k", inner.saved["k"]); err != nil || string(pt) != "hunter2" {
		t.Fatalf("stored value must decrypt: %q %v", pt, err)
	}
}

// D20: the binding comes only from Tenant.spec.namespaces. A tenant whose NAME equals a
// namespace does not own it, and a namespace has one owner.
func TestNamespaceBindingComesOnlyFromTenantSpec(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	op := operator.NewOperator(store, nil, nil, nil)

	// tenant named like the namespace, but it does not list it
	_, _ = op.ReconcileTenant(ctx, &operator.TenantCR{Metadata: operator.Metadata{Name: "payments"}, Spec: operator.TenantSpec{DisplayName: "P"}})
	app := &operator.ApplicationCR{Metadata: operator.Metadata{Name: "a", Namespace: "payments"}, Spec: operator.ApplicationSpec{DisplayName: "A"}}
	st, _ := op.ReconcileApplication(ctx, app)
	if c := st.GetCondition("Ready"); c == nil || c.Status != "False" || c.Reason != "TenantNotFound" {
		t.Fatalf("a tenant name must not bind a namespace (D20), got %+v", c)
	}

	// another tenant lists it
	_, _ = op.ReconcileTenant(ctx, &operator.TenantCR{Metadata: operator.Metadata{Name: "team-a"}, Spec: operator.TenantSpec{DisplayName: "A", Namespaces: []string{"payments"}}})
	st, _ = op.ReconcileApplication(ctx, app)
	if c := st.GetCondition("Ready"); c == nil || c.Status != "True" {
		t.Fatalf("a listed namespace must bind, got %+v", c)
	}

	// a second tenant cannot claim the same namespace
	st2, _ := op.ReconcileTenant(ctx, &operator.TenantCR{Metadata: operator.Metadata{Name: "team-b"}, Spec: operator.TenantSpec{DisplayName: "B", Namespaces: []string{"payments"}}})
	if c := st2.GetCondition("Ready"); c == nil || c.Status != "False" || c.Reason != "NamespaceOwnedByOtherTenant" {
		t.Fatalf("a namespace has one owner, got %+v", c)
	}
}

func TestSLAPolicyReconciler(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	op := operator.NewOperator(store, nil, nil, nil)
	policy := func(ns string, spec map[string]any) *operator.SLAPolicyCR {
		return &operator.SLAPolicyCR{Metadata: operator.Metadata{Name: "default", Namespace: ns, Generation: 3}, Spec: spec}
	}

	// A namespace no tenant lists: not ready, and nothing is stored.
	st, err := op.ReconcileSLAPolicy(ctx, policy("nobody", map[string]any{}))
	if err != nil || st.GetCondition("Ready") == nil || st.GetCondition("Ready").Reason != "TenantNotFound" {
		t.Fatalf("no tenant: %v %+v", err, st.GetCondition("Ready"))
	}

	tn := &operator.TenantCR{Metadata: operator.Metadata{Name: "acme"}, Spec: operator.TenantSpec{Namespaces: []string{"team-payments"}}}
	if _, err := op.ReconcileTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	owner, _ := store.GetTenantBySlug(ctx, "acme")

	// A valid policy is stored and Ready.
	st, err = op.ReconcileSLAPolicy(ctx, policy("team-payments", map[string]any{"matrix": map[string]any{"critical": map[string]any{"critical": 1}}}))
	if err != nil || st.GetCondition("Ready").Status != "True" || st.ObservedGeneration != 3 {
		t.Fatalf("valid policy: %v %+v", err, st)
	}
	got, ok := store.SLAPolicy(owner.ID, "team-payments", "default")
	if !ok || got.Error != "" || got.Generation != 3 {
		t.Fatalf("stored: %+v %v", got, ok)
	}

	// An invalid one is stored with its reason, says so in Ready, and is not an error to retry.
	st, err = op.ReconcileSLAPolicy(ctx, policy("team-payments", map[string]any{"businessDays": true}))
	c := st.GetCondition("Ready")
	if err != nil || c.Status != "False" || c.Reason != "InvalidSpec" || !strings.Contains(c.Message, "business days") {
		t.Fatalf("invalid policy: %v %+v", err, c)
	}
	if got, _ := store.SLAPolicy(owner.ID, "team-payments", "default"); got.Error == "" {
		t.Fatal("the reason must be stored with the spec")
	}
}

func TestIdentityProviderReconciler(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	op := operator.NewOperator(store, nil, nil, nil)

	// Missing tenant namespace
	cr := &operator.IdentityProviderCR{
		Metadata: operator.Metadata{Name: "okta", Namespace: "nobody", Generation: 1},
		Spec: domain.IdentityProviderSpec{
			Type: "oidc",
			OIDC: &domain.IdPOIDCConfig{
				Issuer:   "https://okta.example.com",
				ClientID: "client-123",
			},
		},
	}
	st, err := op.ReconcileIdentityProvider(ctx, cr)
	if err != nil || st.GetCondition("Ready") == nil || st.GetCondition("Ready").Reason != "TenantNotFound" {
		t.Fatalf("expected TenantNotFound, got: %v %+v", err, st.GetCondition("Ready"))
	}

	// Create tenant owning payments namespace
	tn := &operator.TenantCR{Metadata: operator.Metadata{Name: "fintech"}, Spec: operator.TenantSpec{Namespaces: []string{"payments"}}}
	if _, err := op.ReconcileTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	tenant, _ := store.GetTenantBySlug(ctx, "fintech")

	// Valid IdentityProvider
	cr.Metadata.Namespace = "payments"
	cr.Spec.DisplayName = "Okta SSO"
	cr.Spec.Login.EmailDomains = []string{"fintech.com"}
	st, err = op.ReconcileIdentityProvider(ctx, cr)
	if err != nil || st.GetCondition("Ready") == nil || st.GetCondition("Ready").Status != "True" {
		t.Fatalf("expected Ready=True, got: %v %+v", err, st.GetCondition("Ready"))
	}
	if st.RedirectURI != "/auth/oidc/okta/callback" {
		t.Errorf("expected redirect uri /auth/oidc/okta/callback, got %s", st.RedirectURI)
	}
	if len(st.Domains) != 1 || st.Domains[0].Domain != "fintech.com" || st.Domains[0].Approved {
		t.Errorf("expected unapproved domain claim fintech.com, got %+v", st.Domains)
	}

	// Verify saved in store
	saved, err := store.GetIdentityProvider(ctx, &tenant.ID, "okta")
	if err != nil || saved == nil {
		t.Fatalf("expected saved idp in store, got err=%v idp=%+v", err, saved)
	}
	if saved.DisplayName != "Okta SSO" || saved.Type != "oidc" {
		t.Errorf("saved idp fields mismatch: %+v", saved)
	}

	// Approve domain in store (D27)
	saved.Status.Domains[0].Approved = true
	_ = store.SaveIdentityProvider(ctx, &tenant.ID, *saved)

	// Reconcile again with an added domain
	cr.Metadata.Generation = 2
	cr.Spec.Login.EmailDomains = []string{"fintech.com", "fintech.co.uk"}
	st2, err := op.ReconcileIdentityProvider(ctx, cr)
	if err != nil || st2.GetCondition("Ready") == nil || st2.GetCondition("Ready").Status != "True" {
		t.Fatalf("expected Ready=True on re-reconcile, got %v %+v", err, st2)
	}
	if len(st2.Domains) != 2 {
		t.Fatalf("expected 2 domains, got %+v", st2.Domains)
	}
	for _, d := range st2.Domains {
		if d.Domain == "fintech.com" && !d.Approved {
			t.Errorf("fintech.com approval must be preserved across reconcile (D27)")
		}
		if d.Domain == "fintech.co.uk" && d.Approved {
			t.Errorf("newly added domain fintech.co.uk must start unapproved")
		}
	}

	// Invalid IdentityProvider (missing issuer)
	crInvalid := &operator.IdentityProviderCR{
		Metadata: operator.Metadata{Name: "bad-idp", Namespace: "payments"},
		Spec: domain.IdentityProviderSpec{
			Type: "oidc",
			OIDC: &domain.IdPOIDCConfig{ClientID: "xyz"},
		},
	}
	stInvalid, err := op.ReconcileIdentityProvider(ctx, crInvalid)
	if err != nil || stInvalid.GetCondition("Ready") == nil || stInvalid.GetCondition("Ready").Reason != "InvalidSpec" {
		t.Fatalf("expected InvalidSpec, got %v %+v", err, stInvalid.GetCondition("Ready"))
	}
}

func TestClusterIdentityProviderReconciler(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	op := operator.NewOperator(store, nil, nil, nil)

	cr := &operator.ClusterIdentityProviderCR{
		Metadata: operator.Metadata{Name: "google-workspace", Generation: 2},
		Spec: domain.IdentityProviderSpec{
			DisplayName:    "Google Workspace",
			Type:           "oidc",
			AllowedTenants: []string{"acme", "fintech"},
			OIDC: &domain.IdPOIDCConfig{
				Issuer:   "https://accounts.google.com",
				ClientID: "google-client-id",
			},
		},
	}

	st, err := op.ReconcileClusterIdentityProvider(ctx, cr)
	if err != nil || st.GetCondition("Ready") == nil || st.GetCondition("Ready").Status != "True" {
		t.Fatalf("expected Ready=True, got %v %+v", err, st.GetCondition("Ready"))
	}
	if st.RedirectURI != "/auth/oidc/google-workspace/callback" {
		t.Errorf("expected redirect uri /auth/oidc/google-workspace/callback, got %s", st.RedirectURI)
	}

	// Check store
	saved, err := store.GetIdentityProvider(ctx, nil, "google-workspace")
	if err != nil || saved == nil {
		t.Fatalf("expected cluster idp saved in store: %v", err)
	}
	if !saved.IsTenantAllowed("acme") || saved.IsTenantAllowed("evilcorp") {
		t.Errorf("allowedTenants enforcement failed: %+v", saved.Spec.AllowedTenants)
	}
}

func TestConnectorReconciler(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	mockSecrets := operator.NewMockSecretProvider()
	secStore := newMemorySecretStore()
	op := operator.NewOperator(store, mockSecrets, secStore, nil)

	tenantCR := &operator.TenantCR{
		Metadata: operator.Metadata{Name: "acme"},
		Spec:     operator.TenantSpec{DisplayName: "Acme", Namespaces: []string{"acme-ns"}},
	}
	tStatus, err := op.ReconcileTenant(ctx, tenantCR)
	if err != nil {
		t.Fatalf("ReconcileTenant failed: %v", err)
	}

	// 1. Reconcile Jira connector with secret
	mockSecrets.Secrets["acme-ns/jira-secret:apiToken"] = []byte("secret-token-123")

	cr := &operator.ConnectorCR{
		Metadata: operator.Metadata{Name: "jira-sec", Namespace: "acme-ns", Generation: 1},
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeJira,
			Jira: &domain.JiraConnectorConfig{
				URL: "https://acme.atlassian.net",
				CredentialsSecretRef: domain.SecretKeyRef{
					Name: "jira-secret",
					Key:  "apiToken",
				},
				DefaultProject: "SEC",
				IssueType:      "Bug",
			},
		},
	}

	st, err := op.ReconcileConnector(ctx, cr)
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}
	if st.GetCondition("Connected") == nil || st.GetCondition("Connected").Status != "True" {
		t.Fatalf("expected Connected=True, got %+v", st.GetCondition("Connected"))
	}
	if st.WebhookURL != "/hooks/jira/jira-sec" {
		t.Errorf("expected webhook url /hooks/jira/jira-sec, got %s", st.WebhookURL)
	}

	// Verify secret was synced to SecretStore
	storageKey := tStatus.TenantID + ":connector:jira-sec:apiToken"
	if string(secStore.secrets[storageKey]) != "secret-token-123" {
		t.Errorf("expected secret synced to storageKey %s, got %s", storageKey, secStore.secrets[storageKey])
	}

	// 2. Secret missing should set Connected=False, reason SecretNotFound
	crMissingSec := &operator.ConnectorCR{
		Metadata: operator.Metadata{Name: "slack-alert", Namespace: "acme-ns", Generation: 1},
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeSlack,
			Slack: &domain.SlackConnectorConfig{
				TokenSecretRef: domain.SecretKeyRef{Name: "non-existent-secret", Key: "token"},
				DefaultChannel: "#alerts",
			},
		},
	}
	stMissing, err := op.ReconcileConnector(ctx, crMissingSec)
	if err != nil || stMissing.GetCondition("Connected") == nil || stMissing.GetCondition("Connected").Reason != "SecretNotFound" {
		t.Fatalf("expected SecretNotFound, got err: %v, cond: %+v", err, stMissing.GetCondition("Connected"))
	}

	// 3. Finalize
	_, done, err := op.FinalizeConnector(ctx, cr)
	if err != nil || !done {
		t.Fatalf("finalize failed: %v", err)
	}
	tenantID, _ := uuid.Parse(tStatus.TenantID)
	deleted, err := store.GetConnector(ctx, tenantID, "jira-sec")
	if err != nil || deleted != nil {
		t.Errorf("expected connector to be deleted from store, got %+v", deleted)
	}
}
