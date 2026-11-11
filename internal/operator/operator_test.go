package operator_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/config/apply"
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
