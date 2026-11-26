package operator_test

import (
	"context"
	"testing"
	"time"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/operator"
)

func setupOperatorBindingTest(t *testing.T) (*operator.Operator, *apply.MemoryConfigStore, *operator.MockSecretProvider, domain.Tenant) {
	t.Helper()
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	mockSecrets := operator.NewMockSecretProvider()
	secStore := newMemorySecretStore()
	op := operator.NewOperator(store, mockSecrets, secStore, nil)

	tenantCR := &operator.TenantCR{
		Metadata: operator.Metadata{Name: "core-team"},
		Spec:     operator.TenantSpec{DisplayName: "Core Team", Namespaces: []string{"core-ns"}},
	}
	_, err := op.ReconcileTenant(ctx, tenantCR)
	if err != nil {
		t.Fatalf("ReconcileTenant failed: %v", err)
	}

	tn, err := store.GetTenantBySlug(ctx, "core-team")
	if err != nil || tn == nil {
		t.Fatalf("failed to get tenant: %v", err)
	}

	return op, store, mockSecrets, *tn
}

func TestScanSourceReconciler_ApplicationNotFound(t *testing.T) {
	ctx := context.Background()
	op, _, _, _ := setupOperatorBindingTest(t)

	srcCR := &operator.ScanSourceCR{
		Metadata: operator.Metadata{Name: "ci-scanner", Namespace: "core-ns"},
		Spec: operator.ScanSourceSpec{
			ApplicationRef: domain.ApplicationRef{Name: "missing-app"},
			Categories:     []string{"sast"},
		},
	}

	status, err := op.ReconcileScanSource(ctx, srcCR)
	if err != nil {
		t.Fatalf("ReconcileScanSource returned unexpected error: %v", err)
	}

	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "False" || cond.Reason != "ApplicationNotFound" {
		t.Fatalf("expected Ready=False with Reason=ApplicationNotFound, got %+v", cond)
	}
}

func TestScanSourceReconciler_ApplicationBinding_Success(t *testing.T) {
	ctx := context.Background()
	op, store, _, tn := setupOperatorBindingTest(t)

	// Create application first
	app := domain.Application{
		ID:                  domain.NewID(),
		TenantID:            tn.ID,
		Slug:                "payments-api",
		Name:                "payments-api",
		Branch:              "main",
		BusinessCriticality: "high",
		Lifecycle:           "production",
		Version:             1,
		CreatedAt:           time.Now().UTC(),
	}
	if err := store.SaveApplication(ctx, app); err != nil {
		t.Fatalf("failed to save application: %v", err)
	}

	srcCR := &operator.ScanSourceCR{
		Metadata: operator.Metadata{Name: "payments-sast", Namespace: "core-ns"},
		Spec: operator.ScanSourceSpec{
			ApplicationRef: domain.ApplicationRef{Name: "payments-api"},
			Categories:     []string{"sast", "secret"},
		},
	}

	status, err := op.ReconcileScanSource(ctx, srcCR)
	if err != nil {
		t.Fatalf("ReconcileScanSource failed: %v", err)
	}

	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "True" || cond.Reason != "Reconciled" {
		t.Fatalf("expected Ready=True with Reason=Reconciled, got %+v", cond)
	}
	if status.ScanSourceID == "" {
		t.Fatal("expected non-empty ScanSourceID in status")
	}
}

func TestScanSourceReconciler_InvalidCategory(t *testing.T) {
	ctx := context.Background()
	op, store, _, tn := setupOperatorBindingTest(t)

	app := domain.Application{
		ID:        domain.NewID(),
		TenantID:  tn.ID,
		Slug:      "auth-api",
		Name:      "auth-api",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	_ = store.SaveApplication(ctx, app)

	srcCR := &operator.ScanSourceCR{
		Metadata: operator.Metadata{Name: "auth-bad-cat", Namespace: "core-ns"},
		Spec: operator.ScanSourceSpec{
			ApplicationRef: domain.ApplicationRef{Name: "auth-api"},
			Categories:     []string{"sast", "not-a-category"},
		},
	}

	status, err := op.ReconcileScanSource(ctx, srcCR)
	if err != nil {
		t.Fatalf("ReconcileScanSource returned unexpected error: %v", err)
	}

	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "False" || cond.Reason != "InvalidCategory" {
		t.Fatalf("expected Ready=False with Reason=InvalidCategory, got %+v", cond)
	}
}

func TestScanSourceReconciler_Auth_TokenSecretRef(t *testing.T) {
	ctx := context.Background()
	op, store, mockSecrets, tn := setupOperatorBindingTest(t)

	app := domain.Application{
		ID:        domain.NewID(),
		TenantID:  tn.ID,
		Slug:      "token-app",
		Name:      "token-app",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	_ = store.SaveApplication(ctx, app)

	srcCR := &operator.ScanSourceCR{
		Metadata: operator.Metadata{Name: "token-scansource", Namespace: "core-ns"},
		Spec: operator.ScanSourceSpec{
			ApplicationRef: domain.ApplicationRef{Name: "token-app"},
			Categories:     []string{"all"},
			Auth: domain.AuthSpec{
				TokenSecretRef: &domain.SecretRef{
					Name: "ci-secret",
					Key:  "ci-token",
				},
			},
		},
	}

	// 1. Missing secret
	status, _ := op.ReconcileScanSource(ctx, srcCR)
	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "False" || cond.Reason != "SecretNotFound" {
		t.Fatalf("expected SecretNotFound condition, got %+v", cond)
	}

	// 2. Secret exists in secret provider
	mockSecrets.Secrets["core-ns/ci-secret:ci-token"] = []byte("standard-ci-token-value")
	status, err := op.ReconcileScanSource(ctx, srcCR)
	if err != nil {
		t.Fatalf("ReconcileScanSource failed: %v", err)
	}

	cond = status.GetCondition("Ready")
	if cond == nil || cond.Status != "True" || cond.Reason != "Reconciled" {
		t.Fatalf("expected Ready=True/Reconciled, got %+v", cond)
	}
}

func TestScanSourceReconciler_Auth_Federation(t *testing.T) {
	ctx := context.Background()
	op, store, _, tn := setupOperatorBindingTest(t)

	app := domain.Application{
		ID:        domain.NewID(),
		TenantID:  tn.ID,
		Slug:      "fed-app",
		Name:      "fed-app",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	_ = store.SaveApplication(ctx, app)

	// 1. Valid federation spec with bound claims
	srcCR := &operator.ScanSourceCR{
		Metadata: operator.Metadata{Name: "gh-actions-fed", Namespace: "core-ns"},
		Spec: operator.ScanSourceSpec{
			ApplicationRef: domain.ApplicationRef{Name: "fed-app"},
			Categories:     []string{"sast", "sca"},
			Auth: domain.AuthSpec{
				Federation: &domain.FederationSpec{
					Issuer:   "https://token.actions.githubusercontent.com",
					Provider: "github",
					BoundClaims: map[string]string{
						"repository_id":       "123",
						"repository_owner_id": "456",
						"ref":                 "refs/heads/main",
					},
				},
			},
		},
	}

	status, err := op.ReconcileScanSource(ctx, srcCR)
	if err != nil {
		t.Fatalf("ReconcileScanSource failed: %v", err)
	}

	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "True" || cond.Reason != "Reconciled" {
		t.Fatalf("expected Ready=True/Reconciled, got %+v", cond)
	}

	// 2. Invalid federation spec (empty issuer)
	srcBad := &operator.ScanSourceCR{
		Metadata: operator.Metadata{Name: "bad-fed", Namespace: "core-ns"},
		Spec: operator.ScanSourceSpec{
			ApplicationRef: domain.ApplicationRef{Name: "fed-app"},
			Categories:     []string{"all"},
			Auth: domain.AuthSpec{
				Federation: &domain.FederationSpec{
					Issuer: "", // Empty!
					BoundClaims: map[string]string{
						"sub": "123",
					},
				},
			},
		},
	}

	statusBad, _ := op.ReconcileScanSource(ctx, srcBad)
	condBad := statusBad.GetCondition("Ready")
	if condBad == nil || condBad.Status != "False" || condBad.Reason != "InvalidFederation" {
		t.Fatalf("expected Ready=False with Reason=InvalidFederation, got %+v", condBad)
	}
}

func TestScanSourceReconciler_BindingByRepository(t *testing.T) {
	ctx := context.Background()
	op, store, mockSecrets, tn := setupOperatorBindingTest(t)

	app := domain.Application{
		ID:         domain.NewID(),
		TenantID:   tn.ID,
		Slug:       "repo-app",
		Name:       "repo-app",
		Repository: "https://github.com/acme/repo-service",
		Branch:     "main",
		Version:    1,
		CreatedAt:  time.Now().UTC(),
	}
	_ = store.SaveApplication(ctx, app)

	mockSecrets.Secrets["core-ns/dummy:token"] = []byte("token123")

	// Bind via Repository URL (including .git suffix normalization)
	srcCR := &operator.ScanSourceCR{
		Metadata: operator.Metadata{Name: "repo-sast", Namespace: "core-ns"},
		Spec: operator.ScanSourceSpec{
			ApplicationRef: domain.ApplicationRef{
				Repository: "https://github.com/acme/repo-service.git",
			},
			Categories: []string{"sast"},
			Auth: domain.AuthSpec{
				TokenSecretRef: &domain.SecretRef{Name: "dummy", Key: "token"},
			},
		},
	}

	status, err := op.ReconcileScanSource(ctx, srcCR)
	if err != nil {
		t.Fatalf("ReconcileScanSource failed: %v", err)
	}
	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "True" || cond.Reason != "Reconciled" {
		t.Fatalf("expected Ready=True, got %+v", cond)
	}
}

func TestScanSourceReconciler_BindingBySelector(t *testing.T) {
	ctx := context.Background()
	op, store, _, tn := setupOperatorBindingTest(t)

	app := domain.Application{
		ID:        domain.NewID(),
		TenantID:  tn.ID,
		Slug:      "selected-app",
		Name:      "selected-app",
		Tags:      []string{"app=microservice", "team=secops"},
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	_ = store.SaveApplication(ctx, app)

	// Bind via label selector matchLabels
	srcCR := &operator.ScanSourceCR{
		Metadata: operator.Metadata{Name: "selected-sast", Namespace: "core-ns"},
		Spec: operator.ScanSourceSpec{
			ApplicationRef: domain.ApplicationRef{
				Selector: &domain.ApplicationSelector{
					MatchLabels: map[string]string{"app": "microservice"},
				},
			},
			Categories: []string{"sast"},
		},
	}

	status, err := op.ReconcileScanSource(ctx, srcCR)
	if err != nil {
		t.Fatalf("ReconcileScanSource failed: %v", err)
	}
	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "True" || cond.Reason != "Reconciled" {
		t.Fatalf("expected Ready=True, got %+v", cond)
	}
}

func TestScanSourceReconciler_MultiAuth_TokenAndFederations(t *testing.T) {
	ctx := context.Background()
	op, store, mockSecrets, tn := setupOperatorBindingTest(t)

	app := domain.Application{
		ID:        domain.NewID(),
		TenantID:  tn.ID,
		Slug:      "multi-auth-app",
		Name:      "multi-auth-app",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	_ = store.SaveApplication(ctx, app)

	mockSecrets.Secrets["core-ns/ci-pat:token"] = []byte("my-api-token-secret")

	srcCR := &operator.ScanSourceCR{
		Metadata: operator.Metadata{Name: "multi-ci", Namespace: "core-ns"},
		Spec: operator.ScanSourceSpec{
			ApplicationRef: domain.ApplicationRef{Name: "multi-auth-app"},
			Categories:     []string{"all"},
			Type:           "upload",
			Auth: domain.AuthSpec{
				TokenSecretRef: &domain.SecretRef{Name: "ci-pat", Key: "token"},
				Federations: []domain.FederationSpec{
					{
						Issuer:      "https://token.actions.githubusercontent.com",
						Provider:    "github",
						BoundClaims: map[string]string{"repository_id": "111", "repository_owner_id": "1"},
					},
					{
						Issuer:          "https://sts.amazonaws.com",
						BoundClaims:     map[string]string{"account_id": "222"},
						RepositoryClaim: "repository", RefClaim: "ref",
					},
				},
			},
		},
	}

	status, err := op.ReconcileScanSource(ctx, srcCR)
	if err != nil {
		t.Fatalf("ReconcileScanSource failed: %v", err)
	}
	cond := status.GetCondition("Ready")
	if cond == nil || cond.Status != "True" || cond.Reason != "Reconciled" {
		t.Fatalf("expected Ready=True/Reconciled, got %+v", cond)
	}
}

// docs/51 step 1.3: removing the federation from a ScanSource revokes it. Before, the reconciler saved rules only when there were
// some, so the old row stayed and CI could still exchange tokens.
func TestScanSourceReconciler_RemovedFederationIsRevoked(t *testing.T) {
	ctx := context.Background()
	op, store, secrets, tn := setupOperatorBindingTest(t)
	secrets.Secrets["core-ns/ci-pat:token"] = []byte("rpt_example")
	_ = store.SaveApplication(ctx, domain.Application{ID: domain.NewID(), TenantID: tn.ID, Slug: "rev-app", Name: "rev-app", Version: 1, CreatedAt: time.Now().UTC()})

	cr := &operator.ScanSourceCR{
		Metadata: operator.Metadata{Name: "rev-src", Namespace: "core-ns"},
		Spec: operator.ScanSourceSpec{
			ApplicationRef: domain.ApplicationRef{Name: "rev-app"},
			Categories:     []string{"sast"},
			Auth: domain.AuthSpec{
				Federation: &domain.FederationSpec{
					Issuer: "https://token.actions.githubusercontent.com", Provider: "github",
					BoundClaims: map[string]string{"repository_id": "1", "repository_owner_id": "2"},
				},
			},
		},
	}
	if st, err := op.ReconcileScanSource(ctx, cr); err != nil || st.GetCondition("Ready").Status != "True" {
		t.Fatalf("reconcile: %v %+v", err, st.GetCondition("Ready"))
	}
	if rules, _ := store.ListTrustRules(ctx, tn.ID); len(rules) != 1 || rules[0].Rule.Provider != "github" {
		t.Fatalf("want the one federation stored with its provider, got %+v", rules)
	}
	cr.Spec.Auth.Federation = nil
	cr.Spec.Auth.TokenSecretRef = &domain.SecretRef{Name: "ci-pat", Key: "token"} // auth still has one mode
	if st, err := op.ReconcileScanSource(ctx, cr); err != nil || st.GetCondition("Ready").Status != "True" {
		t.Fatalf("reconcile without the federation: %v %+v", err, st.GetCondition("Ready"))
	}
	if rules, _ := store.ListTrustRules(ctx, tn.ID); len(rules) != 0 {
		t.Fatalf("a federation removed from the resource must be revoked, still stored: %+v", rules)
	}
}
