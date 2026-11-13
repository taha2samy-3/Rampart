package operator

import (
	"context"
	"fmt"
	"log/slog"

	"rampart/internal/config/apply"
)

// Operator manages Rampart Kubernetes reconciliation loops.
type Operator struct {
	logger      *slog.Logger
	tenants     *TenantReconciler
	apps        *ApplicationReconciler
	scanSources *ScanSourceReconciler
	slaPolicies *SLAPolicyReconciler
	idps        *IdentityProviderReconciler
	clusterIdps *ClusterIdentityProviderReconciler
}

// NewOperator creates a new Rampart operator instance.
func NewOperator(store apply.ConfigStore, secrets SecretProvider, secretStore SecretMaterialStore, logger *slog.Logger) *Operator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Operator{
		logger:      logger,
		tenants:     NewTenantReconciler(store),
		apps:        NewApplicationReconciler(store),
		scanSources: NewScanSourceReconciler(store, secrets, secretStore),
		slaPolicies: NewSLAPolicyReconciler(store),
		idps:        NewIdentityProviderReconciler(store),
		clusterIdps: NewClusterIdentityProviderReconciler(store),
	}
}

// ReconcileTenant reconciles a Tenant CR.
func (op *Operator) ReconcileTenant(ctx context.Context, cr *TenantCR) (*TenantStatus, error) {
	op.logger.Debug("reconciling tenant", "slug", cr.Metadata.Name)
	return op.tenants.Reconcile(ctx, cr)
}

// ReconcileApplication reconciles an Application CR.
func (op *Operator) ReconcileApplication(ctx context.Context, cr *ApplicationCR) (*ApplicationStatus, error) {
	op.logger.Debug("reconciling application", "name", cr.Metadata.Name, "namespace", cr.Metadata.Namespace)
	return op.apps.Reconcile(ctx, cr)
}

// ReconcileScanSource reconciles a ScanSource CR.
func (op *Operator) ReconcileScanSource(ctx context.Context, cr *ScanSourceCR) (*ScanSourceStatus, error) {
	op.logger.Debug("reconciling scan source", "name", cr.Metadata.Name, "namespace", cr.Metadata.Namespace)
	return op.scanSources.Reconcile(ctx, cr)
}

// ReconcileSLAPolicy reconciles an SLAPolicy CR.
func (op *Operator) ReconcileSLAPolicy(ctx context.Context, cr *SLAPolicyCR) (*SLAPolicyStatus, error) {
	op.logger.Debug("reconciling sla policy", "name", cr.Metadata.Name, "namespace", cr.Metadata.Namespace)
	return op.slaPolicies.Reconcile(ctx, cr)
}

// ReconcileIdentityProvider reconciles an IdentityProvider CR.
func (op *Operator) ReconcileIdentityProvider(ctx context.Context, cr *IdentityProviderCR) (*IdentityProviderStatus, error) {
	op.logger.Debug("reconciling identity provider", "name", cr.Metadata.Name, "namespace", cr.Metadata.Namespace)
	return op.idps.Reconcile(ctx, cr)
}

// ReconcileClusterIdentityProvider reconciles a ClusterIdentityProvider CR.
func (op *Operator) ReconcileClusterIdentityProvider(ctx context.Context, cr *ClusterIdentityProviderCR) (*IdentityProviderStatus, error) {
	op.logger.Debug("reconciling cluster identity provider", "name", cr.Metadata.Name)
	return op.clusterIdps.Reconcile(ctx, cr)
}

// Start runs background watchers or loops if enabled (D6 operator.mode).
func (op *Operator) Start(ctx context.Context) error {
	op.logger.Info("rampart operator started")
	<-ctx.Done()
	op.logger.Info("rampart operator stopped")
	return nil
}

// MockSecretProvider implements SecretProvider for testing and local environments.
type MockSecretProvider struct {
	Secrets map[string][]byte
}

func NewMockSecretProvider() *MockSecretProvider {
	return &MockSecretProvider{
		Secrets: make(map[string][]byte),
	}
}

func (m *MockSecretProvider) GetSecret(ctx context.Context, namespace, name, key string) ([]byte, error) {
	lookupKey := fmt.Sprintf("%s/%s:%s", namespace, name, key)
	if val, ok := m.Secrets[lookupKey]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("secret %q not found", lookupKey)
}
