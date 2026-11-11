package operator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/secrets"
)

// SecretProvider abstracts retrieving secrets from Kubernetes.
type SecretProvider interface {
	GetSecret(ctx context.Context, namespace, name, key string) ([]byte, error)
}

// SecretMaterialStore abstracts storing secret material into PostgreSQL. Implementations
// receive ciphertext only; wrap them in EncryptingSecretStore.
type SecretMaterialStore interface {
	SaveSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string, encryptedValue []byte) error
}

// EncryptingSecretStore encrypts secret material (AES-256-GCM, per-tenant key, D1) before it
// reaches the underlying store. The reconcilers hand it the plaintext they read from the
// Kubernetes Secret; nothing readable is ever written to PostgreSQL.
type EncryptingSecretStore struct {
	Inner  SecretMaterialStore
	Cipher *secrets.Cipher
}

// SaveSecretMaterial encrypts value for the tenant and stores it under key.
func (s *EncryptingSecretStore) SaveSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string, value []byte) error {
	ct, err := s.Cipher.Encrypt(tenantID, key, value)
	if err != nil {
		return fmt.Errorf("encrypting secret material: %w", err)
	}
	return s.Inner.SaveSecretMaterial(ctx, tenantID, key, ct)
}

// TenantReconciler handles reconciliation of Tenant custom resources.
type TenantReconciler struct {
	store apply.ConfigStore
}

func NewTenantReconciler(store apply.ConfigStore) *TenantReconciler {
	return &TenantReconciler{store: store}
}

func (r *TenantReconciler) Reconcile(ctx context.Context, cr *TenantCR) (*TenantStatus, error) {
	status := &cr.Status
	slug := cr.Metadata.Name
	if slug == "" {
		status.SetCondition("Ready", "False", "InvalidName", "metadata.name cannot be empty")
		return status, fmt.Errorf("metadata.name cannot be empty")
	}

	existing, _ := r.store.GetTenantBySlug(ctx, slug)
	tenantID := domain.NewID()
	if existing != nil {
		tenantID = existing.ID
	}

	displayName := cr.Spec.DisplayName
	if displayName == "" {
		displayName = slug
	}

	tenant := domain.Tenant{
		ID:          tenantID,
		Slug:        slug,
		DisplayName: displayName,
		CreatedAt:   time.Now().UTC(),
	}

	if err := r.store.SaveTenant(ctx, tenant); err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}

	// D20: the binding between namespaces and a tenant comes only from spec.namespaces.
	for _, ns := range cr.Spec.Namespaces {
		if err := r.store.ClaimNamespace(ctx, tenant.ID, ns); err != nil {
			if errors.Is(err, apply.ErrNamespaceOwned) {
				status.SetCondition("Ready", "False", "NamespaceOwnedByOtherTenant",
					fmt.Sprintf("namespace %q is already listed by another tenant", ns))
				return status, nil
			}
			status.SetCondition("Ready", "False", "StorageError", err.Error())
			return status, err
		}
	}

	status.ObservedGeneration = cr.Metadata.Generation
	status.TenantID = tenant.ID.String()
	status.SetCondition("Ready", "True", "Reconciled", "Tenant configuration reconciled successfully")
	return status, nil
}

// ApplicationReconciler handles reconciliation of Application custom resources.
type ApplicationReconciler struct {
	store apply.ConfigStore
}

func NewApplicationReconciler(store apply.ConfigStore) *ApplicationReconciler {
	return &ApplicationReconciler{store: store}
}

func (r *ApplicationReconciler) Reconcile(ctx context.Context, cr *ApplicationCR) (*ApplicationStatus, error) {
	status := &cr.Status
	// D20: the tenant is whichever one lists this namespace in spec.namespaces. The namespace
	// name is never a tenant name and a label is never trusted.
	tenant, err := r.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	if tenant == nil {
		// D17: a namespaced CR in a namespace that has no Tenant gets Ready=False, reason TenantNotFound
		status.SetCondition("Ready", "False", "TenantNotFound", fmt.Sprintf("no tenant lists namespace %q", cr.Metadata.Namespace))
		return status, nil
	}

	existing, _ := r.store.GetApplicationBySlug(ctx, tenant.ID, cr.Metadata.Name)
	appID := domain.NewID()
	if existing != nil {
		appID = existing.ID
	}

	crit := cr.Spec.BusinessCriticality
	if crit == "" {
		crit = "medium"
	}
	lifecycle := cr.Spec.Lifecycle
	if lifecycle == "" {
		lifecycle = "production"
	}

	displayName := cr.Spec.DisplayName
	if displayName == "" {
		displayName = cr.Metadata.Name
	}

	app := domain.Application{
		ID:                  appID,
		TenantID:            tenant.ID,
		Slug:                cr.Metadata.Name,
		Name:                displayName,
		BusinessCriticality: crit,
		InternetFacing:      cr.Spec.InternetFacing,
		Owners:              cr.Spec.Owners,
		DataClassification:  cr.Spec.DataClassification,
		Lifecycle:           lifecycle,
		CreatedAt:           time.Now().UTC(),
	}

	if err := r.store.SaveApplication(ctx, app); err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}

	status.ObservedGeneration = cr.Metadata.Generation
	status.ApplicationID = app.ID.String()
	status.SetCondition("Ready", "True", "Reconciled", "Application reconciled successfully")
	return status, nil
}

// ScanSourceReconciler handles reconciliation of ScanSource custom resources and secret synchronization.
type ScanSourceReconciler struct {
	store       apply.ConfigStore
	secrets     SecretProvider
	secretStore SecretMaterialStore
}

func NewScanSourceReconciler(store apply.ConfigStore, secrets SecretProvider, secretStore SecretMaterialStore) *ScanSourceReconciler {
	return &ScanSourceReconciler{
		store:       store,
		secrets:     secrets,
		secretStore: secretStore,
	}
}

func (r *ScanSourceReconciler) Reconcile(ctx context.Context, cr *ScanSourceCR) (*ScanSourceStatus, error) {
	status := &cr.Status
	// D20: the tenant is whichever one lists this namespace in spec.namespaces. The namespace
	// name is never a tenant name and a label is never trusted.
	tenant, err := r.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	if tenant == nil {
		// D17: a namespaced CR in a namespace that has no Tenant gets Ready=False, reason TenantNotFound
		status.SetCondition("Ready", "False", "TenantNotFound", fmt.Sprintf("no tenant lists namespace %q", cr.Metadata.Namespace))
		return status, nil
	}

	// Secret synchronization (D4 line 30, D17)
	if cr.Spec.SecretRef != nil && r.secrets != nil && r.secretStore != nil {
		secretBytes, err := r.secrets.GetSecret(ctx, cr.Metadata.Namespace, cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Key)
		if err != nil {
			status.SetCondition("Ready", "False", "SecretNotFound", fmt.Sprintf("failed to resolve secretRef %s/%s: %v", cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Key, err))
			return status, nil
		}

		secretKey := fmt.Sprintf("scansource:%s:%s", cr.Metadata.Name, cr.Spec.SecretRef.Key)
		if err := r.secretStore.SaveSecretMaterial(ctx, tenant.ID, secretKey, secretBytes); err != nil {
			status.SetCondition("Ready", "False", "SecretSyncFailed", fmt.Sprintf("failed to sync secret material: %v", err))
			return status, err
		}
	}

	sourceID, err := r.store.SaveScanSource(ctx, tenant.ID, cr.Metadata.Name, cr.Spec.ScannerFamily)
	if err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}

	status.ObservedGeneration = cr.Metadata.Generation
	status.ScanSourceID = sourceID.String()
	status.SetCondition("Ready", "True", "Reconciled", "ScanSource reconciled successfully")
	return status, nil
}
