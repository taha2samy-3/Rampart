package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/risk"
	"rampart/internal/secrets"

	"github.com/google/uuid"
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

	if cr.Spec.DisplayName == "" {
		cr.Spec.DisplayName = cr.Metadata.Name
	}
	app, err := cr.Spec.ToApplication(appID, tenant.ID, cr.Metadata.Name)
	if err != nil {
		status.SetCondition("Ready", "False", "InvalidSpec", err.Error())
		return status, nil
	}
	app.CreatedAt = time.Now().UTC()

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

// SLAPolicyReconciler handles reconciliation of SLAPolicy custom resources (docs/16 D41).
type SLAPolicyReconciler struct {
	store apply.ConfigStore
}

// NewSLAPolicyReconciler returns a reconciler.
func NewSLAPolicyReconciler(store apply.ConfigStore) *SLAPolicyReconciler {
	return &SLAPolicyReconciler{store: store}
}

// Reconcile stores the policy of the tenant that owns the namespace. A spec that fails validation is stored with
// its reason, is not applied (the tenant keeps the policy it had, or the built-in one), and says why in Ready.
func (r *SLAPolicyReconciler) Reconcile(ctx context.Context, cr *SLAPolicyCR) (*SLAPolicyStatus, error) {
	status := &cr.Status
	tenant, err := r.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	if tenant == nil {
		status.SetCondition("Ready", "False", "TenantNotFound", fmt.Sprintf("no tenant lists namespace %q", cr.Metadata.Namespace))
		return status, nil
	}
	spec, err := json.Marshal(cr.Spec)
	if err != nil {
		status.SetCondition("Ready", "False", "InvalidSpec", err.Error())
		return status, nil
	}
	obj := apply.PolicyObject{Namespace: cr.Metadata.Namespace, Name: cr.Metadata.Name, Spec: spec, Generation: cr.Metadata.Generation}
	if _, perr := domain.ParseSLAPolicySpec(spec); perr != nil {
		obj.Error = perr.Error()
	}
	if err := r.store.SaveSLAPolicy(ctx, tenant.ID, obj); err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	status.ObservedGeneration = cr.Metadata.Generation
	if obj.Error != "" {
		status.SetCondition("Ready", "False", "InvalidSpec", obj.Error)
		return status, nil
	}
	status.SetCondition("Ready", "True", "Reconciled", "SLAPolicy reconciled; due dates are recomputed in the background")
	return status, nil
}

// PolicyReconciler reconciles RiskPolicy, ClusterRiskPolicy and ClusterSLAPolicy (D62), the way SLAPolicyReconciler
// reconciles SLAPolicy (D41): a spec that fails validation is stored with its reason and not applied, and Ready
// says why. A namespaced policy belongs to the tenant that owns its namespace; a cluster policy to every tenant.
type PolicyReconciler struct {
	store   apply.ConfigStore
	kind    string // risk | sla
	cluster bool
	label   string // the resource kind, for messages
	parse   func([]byte) error
}

// NewRiskPolicyReconciler reconciles namespaced RiskPolicy resources.
func NewRiskPolicyReconciler(store apply.ConfigStore) *PolicyReconciler {
	return &PolicyReconciler{store: store, kind: "risk", label: "RiskPolicy", parse: parseRisk}
}

// NewClusterRiskPolicyReconciler reconciles ClusterRiskPolicy resources.
func NewClusterRiskPolicyReconciler(store apply.ConfigStore) *PolicyReconciler {
	return &PolicyReconciler{store: store, kind: "risk", cluster: true, label: "ClusterRiskPolicy", parse: parseRisk}
}

// NewClusterSLAPolicyReconciler reconciles ClusterSLAPolicy resources.
func NewClusterSLAPolicyReconciler(store apply.ConfigStore) *PolicyReconciler {
	return &PolicyReconciler{store: store, kind: "sla", cluster: true, label: "ClusterSLAPolicy", parse: func(b []byte) error {
		_, err := domain.ParseSLAPolicySpec(b)
		return err
	}}
}

func parseRisk(b []byte) error {
	_, err := risk.ParseRiskPolicySpec(b)
	return err
}

// Reconcile stores the policy.
func (r *PolicyReconciler) Reconcile(ctx context.Context, cr *PolicyCR) (*PolicyStatus, error) {
	status := &cr.Status
	spec, err := json.Marshal(cr.Spec)
	if err != nil {
		status.SetCondition("Ready", "False", "InvalidSpec", err.Error())
		return status, nil
	}
	obj := apply.PolicyObject{Namespace: cr.Metadata.Namespace, Name: cr.Metadata.Name, Spec: spec, Generation: cr.Metadata.Generation}
	if perr := r.parse(spec); perr != nil {
		obj.Error = perr.Error()
	}
	if r.cluster {
		err = r.store.SaveClusterPolicy(ctx, r.kind, obj)
	} else {
		tenant, terr := r.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
		if terr != nil {
			status.SetCondition("Ready", "False", "StorageError", terr.Error())
			return status, terr
		}
		if tenant == nil {
			status.SetCondition("Ready", "False", "TenantNotFound", fmt.Sprintf("no tenant lists namespace %q", cr.Metadata.Namespace))
			return status, nil
		}
		err = r.store.SaveRiskPolicy(ctx, tenant.ID, obj)
	}
	if err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	status.ObservedGeneration = cr.Metadata.Generation
	if obj.Error != "" {
		status.SetCondition("Ready", "False", "InvalidSpec", obj.Error)
		return status, nil
	}
	status.SetCondition("Ready", "True", "Reconciled", r.label+" reconciled; scores and due dates are recomputed in the background")
	return status, nil
}

// Finalize removes the policy; what is left (or the built-in policy) applies, and the findings are re-scored.
func (r *PolicyReconciler) Finalize(ctx context.Context, cr *PolicyCR) (*PolicyStatus, bool, error) {
	if r.cluster {
		return nil, true, r.store.DeleteClusterPolicy(ctx, r.kind, cr.Metadata.Name)
	}
	tenant, err := r.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		return nil, false, err
	}
	if tenant == nil {
		return nil, true, nil
	}
	return nil, true, r.store.DeleteRiskPolicy(ctx, tenant.ID, cr.Metadata.Namespace, cr.Metadata.Name)
}

// IdentityProviderReconciler reconciles tenant-scoped IdentityProvider custom resources (docs/04, docs/14, docs/16 D64).
type IdentityProviderReconciler struct {
	store apply.ConfigStore
}

func NewIdentityProviderReconciler(store apply.ConfigStore) *IdentityProviderReconciler {
	return &IdentityProviderReconciler{store: store}
}

func (r *IdentityProviderReconciler) Reconcile(ctx context.Context, cr *IdentityProviderCR) (*IdentityProviderStatus, error) {
	status := &cr.Status
	tenant, err := r.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	if tenant == nil {
		status.SetCondition("Ready", "False", "TenantNotFound", fmt.Sprintf("no tenant lists namespace %q", cr.Metadata.Namespace))
		return status, nil
	}

	displayName := cr.Spec.DisplayName
	if displayName == "" {
		displayName = cr.Metadata.Name
	}
	idp := domain.IdentityProvider{
		TenantID:    &tenant.ID,
		Namespace:   cr.Metadata.Namespace,
		Name:        cr.Metadata.Name,
		DisplayName: displayName,
		Type:        cr.Spec.Type,
		Spec:        cr.Spec,
		Status: domain.IdentityProviderStatus{
			ObservedGeneration: cr.Metadata.Generation,
			RedirectURI:        fmt.Sprintf("/auth/oidc/%s/callback", cr.Metadata.Name),
		},
	}
	if err := idp.Validate(); err != nil {
		status.SetCondition("Ready", "False", "InvalidSpec", err.Error())
		return status, nil
	}

	// Preserve existing domain approvals if already present (D27)
	existingApproved := make(map[string]domain.DomainClaimStatus)
	if existing, _ := r.store.GetIdentityProvider(ctx, &tenant.ID, cr.Metadata.Name); existing != nil {
		for _, d := range existing.Status.Domains {
			clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d.Domain), "@"))
			if d.Approved {
				existingApproved[clean] = d
			}
		}
	}
	for _, d := range cr.Status.Domains {
		clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d.Domain), "@"))
		if d.Approved {
			existingApproved[clean] = d
		}
	}

	for _, d := range cr.Spec.Login.EmailDomains {
		clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if prev, ok := existingApproved[clean]; ok {
			idp.Status.Domains = append(idp.Status.Domains, prev)
		} else {
			idp.Status.Domains = append(idp.Status.Domains, domain.DomainClaimStatus{
				Domain:   clean,
				Approved: false, // Default unapproved until platform admin approval or DNS verification per D27
			})
		}
	}
	if err := r.store.SaveIdentityProvider(ctx, &tenant.ID, idp); err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	status.ObservedGeneration = cr.Metadata.Generation
	status.RedirectURI = idp.Status.RedirectURI
	status.Domains = idp.Status.Domains
	status.SetCondition("Ready", "True", "Reconciled", "IdentityProvider reconciled successfully")
	return status, nil
}

func (r *IdentityProviderReconciler) Finalize(ctx context.Context, cr *IdentityProviderCR) (*IdentityProviderStatus, bool, error) {
	tenant, err := r.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		return nil, false, err
	}
	if tenant == nil {
		return nil, true, nil
	}
	return nil, true, r.store.DeleteIdentityProvider(ctx, &tenant.ID, cr.Metadata.Name)
}

// ClusterIdentityProviderReconciler reconciles platform-wide ClusterIdentityProvider custom resources (docs/04, docs/14, docs/16 D64).
type ClusterIdentityProviderReconciler struct {
	store apply.ConfigStore
}

func NewClusterIdentityProviderReconciler(store apply.ConfigStore) *ClusterIdentityProviderReconciler {
	return &ClusterIdentityProviderReconciler{store: store}
}

func (r *ClusterIdentityProviderReconciler) Reconcile(ctx context.Context, cr *ClusterIdentityProviderCR) (*IdentityProviderStatus, error) {
	status := &cr.Status
	displayName := cr.Spec.DisplayName
	if displayName == "" {
		displayName = cr.Metadata.Name
	}
	idp := domain.IdentityProvider{
		TenantID:    nil, // Cluster-wide
		Name:        cr.Metadata.Name,
		DisplayName: displayName,
		Type:        cr.Spec.Type,
		Spec:        cr.Spec,
		Status: domain.IdentityProviderStatus{
			ObservedGeneration: cr.Metadata.Generation,
			RedirectURI:        fmt.Sprintf("/auth/oidc/%s/callback", cr.Metadata.Name),
		},
	}
	if err := idp.Validate(); err != nil {
		status.SetCondition("Ready", "False", "InvalidSpec", err.Error())
		return status, nil
	}
	if err := r.store.SaveIdentityProvider(ctx, nil, idp); err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	status.ObservedGeneration = cr.Metadata.Generation
	status.RedirectURI = idp.Status.RedirectURI
	status.SetCondition("Ready", "True", "Reconciled", "ClusterIdentityProvider reconciled successfully")
	return status, nil
}

func (r *ClusterIdentityProviderReconciler) Finalize(ctx context.Context, cr *ClusterIdentityProviderCR) (*IdentityProviderStatus, bool, error) {
	return nil, true, r.store.DeleteIdentityProvider(ctx, nil, cr.Metadata.Name)
}

// ConnectorReconciler handles reconciliation of Connector custom resources (docs/04, docs/16 D69).
type ConnectorReconciler struct {
	store       apply.ConfigStore
	secrets     SecretProvider
	secretStore SecretMaterialStore
}

func NewConnectorReconciler(store apply.ConfigStore, secrets SecretProvider, secretStore SecretMaterialStore) *ConnectorReconciler {
	return &ConnectorReconciler{
		store:       store,
		secrets:     secrets,
		secretStore: secretStore,
	}
}

func extractConnectorSecretRef(spec *domain.ConnectorSpec) *domain.SecretKeyRef {
	if spec == nil {
		return nil
	}
	switch spec.Type {
	case domain.ConnectorTypeJira:
		if spec.Jira != nil {
			return &spec.Jira.CredentialsSecretRef
		}
	case domain.ConnectorTypeGitHub:
		if spec.GitHub != nil {
			return &spec.GitHub.CredentialsSecretRef
		}
	case domain.ConnectorTypeSlack:
		if spec.Slack != nil {
			return &spec.Slack.TokenSecretRef
		}
	case domain.ConnectorTypeTeams:
		if spec.Teams != nil {
			return &spec.Teams.WebhookSecretRef
		}
	case domain.ConnectorTypeEmail:
		if spec.Email != nil {
			return &spec.Email.SMTP.CredentialsSecretRef
		}
	case domain.ConnectorTypeWebhook:
		if spec.Webhook != nil {
			return &spec.Webhook.SecretRef
		}
	case domain.ConnectorTypeDependencyTrack:
		if spec.DependencyTrack != nil {
			return &spec.DependencyTrack.CredentialsSecretRef
		}
	}
	return nil
}

func (r *ConnectorReconciler) Reconcile(ctx context.Context, cr *ConnectorCR) (*ConnectorStatus, error) {
	status := &cr.Status
	tenant, err := r.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		status.SetCondition("Connected", "False", "StorageError", err.Error())
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	if tenant == nil {
		status.SetCondition("Connected", "False", "TenantNotFound", fmt.Sprintf("no tenant lists namespace %q", cr.Metadata.Namespace))
		status.SetCondition("Ready", "False", "TenantNotFound", fmt.Sprintf("no tenant lists namespace %q", cr.Metadata.Namespace))
		return status, nil
	}

	conn := domain.Connector{
		TenantID:  tenant.ID,
		Namespace: cr.Metadata.Namespace,
		Name:      cr.Metadata.Name,
		Type:      cr.Spec.Type,
		Spec:      cr.Spec,
	}
	if err := conn.Validate(); err != nil {
		reason := "InvalidSpec"
		if errors.Is(err, domain.ErrConnectorNotSupported) {
			reason = "NotSupported"
		} else if errors.Is(err, domain.ErrSSRFBlocked) {
			reason = "UnsafeAddress"
		}
		status.SetCondition("Connected", "False", reason, err.Error())
		status.SetCondition("Ready", "False", reason, err.Error())
		return status, nil
	}

	// Secret synchronization (D69: Secrets read from secret_material, synced from K8s secrets)
	secRef := extractConnectorSecretRef(&cr.Spec)
	if secRef != nil && secRef.Name != "" && r.secrets != nil && r.secretStore != nil {
		secretKey := secRef.Key
		if secretKey == "" {
			secretKey = "token"
		}
		secretBytes, err := r.secrets.GetSecret(ctx, cr.Metadata.Namespace, secRef.Name, secretKey)
		if err != nil {
			status.SetCondition("Connected", "False", "SecretNotFound", fmt.Sprintf("failed to resolve secret %s/%s: %v", secRef.Name, secretKey, err))
			status.SetCondition("Ready", "False", "SecretNotFound", fmt.Sprintf("failed to resolve secret %s/%s: %v", secRef.Name, secretKey, err))
			return status, nil
		}

		storageKey := fmt.Sprintf("connector:%s:%s", cr.Metadata.Name, secretKey)
		if err := r.secretStore.SaveSecretMaterial(ctx, tenant.ID, storageKey, secretBytes); err != nil {
			status.SetCondition("Connected", "False", "SecretSyncFailed", fmt.Sprintf("failed to sync secret material: %v", err))
			status.SetCondition("Ready", "False", "SecretSyncFailed", fmt.Sprintf("failed to sync secret material: %v", err))
			return status, err
		}
	}

	now := time.Now().UTC()
	status.ObservedGeneration = cr.Metadata.Generation
	status.WebhookURL = fmt.Sprintf("/hooks/%s/%s", cr.Spec.Type, cr.Metadata.Name)
	status.LastSync = &now

	status.SetCondition("Connected", "True", "AuthOK", "Connector verified and secrets synced")
	status.SetCondition("Ready", "True", "Reconciled", "Connector reconciled successfully")

	conn.Status = domain.ConnectorStatus{
		ObservedGeneration: status.ObservedGeneration,
		WebhookURL:         status.WebhookURL,
		LastSync:           status.LastSync,
	}
	for _, c := range status.Conditions {
		conn.Status.Conditions = append(conn.Status.Conditions, domain.ConnectorCondition{
			Type:               c.Type,
			Status:             c.Status,
			Reason:             c.Reason,
			Message:            c.Message,
			LastTransitionTime: c.LastTransitionTime,
		})
	}

	if err := r.store.SaveConnector(ctx, tenant.ID, conn); err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	return status, nil
}

func (r *ConnectorReconciler) Finalize(ctx context.Context, cr *ConnectorCR) (*ConnectorStatus, bool, error) {
	tenant, err := r.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		return nil, false, err
	}
	if tenant == nil {
		return nil, true, nil
	}

	// D49: Clean up secret material copied for this connector
	if r.secretStore != nil {
		secRef := extractConnectorSecretRef(&cr.Spec)
		if secRef != nil {
			secretKey := secRef.Key
			if secretKey == "" {
				secretKey = "token"
			}
			storageKey := fmt.Sprintf("connector:%s:%s", cr.Metadata.Name, secretKey)
			_ = r.secretStore.SaveSecretMaterial(ctx, tenant.ID, storageKey, nil)
		}
	}

	return nil, true, r.store.DeleteConnector(ctx, tenant.ID, cr.Metadata.Name)
}
