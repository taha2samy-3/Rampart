package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/risk"
)

var (
	ErrUnsupportedKind = errors.New("apply: unsupported resource kind")
	ErrInvalidYAML     = errors.New("apply: invalid resource definition")
	// ErrNamespaceOwned is returned when a namespace is already listed by another Tenant (D20).
	ErrNamespaceOwned = errors.New("apply: namespace is owned by another tenant")
)

// ResourceHeader captures generic Kubernetes/Rampart CRD metadata.
type ResourceHeader struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec json.RawMessage `json:"spec"`
}

// ConfigStore abstracts storage of reconciled configuration entities.
type ConfigStore interface {
	SaveTenant(ctx context.Context, tenant domain.Tenant) error
	GetTenantBySlug(ctx context.Context, slug string) (*domain.Tenant, error)
	// ClaimNamespace binds a namespace to a tenant (D20). It fails with ErrNamespaceOwned when
	// another tenant already owns it.
	ClaimNamespace(ctx context.Context, tenantID uuid.UUID, namespace string) error
	// GetTenantByNamespace returns the tenant that owns the namespace, or nil (D20).
	GetTenantByNamespace(ctx context.Context, namespace string) (*domain.Tenant, error)
	SaveApplication(ctx context.Context, app domain.Application) error
	GetApplicationBySlug(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Application, error)
	SaveScanSource(ctx context.Context, tenantID uuid.UUID, name string, scannerFamily string, policy *domain.IngestionPolicy) (uuid.UUID, error)
	// SaveSLAPolicy stores an SLAPolicy of a tenant. A spec that failed validation is stored with its error, so
	// the object's status can say why it is not applied (docs/16 D41).
	SaveSLAPolicy(ctx context.Context, tenantID uuid.UUID, p PolicyObject) error
	// SaveRiskPolicy stores a RiskPolicy of a tenant the same way (D62).
	SaveRiskPolicy(ctx context.Context, tenantID uuid.UUID, p PolicyObject) error
	// SaveClusterPolicy stores a ClusterRiskPolicy (kind "risk") or ClusterSLAPolicy (kind "sla") (D62).
	SaveClusterPolicy(ctx context.Context, kind string, p PolicyObject) error
	// SaveIdentityProvider stores a tenant-scoped or cluster-scoped (tenantID == nil) IdentityProvider (D8, D27, D64).
	SaveIdentityProvider(ctx context.Context, tenantID *uuid.UUID, idp domain.IdentityProvider) error
	GetIdentityProvider(ctx context.Context, tenantID *uuid.UUID, name string) (*domain.IdentityProvider, error)
	DeleteIdentityProvider(ctx context.Context, tenantID *uuid.UUID, name string) error
	SaveConnector(ctx context.Context, tenantID uuid.UUID, conn domain.Connector) error
	GetConnector(ctx context.Context, tenantID uuid.UUID, name string) (*domain.Connector, error)
	DeleteConnector(ctx context.Context, tenantID uuid.UUID, name string) error
	UpdateConnectorStatus(ctx context.Context, tenantID uuid.UUID, name string, status domain.ConnectorStatus) error
	Finalizer
}

// Finalizer is what deleting a custom resource asks of the store (docs/16 D21, D49). Every method can be called
// again after a failure: the operator retries a finalizer until it succeeds.
type Finalizer interface {
	// OrphanApplication keeps the application and its findings and marks it as no longer managed by a resource.
	OrphanApplication(ctx context.Context, tenantID uuid.UUID, slug string) error
	// DisableScanSource disables the source, revokes the tokens bound to it and removes its secret material.
	// History is kept. It returns how many tokens it revoked.
	DisableScanSource(ctx context.Context, tenantID uuid.UUID, name string) (int, error)
	// DeleteSLAPolicy removes the policy; the due dates of the tenant are recomputed against what is left.
	DeleteSLAPolicy(ctx context.Context, tenantID uuid.UUID, namespace, name string) error
	// DeleteRiskPolicy removes the policy; the tenant is re-scored against what is left.
	DeleteRiskPolicy(ctx context.Context, tenantID uuid.UUID, namespace, name string) error
	// DeleteClusterPolicy removes a cluster policy; every tenant is re-scored against what is left.
	DeleteClusterPolicy(ctx context.Context, kind, name string) error
	// TenantHasData says whether the tenant has applications, assets, findings or ingest runs.
	TenantHasData(ctx context.Context, tenantID uuid.UUID) (bool, error)
	// PurgeTenant deletes the tenant and everything that belongs to it.
	PurgeTenant(ctx context.Context, tenantID uuid.UUID) error
}

// PolicyObject is a policy as the control plane hands it to the store.
type PolicyObject struct {
	Namespace  string
	Name       string
	Spec       []byte
	Generation int64
	// Error is why the spec was refused; empty when it is valid.
	Error string
}

// Applier turns declarative resources into active configuration (normative D3).
type Applier struct {
	store ConfigStore
}

// NewApplier creates a new config applier.
func NewApplier(store ConfigStore) *Applier {
	return &Applier{store: store}
}

// ApplyDocument parses and reconciles a single JSON/YAML resource definition.
type accessBindingStore interface {
	UpsertAccessBinding(ctx context.Context, tenantID uuid.UUID, b *domain.AccessBinding) error
}

func (a *Applier) ApplyDocument(ctx context.Context, raw []byte) (string, error) {
	var generic map[string]any
	if err := yaml.Unmarshal(raw, &generic); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidYAML, err)
	}

	jsonBytes, err := json.Marshal(generic)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidYAML, err)
	}

	var header ResourceHeader
	if err := json.Unmarshal(jsonBytes, &header); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidYAML, err)
	}

	if header.Metadata.Name == "" {
		return "", fmt.Errorf("%w: metadata.name is required", ErrInvalidYAML)
	}

	lk := strings.ToLower(header.Kind)
	switch lk {
	case "tenant":
		var spec struct {
			DisplayName string   `json:"displayName"`
			Namespaces  []string `json:"namespaces"`
		}
		_ = json.Unmarshal(header.Spec, &spec)
		displayName := spec.DisplayName
		if displayName == "" {
			displayName = header.Metadata.Name
		}

		// Check if tenant exists
		existing, _ := a.store.GetTenantBySlug(ctx, header.Metadata.Name)
		tenantID := domain.NewID()
		if existing != nil {
			tenantID = existing.ID
		}

		t := domain.Tenant{
			ID:           tenantID,
			Slug:         header.Metadata.Name,
			DisplayName:  displayName,
			K8sNamespace: header.Metadata.Namespace,
			CreatedAt:    time.Now().UTC(),
		}
		if err := a.store.SaveTenant(ctx, t); err != nil {
			return "", err
		}
		for _, ns := range spec.Namespaces {
			if err := a.store.ClaimNamespace(ctx, t.ID, ns); err != nil {
				return "", fmt.Errorf("apply: tenant %q cannot claim namespace %q: %w", t.Slug, ns, err)
			}
		}
		return fmt.Sprintf("tenant.rampart.aspm.dev/%s configured", t.Slug), nil

	case "slapolicy":
		namespace := defaultNamespace(header.Metadata.Namespace)
		tenant, err := a.store.GetTenantByNamespace(ctx, namespace)
		if err != nil || tenant == nil {
			return "", fmt.Errorf("apply: no tenant owns namespace %q (TenantNotFound)", namespace)
		}
		obj := PolicyObject{Namespace: namespace, Name: header.Metadata.Name, Spec: header.Spec}
		if _, err := domain.ParseSLAPolicySpec(header.Spec); err != nil {
			obj.Error = err.Error()
		}
		if err := a.store.SaveSLAPolicy(ctx, tenant.ID, obj); err != nil {
			return "", err
		}
		if obj.Error != "" {
			return "", fmt.Errorf("apply: slapolicy %q was stored but is not applied: %s", header.Metadata.Name, obj.Error)
		}
		return fmt.Sprintf("slapolicy.rampart.aspm.dev/%s configured", header.Metadata.Name), nil

	case "riskpolicy":
		namespace := defaultNamespace(header.Metadata.Namespace)
		tenant, err := a.store.GetTenantByNamespace(ctx, namespace)
		if err != nil || tenant == nil {
			return "", fmt.Errorf("apply: no tenant owns namespace %q (TenantNotFound)", namespace)
		}
		obj := PolicyObject{Namespace: namespace, Name: header.Metadata.Name, Spec: header.Spec}
		if _, err := risk.ParseRiskPolicySpec(header.Spec); err != nil {
			obj.Error = err.Error()
		}
		if err := a.store.SaveRiskPolicy(ctx, tenant.ID, obj); err != nil {
			return "", err
		}
		if obj.Error != "" {
			return "", fmt.Errorf("apply: riskpolicy %q was stored but is not applied: %s", header.Metadata.Name, obj.Error)
		}
		return fmt.Sprintf("riskpolicy.rampart.aspm.dev/%s configured", header.Metadata.Name), nil

	case "clusterriskpolicy", "clusterslapolicy":
		kind, parse := "risk", func(b []byte) error { _, err := risk.ParseRiskPolicySpec(b); return err }
		if lk == "clusterslapolicy" {
			kind, parse = "sla", func(b []byte) error { _, err := domain.ParseSLAPolicySpec(b); return err }
		}
		obj := PolicyObject{Name: header.Metadata.Name, Spec: header.Spec}
		if err := parse(header.Spec); err != nil {
			obj.Error = err.Error()
		}
		if err := a.store.SaveClusterPolicy(ctx, kind, obj); err != nil {
			return "", err
		}
		if obj.Error != "" {
			return "", fmt.Errorf("apply: %s %q was stored but is not applied: %s", lk, header.Metadata.Name, obj.Error)
		}
		return fmt.Sprintf("%s.rampart.aspm.dev/%s configured", lk, header.Metadata.Name), nil

	case "application":
		var spec domain.ApplicationSpec
		if err := json.Unmarshal(header.Spec, &spec); err != nil {
			return "", fmt.Errorf("apply: application %q: %w", header.Metadata.Name, err)
		}

		namespace := defaultNamespace(header.Metadata.Namespace)
		tenant, err := a.store.GetTenantByNamespace(ctx, namespace)
		if err != nil || tenant == nil {
			return "", fmt.Errorf("apply: no tenant owns namespace %q (TenantNotFound)", namespace)
		}

		existing, _ := a.store.GetApplicationBySlug(ctx, tenant.ID, header.Metadata.Name)
		appID := domain.NewID()
		if existing != nil {
			appID = existing.ID
		}

		app, err := spec.ToApplication(appID, tenant.ID, header.Metadata.Name)
		if err != nil {
			return "", fmt.Errorf("apply: application %q: %w", header.Metadata.Name, err)
		}
		app.CreatedAt = time.Now().UTC()

		if err := a.store.SaveApplication(ctx, app); err != nil {
			return "", err
		}
		return fmt.Sprintf("application.rampart.aspm.dev/%s configured", app.Slug), nil

	case "scansource":
		var spec struct {
			ScannerFamily   string                  `json:"scannerFamily"`
			Type            string                  `json:"type"`
			IngestionPolicy *domain.IngestionPolicy `json:"ingestionPolicy"`
		}
		_ = json.Unmarshal(header.Spec, &spec)

		namespace := defaultNamespace(header.Metadata.Namespace)
		tenant, err := a.store.GetTenantByNamespace(ctx, namespace)
		if err != nil || tenant == nil {
			return "", fmt.Errorf("apply: no tenant owns namespace %q (TenantNotFound)", namespace)
		}

		if spec.IngestionPolicy != nil {
			if err := spec.IngestionPolicy.Validate(); err != nil {
				return "", fmt.Errorf("apply: invalid ingestionPolicy: %w", err)
			}
		}

		id, err := a.store.SaveScanSource(ctx, tenant.ID, header.Metadata.Name, spec.ScannerFamily, spec.IngestionPolicy)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("scansource.rampart.aspm.dev/%s configured (id=%s)", header.Metadata.Name, id), nil

	case "accessbinding":
		var spec struct {
			Role     string `json:"role"`
			Subjects []struct {
				Kind    string `json:"kind"`
				IDP     string `json:"idp"`
				Name    string `json:"name"`
				Subject string `json:"subject"`
			} `json:"subjects"`
			Scope struct {
				Tenant       bool     `json:"tenant"`
				Hierarchy    []string `json:"hierarchy"`
				Applications []string `json:"applications"`
			} `json:"scope"`
		}
		if err := json.Unmarshal(header.Spec, &spec); err != nil {
			return "", fmt.Errorf("apply: accessbinding %q: %w", header.Metadata.Name, err)
		}
		namespace := defaultNamespace(header.Metadata.Namespace)
		tenant, err := a.store.GetTenantByNamespace(ctx, namespace)
		if err != nil || tenant == nil {
			return "", fmt.Errorf("apply: no tenant owns namespace %q (TenantNotFound)", namespace)
		}
		bs, ok := a.store.(accessBindingStore)
		if !ok {
			return "", fmt.Errorf("apply: store does not support access bindings")
		}
		role, rok := auth.ParseRole(spec.Role)
		if !rok {
			return "", fmt.Errorf("apply: unknown role %q", spec.Role)
		}

		for _, sub := range spec.Subjects {
			subject := sub.Subject
			if subject == "" {
				subject = sub.Name
			}
			if subject == "" {
				continue
			}

			if spec.Scope.Tenant {
				b := &domain.AccessBinding{
					Subject:     subject,
					SubjectKind: strings.ToLower(sub.Kind),
					IdP:         sub.IDP,
					Role:        string(role),
					TenantScope: true,
					ManagedBy:   "k8s",
				}
				if err := bs.UpsertAccessBinding(ctx, tenant.ID, b); err != nil {
					return "", err
				}
			}
			for _, h := range spec.Scope.Hierarchy {
				b := &domain.AccessBinding{
					Subject:       subject,
					SubjectKind:   strings.ToLower(sub.Kind),
					IdP:           sub.IDP,
					Role:          string(role),
					HierarchyPath: h,
					ManagedBy:     "k8s",
				}
				if err := bs.UpsertAccessBinding(ctx, tenant.ID, b); err != nil {
					return "", err
				}
			}
			for _, appSlug := range spec.Scope.Applications {
				app, err := a.store.GetApplicationBySlug(ctx, tenant.ID, appSlug)
				if err != nil || app == nil {
					return "", fmt.Errorf("apply: application %q not found", appSlug)
				}
				b := &domain.AccessBinding{
					Subject:       subject,
					SubjectKind:   strings.ToLower(sub.Kind),
					IdP:           sub.IDP,
					Role:          string(role),
					ApplicationID: app.ID,
					ManagedBy:     "k8s",
				}
				if err := bs.UpsertAccessBinding(ctx, tenant.ID, b); err != nil {
					return "", err
				}
			}
		}
		return fmt.Sprintf("accessbinding.rampart.aspm.dev/%s configured", header.Metadata.Name), nil

	case "clusteraccessbinding":
		var spec struct {
			Role     string `json:"role"`
			Subjects []struct {
				Kind    string `json:"kind"`
				IDP     string `json:"idp"`
				Name    string `json:"name"`
				Subject string `json:"subject"`
			} `json:"subjects"`
			Scope struct {
				AllTenants bool     `json:"allTenants"`
				Tenants    []string `json:"tenants"`
			} `json:"scope"`
		}
		if err := json.Unmarshal(header.Spec, &spec); err != nil {
			return "", fmt.Errorf("apply: clusteraccessbinding %q: %w", header.Metadata.Name, err)
		}
		role, rok := auth.ParseRole(spec.Role)
		if !rok {
			return "", fmt.Errorf("apply: unknown role %q", spec.Role)
		}
		bs, ok := a.store.(accessBindingStore)
		if !ok {
			return "", fmt.Errorf("apply: store does not support access bindings")
		}
		var tenantIDs []uuid.UUID
		if spec.Scope.AllTenants {
			if lister, ok := a.store.(interface {
				ListTenantIDs(ctx context.Context) ([]uuid.UUID, error)
			}); ok {
				tenantIDs, _ = lister.ListTenantIDs(ctx)
			}
		} else {
			for _, tSlug := range spec.Scope.Tenants {
				t, err := a.store.GetTenantBySlug(ctx, tSlug)
				if err == nil && t != nil {
					tenantIDs = append(tenantIDs, t.ID)
				}
			}
		}
		for _, tID := range tenantIDs {
			for _, sub := range spec.Subjects {
				subject := sub.Subject
				if subject == "" {
					subject = sub.Name
				}
				if subject == "" {
					continue
				}
				b := &domain.AccessBinding{
					Subject:     subject,
					SubjectKind: strings.ToLower(sub.Kind),
					IdP:         sub.IDP,
					Role:        string(role),
					TenantScope: true,
					ManagedBy:   "k8s",
				}
				_ = bs.UpsertAccessBinding(ctx, tID, b)
			}
		}
		return fmt.Sprintf("clusteraccessbinding.rampart.aspm.dev/%s configured", header.Metadata.Name), nil

	case "identityprovider":
		tenant, err := a.store.GetTenantByNamespace(ctx, header.Metadata.Namespace)
		if err != nil {
			return "", err
		}
		if tenant == nil {
			return "", fmt.Errorf("apply: no tenant lists namespace %q", header.Metadata.Namespace)
		}
		var spec domain.IdentityProviderSpec
		if err := json.Unmarshal(header.Spec, &spec); err != nil {
			return "", fmt.Errorf("apply: invalid identityprovider spec: %w", err)
		}
		displayName := spec.DisplayName
		if displayName == "" {
			displayName = header.Metadata.Name
		}
		idp := domain.IdentityProvider{
			TenantID:    &tenant.ID,
			Namespace:   header.Metadata.Namespace,
			Name:        header.Metadata.Name,
			DisplayName: displayName,
			Type:        spec.Type,
			Spec:        spec,
			Status: domain.IdentityProviderStatus{
				RedirectURI: fmt.Sprintf("/auth/oidc/%s/callback", header.Metadata.Name),
			},
		}
		if err := idp.Validate(); err != nil {
			return "", fmt.Errorf("apply: identityprovider validation failed: %w", err)
		}

		// Preserve existing domain approvals if already present (D27)
		existing, _ := a.store.GetIdentityProvider(ctx, &tenant.ID, header.Metadata.Name)
		existingApproved := make(map[string]domain.DomainClaimStatus)
		if existing != nil {
			for _, d := range existing.Status.Domains {
				clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d.Domain), "@"))
				if d.Approved {
					existingApproved[clean] = d
				}
			}
		}

		for _, d := range spec.Login.EmailDomains {
			clean := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
			if prev, ok := existingApproved[clean]; ok {
				idp.Status.Domains = append(idp.Status.Domains, prev)
			} else {
				idp.Status.Domains = append(idp.Status.Domains, domain.DomainClaimStatus{
					Domain:   clean,
					Approved: false, // Requires platform admin approval per D27
				})
			}
		}
		if err := a.store.SaveIdentityProvider(ctx, &tenant.ID, idp); err != nil {
			return "", err
		}
		return fmt.Sprintf("identityprovider.rampart.aspm.dev/%s configured", header.Metadata.Name), nil

	case "clusteridentityprovider":
		var spec domain.IdentityProviderSpec
		if err := json.Unmarshal(header.Spec, &spec); err != nil {
			return "", fmt.Errorf("apply: invalid clusteridentityprovider spec: %w", err)
		}
		displayName := spec.DisplayName
		if displayName == "" {
			displayName = header.Metadata.Name
		}
		idp := domain.IdentityProvider{
			TenantID:    nil,
			Name:        header.Metadata.Name,
			DisplayName: displayName,
			Type:        spec.Type,
			Spec:        spec,
			Status: domain.IdentityProviderStatus{
				RedirectURI: fmt.Sprintf("/auth/oidc/%s/callback", header.Metadata.Name),
			},
		}
		if err := idp.Validate(); err != nil {
			return "", fmt.Errorf("apply: clusteridentityprovider validation failed: %w", err)
		}
		if err := a.store.SaveIdentityProvider(ctx, nil, idp); err != nil {
			return "", err
		}
		return fmt.Sprintf("clusteridentityprovider.rampart.aspm.dev/%s configured", header.Metadata.Name), nil

	case "connector":
		tenant, err := a.store.GetTenantByNamespace(ctx, header.Metadata.Namespace)
		if err != nil {
			return "", err
		}
		if tenant == nil {
			return "", fmt.Errorf("apply: no tenant lists namespace %q", header.Metadata.Namespace)
		}
		var spec domain.ConnectorSpec
		if err := json.Unmarshal(header.Spec, &spec); err != nil {
			return "", fmt.Errorf("apply: invalid connector spec: %w", err)
		}
		conn := domain.Connector{
			TenantID:  tenant.ID,
			Namespace: header.Metadata.Namespace,
			Name:      header.Metadata.Name,
			Type:      spec.Type,
			Spec:      spec,
		}
		if err := conn.Validate(); err != nil {
			return "", fmt.Errorf("apply: connector validation failed: %w", err)
		}

		// Preserve existing status/conditions if already present
		existing, _ := a.store.GetConnector(ctx, tenant.ID, header.Metadata.Name)
		if existing != nil {
			conn.Status = existing.Status
		} else {
			conn.Status = domain.ConnectorStatus{
				WebhookURL: fmt.Sprintf("/hooks/%s/%s", spec.Type, header.Metadata.Name),
			}
		}

		if err := a.store.SaveConnector(ctx, tenant.ID, conn); err != nil {
			return "", err
		}
		return fmt.Sprintf("connector.rampart.aspm.dev/%s configured", header.Metadata.Name), nil

	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedKind, header.Kind)
	}
}

// ApplyMultiDocument decodes and applies one or more YAML or JSON resource definitions in sequence.
func (a *Applier) ApplyMultiDocument(ctx context.Context, raw []byte) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var list []json.RawMessage
		if err := json.Unmarshal(trimmed, &list); err == nil {
			var results []string
			for _, item := range list {
				res, err := a.ApplyDocument(ctx, item)
				if err != nil {
					return results, err
				}
				results = append(results, res)
			}
			return results, nil
		}
	}

	docs := bytes.Split(raw, []byte("\n---"))
	var results []string
	for _, doc := range docs {
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}
		res, err := a.ApplyDocument(ctx, doc)
		if err != nil {
			return results, err
		}
		results = append(results, res)
	}
	return results, nil
}

// defaultNamespace is the namespace of a resource applied without one (file mode).
func defaultNamespace(ns string) string {
	if ns == "" {
		return "default"
	}
	return ns
}

// MemoryConfigStore provides an in-memory implementation of ConfigStore.
type MemoryConfigStore struct {
	mu           sync.RWMutex
	orphaned     map[string]bool
	disabled     map[string]bool
	withData     map[uuid.UUID]bool
	purged       map[uuid.UUID]bool
	tenants      map[string]domain.Tenant
	applications map[string]domain.Application
	scanSources  map[string]uuid.UUID
	namespaces   map[string]uuid.UUID
	policies     map[string]PolicyObject
	idps         map[string]domain.IdentityProvider
	connectors   map[string]domain.Connector
}

// NewMemoryConfigStore creates a new in-memory config store.
func NewMemoryConfigStore() *MemoryConfigStore {
	return &MemoryConfigStore{
		tenants:      make(map[string]domain.Tenant),
		applications: make(map[string]domain.Application),
		scanSources:  make(map[string]uuid.UUID),
		namespaces:   make(map[string]uuid.UUID),
		policies:     make(map[string]PolicyObject),
		idps:         make(map[string]domain.IdentityProvider),
		connectors:   make(map[string]domain.Connector),
		orphaned:     make(map[string]bool),
		disabled:     make(map[string]bool),
		withData:     make(map[uuid.UUID]bool),
		purged:       make(map[uuid.UUID]bool),
	}
}

// OrphanApplication implements Finalizer.
func (m *MemoryConfigStore) OrphanApplication(ctx context.Context, tenantID uuid.UUID, slug string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orphaned[tenantID.String()+":"+slug] = true
	return nil
}

// DisableScanSource implements Finalizer.
func (m *MemoryConfigStore) DisableScanSource(ctx context.Context, tenantID uuid.UUID, name string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disabled[tenantID.String()+":"+name] = true
	return 0, nil
}

// DeleteSLAPolicy implements Finalizer.
func (m *MemoryConfigStore) DeleteSLAPolicy(ctx context.Context, tenantID uuid.UUID, namespace, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policies, tenantID.String()+":"+namespace+":"+name)
	return nil
}

// DeleteRiskPolicy implements Finalizer.
func (m *MemoryConfigStore) DeleteRiskPolicy(ctx context.Context, tenantID uuid.UUID, namespace, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policies, "risk:"+tenantID.String()+":"+namespace+":"+name)
	return nil
}

// DeleteIdentityProvider implements ConfigStore and Finalizer.
func (m *MemoryConfigStore) DeleteIdentityProvider(ctx context.Context, tenantID *uuid.UUID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := "cluster:" + name
	if tenantID != nil {
		key = "tenant:" + tenantID.String() + ":" + name
	}
	delete(m.idps, key)
	return nil
}

// SaveIdentityProvider implements ConfigStore.
func (m *MemoryConfigStore) SaveIdentityProvider(ctx context.Context, tenantID *uuid.UUID, idp domain.IdentityProvider) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := "cluster:" + idp.Name
	if tenantID != nil {
		key = "tenant:" + tenantID.String() + ":" + idp.Name
	}
	m.idps[key] = idp
	return nil
}

// GetIdentityProvider implements ConfigStore.
func (m *MemoryConfigStore) GetIdentityProvider(ctx context.Context, tenantID *uuid.UUID, name string) (*domain.IdentityProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if tenantID != nil {
		if idp, ok := m.idps["tenant:"+tenantID.String()+":"+name]; ok {
			return &idp, nil
		}
	}
	if idp, ok := m.idps["cluster:"+name]; ok {
		return &idp, nil
	}
	return nil, nil
}

// SaveConnector implements ConfigStore.
func (m *MemoryConfigStore) SaveConnector(ctx context.Context, tenantID uuid.UUID, conn domain.Connector) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectors[tenantID.String()+":"+conn.Name] = conn
	return nil
}

// GetConnector implements ConfigStore.
func (m *MemoryConfigStore) GetConnector(ctx context.Context, tenantID uuid.UUID, name string) (*domain.Connector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if conn, ok := m.connectors[tenantID.String()+":"+name]; ok {
		return &conn, nil
	}
	return nil, nil
}

// DeleteConnector implements ConfigStore.
func (m *MemoryConfigStore) DeleteConnector(ctx context.Context, tenantID uuid.UUID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.connectors, tenantID.String()+":"+name)
	return nil
}

// UpdateConnectorStatus implements ConfigStore.
func (m *MemoryConfigStore) UpdateConnectorStatus(ctx context.Context, tenantID uuid.UUID, name string, status domain.ConnectorStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID.String() + ":" + name
	if conn, ok := m.connectors[key]; ok {
		conn.Status = status
		conn.UpdatedAt = time.Now().UTC()
		m.connectors[key] = conn
	}
	return nil
}

// DeleteClusterPolicy implements Finalizer.
func (m *MemoryConfigStore) DeleteClusterPolicy(ctx context.Context, kind, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policies, "cluster:"+kind+":"+name)
	return nil
}

// TenantHasData implements Finalizer.
func (m *MemoryConfigStore) TenantHasData(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.withData[tenantID], nil
}

// PurgeTenant implements Finalizer.
func (m *MemoryConfigStore) PurgeTenant(ctx context.Context, tenantID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purged[tenantID] = true
	for slug, t := range m.tenants {
		if t.ID == tenantID {
			delete(m.tenants, slug)
		}
	}
	return nil
}

// SetHasData makes TenantHasData answer true for a tenant, for tests.
func (m *MemoryConfigStore) SetHasData(tenantID uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.withData[tenantID] = true
}

// Orphaned, Disabled and Purged tell what the finalizers did, for tests.
func (m *MemoryConfigStore) Orphaned(tenantID uuid.UUID, slug string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.orphaned[tenantID.String()+":"+slug]
}
func (m *MemoryConfigStore) Disabled(tenantID uuid.UUID, name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.disabled[tenantID.String()+":"+name]
}
func (m *MemoryConfigStore) Purged(tenantID uuid.UUID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.purged[tenantID]
}

// SaveSLAPolicy stores an SLAPolicy.
func (m *MemoryConfigStore) SaveSLAPolicy(ctx context.Context, tenantID uuid.UUID, p PolicyObject) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[tenantID.String()+":"+p.Namespace+":"+p.Name] = p
	return nil
}

// SaveRiskPolicy implements ConfigStore.
func (m *MemoryConfigStore) SaveRiskPolicy(ctx context.Context, tenantID uuid.UUID, p PolicyObject) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies["risk:"+tenantID.String()+":"+p.Namespace+":"+p.Name] = p
	return nil
}

// SaveClusterPolicy implements ConfigStore.
func (m *MemoryConfigStore) SaveClusterPolicy(ctx context.Context, kind string, p PolicyObject) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies["cluster:"+kind+":"+p.Name] = p
	return nil
}

// Policy returns a stored risk or cluster policy by its key ("risk:<tenant>:<ns>:<name>", "cluster:<kind>:<name>"),
// for tests.
func (m *MemoryConfigStore) Policy(key string) (PolicyObject, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.policies[key]
	return p, ok
}

// SLAPolicy returns a stored policy, for tests.
func (m *MemoryConfigStore) SLAPolicy(tenantID uuid.UUID, namespace, name string) (PolicyObject, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[tenantID.String()+":"+namespace+":"+name]
	return p, ok
}

func (m *MemoryConfigStore) SaveTenant(ctx context.Context, tenant domain.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenants[tenant.Slug] = tenant
	return nil
}

func (m *MemoryConfigStore) GetTenantBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tenants[slug]
	if !ok {
		return nil, nil
	}
	return &t, nil
}

func (m *MemoryConfigStore) SaveApplication(ctx context.Context, app domain.Application) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := app.TenantID.String() + ":" + app.Slug
	m.applications[key] = app
	return nil
}

func (m *MemoryConfigStore) GetApplicationBySlug(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Application, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := tenantID.String() + ":" + slug
	app, ok := m.applications[key]
	if !ok {
		return nil, nil
	}
	return &app, nil
}

func (m *MemoryConfigStore) SaveScanSource(ctx context.Context, tenantID uuid.UUID, name string, scannerFamily string, policy *domain.IngestionPolicy) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID.String() + ":" + name
	id, ok := m.scanSources[key]
	if !ok {
		id = domain.NewID()
		m.scanSources[key] = id
	}
	return id, nil
}

func (m *MemoryConfigStore) SaveTrustRules(ctx context.Context, tenantID, scanSourceID uuid.UUID, rules []domain.TrustRule) error {
	return nil
}

// Ensure interface compatibility
var _ = io.Reader(bytes.NewBuffer(nil))

func (m *MemoryConfigStore) ClaimNamespace(ctx context.Context, tenantID uuid.UUID, namespace string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if owner, ok := m.namespaces[namespace]; ok && owner != tenantID {
		return ErrNamespaceOwned
	}
	m.namespaces[namespace] = tenantID
	return nil
}

func (m *MemoryConfigStore) GetTenantByNamespace(ctx context.Context, namespace string) (*domain.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	owner, ok := m.namespaces[namespace]
	if !ok {
		return nil, nil
	}
	for _, t := range m.tenants {
		if t.ID == owner {
			cp := t
			return &cp, nil
		}
	}
	return nil, nil
}
