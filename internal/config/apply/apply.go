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
	"rampart/internal/domain"
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
	SaveScanSource(ctx context.Context, tenantID uuid.UUID, name string, scannerFamily string) (uuid.UUID, error)
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

	switch strings.ToLower(header.Kind) {
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

	case "application":
		var spec struct {
			DisplayName         string   `json:"displayName"`
			BusinessCriticality string   `json:"businessCriticality"`
			InternetFacing      bool     `json:"internetFacing"`
			Owners              []string `json:"owners"`
		}
		_ = json.Unmarshal(header.Spec, &spec)

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

		crit := spec.BusinessCriticality
		if crit == "" {
			crit = "medium"
		}

		app := domain.Application{
			ID:                  appID,
			TenantID:            tenant.ID,
			Slug:                header.Metadata.Name,
			Name:                spec.DisplayName,
			BusinessCriticality: crit,
			InternetFacing:      spec.InternetFacing,
			Owners:              spec.Owners,
			Lifecycle:           "production",
			CreatedAt:           time.Now().UTC(),
		}
		if app.Name == "" {
			app.Name = header.Metadata.Name
		}

		if err := a.store.SaveApplication(ctx, app); err != nil {
			return "", err
		}
		return fmt.Sprintf("application.rampart.aspm.dev/%s configured", app.Slug), nil

	case "scansource":
		var spec struct {
			ScannerFamily string `json:"scannerFamily"`
			Type          string `json:"type"`
		}
		_ = json.Unmarshal(header.Spec, &spec)

		namespace := defaultNamespace(header.Metadata.Namespace)
		tenant, err := a.store.GetTenantByNamespace(ctx, namespace)
		if err != nil || tenant == nil {
			return "", fmt.Errorf("apply: no tenant owns namespace %q (TenantNotFound)", namespace)
		}

		id, err := a.store.SaveScanSource(ctx, tenant.ID, header.Metadata.Name, spec.ScannerFamily)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("scansource.rampart.aspm.dev/%s configured (id=%s)", header.Metadata.Name, id), nil

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
	tenants      map[string]domain.Tenant
	applications map[string]domain.Application
	scanSources  map[string]uuid.UUID
	namespaces   map[string]uuid.UUID
}

// NewMemoryConfigStore creates a new in-memory config store.
func NewMemoryConfigStore() *MemoryConfigStore {
	return &MemoryConfigStore{
		tenants:      make(map[string]domain.Tenant),
		applications: make(map[string]domain.Application),
		scanSources:  make(map[string]uuid.UUID),
		namespaces:   make(map[string]uuid.UUID),
	}
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

func (m *MemoryConfigStore) SaveScanSource(ctx context.Context, tenantID uuid.UUID, name string, scannerFamily string) (uuid.UUID, error) {
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
