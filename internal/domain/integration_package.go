package domain

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ErrPackageNotFound is returned for an IntegrationPackage that is not installed.
var ErrPackageNotFound = errors.New("integration package not found")

// IntegrationPackageRecord is an installed tier-1 package (D94). Error is set when the spec does not validate:
// the package is kept, shown with its error, and not used.
type IntegrationPackageRecord struct {
	TenantID   uuid.UUID `json:"-"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Runtime    string    `json:"runtime"`
	Version    string    `json:"version"`
	Spec       []byte    `json:"-"`
	Error      string    `json:"error,omitempty"`
	Generation int64     `json:"-"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// IntegrationPackages stores installed packages.
type IntegrationPackages interface {
	SaveIntegrationPackage(ctx context.Context, p IntegrationPackageRecord) error
	GetIntegrationPackage(ctx context.Context, tenantID uuid.UUID, name string) (*IntegrationPackageRecord, error)
	ListIntegrationPackages(ctx context.Context, tenantID uuid.UUID) ([]IntegrationPackageRecord, error)
	DeleteIntegrationPackage(ctx context.Context, tenantID uuid.UUID, name string) error
}

// StoredParserObject captures a cluster-wide or tenant-scoped parser (docs/29).
type StoredParserObject struct {
	Origin    string    `json:"origin"` // "cluster" or "tenant"
	Name      string    `json:"name"`
	Spec      []byte    `json:"spec"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ParserStore lists cluster and tenant parsers.
type ParserStore interface {
	ListParsers(ctx context.Context, tenantID uuid.UUID) ([]StoredParserObject, error)
}

// PackageMap is an in-memory IntegrationPackages, embedded by the in-memory stores.
type PackageMap struct {
	mu   sync.RWMutex
	pkgs map[string]IntegrationPackageRecord
}

func pkgKey(t uuid.UUID, name string) string { return t.String() + "/" + name }

func (m *PackageMap) SaveIntegrationPackage(_ context.Context, p IntegrationPackageRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pkgs == nil {
		m.pkgs = map[string]IntegrationPackageRecord{}
	}
	p.UpdatedAt = time.Now().UTC()
	m.pkgs[pkgKey(p.TenantID, p.Name)] = p
	return nil
}

func (m *PackageMap) GetIntegrationPackage(_ context.Context, tenantID uuid.UUID, name string) (*IntegrationPackageRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.pkgs[pkgKey(tenantID, name)]
	if !ok {
		return nil, ErrPackageNotFound
	}
	return &p, nil
}

func (m *PackageMap) ListIntegrationPackages(_ context.Context, tenantID uuid.UUID) ([]IntegrationPackageRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []IntegrationPackageRecord
	for _, p := range m.pkgs {
		if p.TenantID == tenantID {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *PackageMap) DeleteIntegrationPackage(_ context.Context, tenantID uuid.UUID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pkgs, pkgKey(tenantID, name))
	return nil
}
