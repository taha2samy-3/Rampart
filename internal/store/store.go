package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
)

// CloseScope is aliased to domain.CloseScope for convenience.
type CloseScope = domain.CloseScope

// Store defines the comprehensive persistence contract for Rampart Phase 0 and Phase 1.
type Store interface {
	// People, memberships and browser sessions (D8, doc 14)
	auth.IdentityStore

	// Transactions and locks (D13). The Store passed to fn joins one transaction.
	InTenantTx(ctx context.Context, tenantID uuid.UUID, fn func(Store) error) error
	LockScope(ctx context.Context, scope CloseScope) error
	RecomputeOccurrenceCounts(ctx context.Context, tenantID uuid.UUID, findingIDs []uuid.UUID) error
	EnsureScanSource(ctx context.Context, tenantID uuid.UUID, ref string) (uuid.UUID, error)

	// Finding & Occurrence Merge Engine (D12, D13)
	GetFindingsByKeys(ctx context.Context, tenantID uuid.UUID, keys []string) (map[string]*domain.Finding, error)
	UpsertFindings(ctx context.Context, tenantID uuid.UUID, findings []*domain.Finding) error
	UpsertOccurrences(ctx context.Context, occurrences []*domain.Occurrence) error
	GetActiveScopeOccurrences(ctx context.Context, scope CloseScope) ([]*domain.Occurrence, error)
	UpdateOccurrencesPresence(ctx context.Context, tenantID uuid.UUID, occurrenceIDs []uuid.UUID, present bool) error
	GetActiveScopeFindings(ctx context.Context, tenantID uuid.UUID, assetID uuid.UUID, track string) ([]*domain.Finding, error)
	CountPresentOccurrences(ctx context.Context, tenantID uuid.UUID, findingID uuid.UUID) (int, error)
	CountPresentOccurrencesBatch(ctx context.Context, tenantID uuid.UUID, findingIDs []uuid.UUID) (map[uuid.UUID]int, error)
	CheckScopeOrdering(scope CloseScope, scanFinished time.Time) (bool, error)
	RecordFindingEvents(ctx context.Context, tenantID uuid.UUID, events []*domain.FindingEvent) error
	GetFindingEvents(ctx context.Context, tenantID, findingID uuid.UUID) ([]*domain.FindingEvent, error)

	// Query / Explorer API (D14, D16)
	ListFindings(ctx context.Context, tenantID uuid.UUID) ([]*domain.Finding, error)
	GetFinding(ctx context.Context, tenantID, findingID uuid.UUID) (*domain.Finding, []*domain.Occurrence, error)

	// Asset, Application & Track Resolution (D10)
	LookupAsset(ctx context.Context, tenantID uuid.UUID, assetType domain.AssetType, key string) (*domain.Asset, error)
	CreateAsset(ctx context.Context, asset *domain.Asset) error
	LookupApplication(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Application, error)
	CreateApplication(ctx context.Context, app *domain.Application) error

	// Ingest Run & Ephemeral Results (D2, D10, D13)
	CreateIngestRun(ctx context.Context, run *domain.IngestRun) error
	GetIngestRun(ctx context.Context, tenantID, runID uuid.UUID) (*domain.IngestRun, error)
	UpdateIngestRun(ctx context.Context, run *domain.IngestRun) error
	RecordRunScope(ctx context.Context, scope *domain.IngestRunScope) error
	RecordRunResult(ctx context.Context, result *domain.IngestRunResult) error

	// SBOM & Dependency Graph (docs/12)
	SaveSBOM(ctx context.Context, sbom *domain.SBOM, components []domain.SBOMComponent) error
	GetSBOM(ctx context.Context, tenantID, assetID uuid.UUID) (*domain.SBOM, []domain.SBOMComponent, error)

	// Tokens / Authentication (D8)
	LookupTokenByHash(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*auth.TokenRecord, error)
	SaveToken(ctx context.Context, record *auth.TokenRecord) error

	// Tenant Bootstrap & Verification (Phase 0)
	CreateTenant(ctx context.Context, tenant *domain.Tenant) error
	GetTenant(ctx context.Context, tenantID uuid.UUID) (*domain.Tenant, error)
}
