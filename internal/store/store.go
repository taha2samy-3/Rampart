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
// RunPosition is where a page of runs ends: the creation time and id of its last run.
type RunPosition struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

type Store interface {
	// People, memberships and browser sessions (D8, doc 14)
	auth.IdentityStore
	auth.LocalAdminStore // break-glass local administrator (D3)
	auth.AuditStore

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
	// GetDispositionedScopeFindings returns the findings of a scope that a person decided on (risk_accepted,
	// not_affected, out_of_scope, duplicate) and that are still detected. When no scanner reports them any more
	// their detection becomes absent, and their disposition stays (docs/16 D18).
	GetDispositionedScopeFindings(ctx context.Context, tenantID, assetID uuid.UUID, track string) ([]*domain.Finding, error)
	CountPresentOccurrences(ctx context.Context, tenantID uuid.UUID, findingID uuid.UUID) (int, error)
	CountPresentOccurrencesBatch(ctx context.Context, tenantID uuid.UUID, findingIDs []uuid.UUID) (map[uuid.UUID]int, error)
	CheckScopeOrdering(scope CloseScope, scanFinished time.Time) (bool, error)
	RecordFindingEvents(ctx context.Context, tenantID uuid.UUID, events []*domain.FindingEvent) error
	GetFindingEvents(ctx context.Context, tenantID, findingID uuid.UUID) ([]*domain.FindingEvent, error)

	// Aliases and correlation (D11, D19, D24)
	// CanonicalVulnIDs maps each given identifier to its canonical id (the CVE it is an alias of). Identifiers
	// without a known alias are absent from the result.
	CanonicalVulnIDs(ctx context.Context, tenantID uuid.UUID, ids []string) (map[string]string, error)
	// ListCorrelated returns the other findings that share the correlation key of the given finding.
	ListCorrelated(ctx context.Context, tenantID, findingID uuid.UUID) ([]*domain.Finding, error)

	// UpdateFindingTriage writes a human decision and its events together, only if the finding is still at
	// expectedVersion (ErrVersionConflict otherwise).
	UpdateFindingTriage(ctx context.Context, tenantID uuid.UUID, f *domain.Finding, expectedVersion int, events []*domain.FindingEvent) error

	// Risk acceptance and tenant settings (docs/06 section 6, D39)
	CreateRiskAcceptance(ctx context.Context, tenantID uuid.UUID, ra *domain.RiskAcceptance) error
	GetRiskAcceptance(ctx context.Context, tenantID, id uuid.UUID) (*domain.RiskAcceptance, error)
	ListRiskAcceptances(ctx context.Context, tenantID uuid.UUID, status domain.RiskAcceptanceStatus, limit int) ([]*domain.RiskAcceptance, error)
	// SetRiskAcceptanceStatus moves an acceptance from `from` to `to`, only if it is still in `from`
	// (ErrVersionConflict otherwise), so two approvers cannot both decide.
	SetRiskAcceptanceStatus(ctx context.Context, tenantID, id uuid.UUID, from, to domain.RiskAcceptanceStatus, by, note string, at time.Time) error
	// FindingsUnderAcceptance returns, for the given findings, the pending or approved acceptance that covers each.
	FindingsUnderAcceptance(ctx context.Context, tenantID uuid.UUID, findingIDs []uuid.UUID) (map[uuid.UUID]uuid.UUID, error)
	// ListDueAcceptances returns the approved acceptances whose expiry has passed.
	ListDueAcceptances(ctx context.Context, tenantID uuid.UUID, now time.Time) ([]*domain.RiskAcceptance, error)
	// TenantsWithDueAcceptances lists, across tenants, those that have an approved acceptance past its expiry.
	// It needs a role that sees every tenant (rampart_system).
	TenantsWithDueAcceptances(ctx context.Context, now time.Time) ([]uuid.UUID, error)
	GetTenantSettings(ctx context.Context, tenantID uuid.UUID) (domain.TenantSettings, error)
	SaveTenantSettings(ctx context.Context, tenantID uuid.UUID, settings domain.TenantSettings) error

	// SLA policy objects (D41): the spec the engine uses for a tenant, and the recompute flag.
	GetSLAPolicySpec(ctx context.Context, tenantID uuid.UUID) (spec []byte, found bool, err error)
	// GetRiskPolicySpec is the RiskPolicy in force: the tenant's, else the cluster default (D62).
	GetRiskPolicySpec(ctx context.Context, tenantID uuid.UUID) (spec []byte, found bool, err error)
	TenantsNeedingSLARecompute(ctx context.Context) ([]uuid.UUID, error)
	ClearSLARecompute(ctx context.Context, tenantID uuid.UUID) error
	// ListActiveFindings pages every active finding of a tenant, ordered by id, after the given id.
	ListActiveFindings(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]*domain.Finding, error)

	// Scoring and SLA (docs/06, D40)
	GetApplication(ctx context.Context, tenantID, id uuid.UUID) (*domain.Application, error)
	ListTenantIDs(ctx context.Context) ([]uuid.UUID, error)
	// ListFindingsForRescore pages the findings a re-score concerns (active or risk_accepted with a
	// vulnerability id), ordered by id, starting after the given id.
	ListFindingsForRescore(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]*domain.Finding, error)
	// UpdateFindingRisk stores score, band, KEV, EPSS bucket and SLA start and due date, and nothing else.
	UpdateFindingRisk(ctx context.Context, tenantID uuid.UUID, fs []*domain.Finding) error
	// MarkSLABreaches sets sla_breached_at on active, unpaused findings past their due date and returns their ids.
	MarkSLABreaches(ctx context.Context, tenantID uuid.UUID, now time.Time) ([]uuid.UUID, error)

	// Query / Explorer API (D14, D16)
	ListFindings(ctx context.Context, tenantID uuid.UUID) ([]*domain.Finding, error)
	GetFinding(ctx context.Context, tenantID, findingID uuid.UUID) (*domain.Finding, []*domain.Occurrence, error)

	// Asset, Application & Track Resolution (D10)
	LookupAsset(ctx context.Context, tenantID uuid.UUID, assetType domain.AssetType, key string) (*domain.Asset, error)
	CreateAsset(ctx context.Context, asset *domain.Asset) error
	LookupApplication(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Application, error)
	CreateApplication(ctx context.Context, app *domain.Application) error

	// Presigned uploads (D2, D9)
	CreateUpload(ctx context.Context, u *domain.Upload) error
	GetUpload(ctx context.Context, tenantID, id uuid.UUID) (*domain.Upload, error)
	FindUploadByKey(ctx context.Context, tenantID uuid.UUID, key string) (*domain.Upload, error)
	DeleteUpload(ctx context.Context, tenantID, id uuid.UUID) error
	// CompleteUpload moves created -> completed and records the declared SHA-256. It reports false,
	// with no error, when the upload was already completed (a repeated call).
	CompleteUpload(ctx context.Context, tenantID, id uuid.UUID, sha256 string) (bool, error)
	FindRunByUpload(ctx context.Context, tenantID, uploadID uuid.UUID) (*domain.IngestRun, error)

	// Ingest Run & Ephemeral Results (D2, D10, D13)
	CreateIngestRun(ctx context.Context, run *domain.IngestRun) error
	GetIngestRun(ctx context.Context, tenantID, runID uuid.UUID) (*domain.IngestRun, error)
	// ListIngestRuns returns up to limit runs, newest first, starting after the (createdAt, id) position when
	// after is set. Callers ask for one more than they show to learn whether another page exists.
	ListIngestRuns(ctx context.Context, tenantID uuid.UUID, limit int, after *RunPosition) ([]*domain.IngestRun, error)
	UpdateIngestRun(ctx context.Context, run *domain.IngestRun) error
	RecordRunScope(ctx context.Context, scope *domain.IngestRunScope) error
	RecordRunResult(ctx context.Context, result *domain.IngestRunResult) error
	// ReplaceRunResults stores the ephemeral results of a run, replacing earlier rows of the same run (D10).
	ReplaceRunResults(ctx context.Context, tenantID, runID uuid.UUID, results []*domain.IngestRunResult) error
	// ListRunScopes returns the scanner families a run reported on (the tools in its report).
	ListRunScopes(ctx context.Context, tenantID, runID uuid.UUID) ([]string, error)
	ListRunResults(ctx context.Context, tenantID, runID uuid.UUID) ([]*domain.IngestRunResult, error)
	// ListRunsForGate returns the runs a CI gate waits for: those of the source that carry the commit or image digest.
	ListRunsForGate(ctx context.Context, tenantID, scanSourceID uuid.UUID, commit, imageDigest string) ([]*domain.IngestRun, error)

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
