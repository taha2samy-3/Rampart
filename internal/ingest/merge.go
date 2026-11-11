package ingest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// ErrRunStale indicates that a run's scanFinished timestamp is older than the last applied scan for this scope (D13 line 204).
var ErrRunStale = errors.New("ingest: run is stale (scanFinished is older than last applied scan for this scope)")

// CloseScope uniquely identifies the rescan closure boundary (normative D13).
type CloseScope struct {
	TenantID      uuid.UUID
	ScanSourceID  uuid.UUID
	ScannerFamily string
	AssetID       uuid.UUID
	Track         string
}

// Key formats the scope for advisory locking and logging.
func (s CloseScope) Key() string {
	return fmt.Sprintf("%s:%s:%s:%s:%s", s.TenantID, s.ScanSourceID, s.ScannerFamily, s.AssetID, s.Track)
}

// StagedRecord represents a normalized record ready for batch merge (D13).
type StagedRecord struct {
	FindingKey   string
	Category     domain.FindingCategory
	RuleID       string
	Title        string
	Description  string
	ToolSeverity string
	Severity     domain.Severity
	Location     domain.Location
	CWEs         []int
	VulnID       string
	CVSSVector   string
	ContentHash  string
	SeenAt       time.Time
	RawPayload   []byte
}

// MergeOutcome records the result breakdown of a batch merge.
type MergeOutcome struct {
	Created     int
	Updated     int
	Untouched   int
	Reactivated int
	Closed      int
}

// MergeOptions configures behavioral policies during merge and close (D13).
type MergeOptions struct {
	MinimumSeverity domain.Severity // Records below this do not create findings
	DoNotReactivate bool            // If true, fixed findings stay fixed
	FieldMerge      string          // "scanner" (default) or "keep"
	IsEphemeral     bool            // If true, runs from untracked PR branches don't change inventory
	ScanFinished    time.Time       // Scan completion time for out-of-order check (D13 line 204)
}

// CloseScopeResult records the outcome of closing missing findings.
type CloseScopeResult struct {
	Closed              int  `json:"closed"`
	HeldForConfirmation bool `json:"held_for_confirmation"`
}

// Store abstracts the persistence layer for the merge engine.
type Store interface {
	GetFindingsByKeys(ctx context.Context, tenantID uuid.UUID, keys []string) (map[string]*domain.Finding, error)
	UpsertFindings(ctx context.Context, tenantID uuid.UUID, findings []*domain.Finding) error
	UpsertOccurrences(ctx context.Context, occurrences []*domain.Occurrence) error
	GetActiveScopeOccurrences(ctx context.Context, scope CloseScope) ([]*domain.Occurrence, error)
	UpdateOccurrencesPresence(ctx context.Context, occurrenceIDs []uuid.UUID, present bool) error
	GetActiveScopeFindings(ctx context.Context, tenantID uuid.UUID, assetID uuid.UUID, track string) ([]*domain.Finding, error)
	CountPresentOccurrences(ctx context.Context, tenantID uuid.UUID, findingID uuid.UUID) (int, error)
	CheckScopeOrdering(scope CloseScope, scanFinished time.Time) (bool, error)
}

// Engine implements the normative D13 deduplication and reimport merge algorithm.
type Engine struct {
	store Store
}

// NewEngine creates a new merge engine.
func NewEngine(store Store) *Engine {
	return &Engine{store: store}
}

// MergeBatch processes a bounded batch (<= 5 000 records per D2) within a scope.
func (e *Engine) MergeBatch(
	ctx context.Context,
	scope CloseScope,
	runID uuid.UUID,
	applicationID uuid.UUID,
	records []StagedRecord,
) (MergeOutcome, error) {
	return e.MergeBatchWithOptions(ctx, scope, runID, applicationID, records, MergeOptions{
		FieldMerge: "scanner",
	})
}

// MergeBatchWithOptions processes a batch with explicit policy options (minimumSeverity, ephemeral runs, fieldMerge).
func (e *Engine) MergeBatchWithOptions(
	ctx context.Context,
	scope CloseScope,
	runID uuid.UUID,
	applicationID uuid.UUID,
	records []StagedRecord,
	opts MergeOptions,
) (MergeOutcome, error) {
	var outcome MergeOutcome
	if len(records) == 0 {
		return outcome, nil
	}

	// 0. Verify ordering per D13 line 204: late-arriving older scan is marked stale
	if !opts.ScanFinished.IsZero() {
		isStale, err := e.store.CheckScopeOrdering(scope, opts.ScanFinished)
		if err != nil {
			return outcome, err
		}
		if isStale {
			return outcome, ErrRunStale
		}
	}

	// 1. Collapse duplicate keys within the same batch (D13: distinct on finding_key)
	dedupMap := make(map[string]StagedRecord)
	for _, rec := range records {
		existing, found := dedupMap[rec.FindingKey]
		if !found || rec.Severity.Rank() > existing.Severity.Rank() {
			dedupMap[rec.FindingKey] = rec
		}
	}

	var keys []string
	for k := range dedupMap {
		keys = append(keys, k)
	}

	// 2. Fetch existing findings for update
	existingFindings, err := e.store.GetFindingsByKeys(ctx, scope.TenantID, keys)
	if err != nil {
		return outcome, fmt.Errorf("ingest: failed to query existing findings: %w", err)
	}

	var findingsToUpsert []*domain.Finding
	var occurrencesToUpsert []*domain.Occurrence

	for _, rec := range dedupMap {
		existing, exists := existingFindings[rec.FindingKey]

		var targetFinding *domain.Finding

		if !exists {
			// Check minimum severity filter (D13 line 286)
			if opts.MinimumSeverity != "" && rec.Severity.Rank() < opts.MinimumSeverity.Rank() {
				continue
			}

			// Created: fresh finding
			findingID := domain.NewID()
			targetFinding = &domain.Finding{
				ID:                findingID,
				TenantID:          scope.TenantID,
				FindingKey:        rec.FindingKey,
				DedupScope:        "asset",
				AssetID:           scope.AssetID,
				ApplicationID:     applicationID,
				Track:             scope.Track,
				Category:          rec.Category,
				RuleScannerFamily: scope.ScannerFamily,
				RuleID:            rec.RuleID,
				Title:             rec.Title,
				Description:       rec.Description,
				CWEs:              rec.CWEs,
				Location:          rec.Location,
				Severity:          rec.Severity,
				ToolSeverity:      rec.ToolSeverity,
				CVSSVector:        rec.CVSSVector,
				State:             domain.StateOpen,
				Detection:         domain.DetectionPresent,
				ContentHash:       rec.ContentHash,
				FirstSeen:         rec.SeenAt,
				LastSeen:          rec.SeenAt,
				OccurrenceCount:   1,
				Version:           1,
				CreatedAt:         rec.SeenAt,
				UpdatedAt:         rec.SeenAt,
			}
			outcome.Created++
		} else {
			targetFinding = existing
			targetFinding.LastSeen = rec.SeenAt
			targetFinding.Detection = domain.DetectionPresent

			// Check for reactivation: previously fixed finding reported again by scanner (D13, D18)
			if existing.State == domain.StateFixed {
				if !opts.DoNotReactivate {
					targetFinding.State = existing.PreviousState
					if targetFinding.State == "" || targetFinding.State == domain.StateFixed {
						targetFinding.State = domain.StateOpen
					}
					targetFinding.PreviousState = ""
					targetFinding.Resolution = nil
					targetFinding.ResolvedAt = nil
					targetFinding.ReopenedCount++
					targetFinding.Version++
					outcome.Reactivated++
				}
			} else if existing.State == domain.StateNotAffected && existing.ContentHash != rec.ContentHash {
				// Code changed at location: flag not_affected finding for re-review (D18 line 358)
				targetFinding.StateReason = "code_changed_recheck_needed"
				targetFinding.ContentHash = rec.ContentHash
				targetFinding.Version++
				outcome.Updated++
			} else if existing.ContentHash != rec.ContentHash {
				// Updated: scanner changed title, description, or location
				if opts.FieldMerge != "keep" {
					targetFinding.Title = rec.Title
					targetFinding.Description = rec.Description
					targetFinding.ToolSeverity = rec.ToolSeverity
					targetFinding.Severity = rec.Severity
				}
				targetFinding.Location = rec.Location
				targetFinding.ContentHash = rec.ContentHash
				targetFinding.Version++
				outcome.Updated++
			} else {
				// Untouched: rescan sees identical issue
				outcome.Untouched++
			}
		}

		findingsToUpsert = append(findingsToUpsert, targetFinding)

		// Create or refresh Occurrence (D12)
		occKey := rec.FindingKey
		if rec.Location.Code != nil && rec.Location.Code.FilePath != "" {
			occKey = fmt.Sprintf("%s:%s:%d", rec.FindingKey, rec.Location.Code.FilePath, rec.Location.Code.StartLine)
		}

		occ := &domain.Occurrence{
			ID:            domain.NewID(),
			TenantID:      scope.TenantID,
			FindingID:     targetFinding.ID,
			IngestRunID:   runID,
			ScanSourceID:  scope.ScanSourceID,
			AssetID:       scope.AssetID,
			Track:         scope.Track,
			OccurrenceKey: occKey,
			ScannerFamily: scope.ScannerFamily,
			ScannerName:   scope.ScannerFamily,
			Location:      rec.Location,
			ToolSeverity:  rec.ToolSeverity,
			Present:       true,
			SeenCount:     1,
			FirstSeen:     rec.SeenAt,
			LastSeen:      rec.SeenAt,
			Raw:           rec.RawPayload,
		}
		occurrencesToUpsert = append(occurrencesToUpsert, occ)
	}

	// Ephemeral runs (e.g. untracked PR branches per D10, D13) do not mutate the long-lived inventory
	if opts.IsEphemeral {
		return outcome, nil
	}

	// Persist findings and occurrences
	if err := e.store.UpsertFindings(ctx, scope.TenantID, findingsToUpsert); err != nil {
		return outcome, fmt.Errorf("ingest: upserting findings failed: %w", err)
	}
	if err := e.store.UpsertOccurrences(ctx, occurrencesToUpsert); err != nil {
		return outcome, fmt.Errorf("ingest: upserting occurrences failed: %w", err)
	}

	return outcome, nil
}

// CloseScopeStep executes the normative D13 close step once per scope after all batches commit.
// Only executes when run has zero record errors!
func (e *Engine) CloseScopeStep(ctx context.Context, scope CloseScope, currentRunID uuid.UUID) (int, error) {
	res, err := e.CloseScopeStepWithGuard(ctx, scope, currentRunID, false)
	return res.Closed, err
}

// CloseScopeStepWithGuard executes the close step with optional mass-close safety guard (D13 line 104, D22).
func (e *Engine) CloseScopeStepWithGuard(
	ctx context.Context,
	scope CloseScope,
	currentRunID uuid.UUID,
	enableMassCloseGuard bool,
) (CloseScopeResult, error) {
	var res CloseScopeResult

	// 1. Mark occurrences of this scope not seen in current run as present = false (D13)
	existingOccs, err := e.store.GetActiveScopeOccurrences(ctx, scope)
	if err != nil {
		return res, fmt.Errorf("ingest: querying scope occurrences failed: %w", err)
	}

	var absentIDs []uuid.UUID
	for _, occ := range existingOccs {
		if occ.IngestRunID != currentRunID && occ.Present {
			absentIDs = append(absentIDs, occ.ID)
		}
	}

	if len(absentIDs) > 0 {
		if err := e.store.UpdateOccurrencesPresence(ctx, absentIDs, false); err != nil {
			return res, fmt.Errorf("ingest: updating occurrences presence failed: %w", err)
		}
	}

	// 2. Active findings with NO present occurrence left -> state = 'fixed' (D13, D18)
	activeFindings, err := e.store.GetActiveScopeFindings(ctx, scope.TenantID, scope.AssetID, scope.Track)
	if err != nil {
		return res, fmt.Errorf("ingest: querying active findings failed: %w", err)
	}

	closedCount := 0
	var fixedFindings []*domain.Finding
	now := time.Now().UTC()

	for _, f := range activeFindings {
		// Only active triage states are auto-closed (D18: not_affected/risk_accepted stay as-is!)
		if f.State != domain.StateOpen && f.State != domain.StateUnderInvestigation && f.State != domain.StateAffected {
			continue
		}

		presentCount, err := e.store.CountPresentOccurrences(ctx, scope.TenantID, f.ID)
		if err != nil {
			return res, fmt.Errorf("ingest: counting occurrences failed: %w", err)
		}

		if presentCount == 0 {
			resFixed := domain.ResolutionFixed
			f.State = domain.StateFixed
			f.Detection = domain.DetectionAbsent
			f.Resolution = &resFixed
			f.ResolvedAt = &now
			f.Version++
			fixedFindings = append(fixedFindings, f)
			closedCount++
		}
	}

	// Mass-close guard (D13 line 104, D22): held for confirmation if closing > 50% of scope
	if enableMassCloseGuard && len(activeFindings) >= 10 && closedCount > len(activeFindings)/2 {
		return CloseScopeResult{
			Closed:              0,
			HeldForConfirmation: true,
		}, nil
	}

	if len(fixedFindings) > 0 {
		if err := e.store.UpsertFindings(ctx, scope.TenantID, fixedFindings); err != nil {
			return res, fmt.Errorf("ingest: closing findings failed: %w", err)
		}
	}

	return CloseScopeResult{
		Closed:              closedCount,
		HeldForConfirmation: false,
	}, nil
}

// MemoryStore provides a thread-safe, in-memory store for unit tests and local execution.
type MemoryStore struct {
	mu                    sync.RWMutex
	findings              map[string]*domain.Finding
	occurrences           map[string]*domain.Occurrence
	sboms                 map[string]*domain.SBOM
	sbomComponents        map[string][]domain.SBOMComponent
	scopeLastScanFinished map[string]time.Time
}

// NewMemoryStore initializes a new MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		findings:              make(map[string]*domain.Finding),
		occurrences:           make(map[string]*domain.Occurrence),
		sboms:                 make(map[string]*domain.SBOM),
		sbomComponents:        make(map[string][]domain.SBOMComponent),
		scopeLastScanFinished: make(map[string]time.Time),
	}
}

// CheckScopeOrdering checks whether the incoming scanFinished time is older than the last applied scan for this scope (D13 line 204).
func (m *MemoryStore) CheckScopeOrdering(scope CloseScope, scanFinished time.Time) (bool, error) {
	if scanFinished.IsZero() {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	last, exists := m.scopeLastScanFinished[scope.Key()]
	if exists && scanFinished.Before(last) {
		return true, nil
	}
	if scanFinished.After(last) {
		m.scopeLastScanFinished[scope.Key()] = scanFinished
	}
	return false, nil
}

func (m *MemoryStore) GetFindingsByKeys(ctx context.Context, tenantID uuid.UUID, keys []string) (map[string]*domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*domain.Finding)
	for _, key := range keys {
		compositeKey := tenantID.String() + ":" + key
		if f, exists := m.findings[compositeKey]; exists {
			// Return a copy to simulate database row fetch
			cp := *f
			result[key] = &cp
		}
	}
	return result, nil
}

func (m *MemoryStore) UpsertFindings(ctx context.Context, tenantID uuid.UUID, findings []*domain.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, f := range findings {
		compositeKey := tenantID.String() + ":" + f.FindingKey
		cp := *f
		m.findings[compositeKey] = &cp
	}
	return nil
}

func (m *MemoryStore) UpsertOccurrences(ctx context.Context, occurrences []*domain.Occurrence) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, occ := range occurrences {
		compositeKey := fmt.Sprintf("%s:%s:%s:%s", occ.TenantID, occ.FindingID, occ.ScanSourceID, occ.OccurrenceKey)
		if existing, exists := m.occurrences[compositeKey]; exists {
			existing.Present = true
			existing.LastSeen = occ.LastSeen
			existing.SeenCount++
			existing.IngestRunID = occ.IngestRunID
			existing.Raw = occ.Raw
		} else {
			cp := *occ
			m.occurrences[compositeKey] = &cp
		}
	}
	return nil
}

func (m *MemoryStore) GetActiveScopeOccurrences(ctx context.Context, scope CloseScope) ([]*domain.Occurrence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*domain.Occurrence
	for _, occ := range m.occurrences {
		if occ.TenantID == scope.TenantID && occ.ScanSourceID == scope.ScanSourceID && occ.ScannerFamily == scope.ScannerFamily &&
			occ.AssetID == scope.AssetID && occ.Track == scope.Track {
			cp := *occ
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (m *MemoryStore) UpdateOccurrencesPresence(ctx context.Context, occurrenceIDs []uuid.UUID, present bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	idMap := make(map[uuid.UUID]bool)
	for _, id := range occurrenceIDs {
		idMap[id] = true
	}

	for _, occ := range m.occurrences {
		if idMap[occ.ID] {
			occ.Present = present
		}
	}
	return nil
}

func (m *MemoryStore) GetActiveScopeFindings(ctx context.Context, tenantID uuid.UUID, assetID uuid.UUID, track string) ([]*domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*domain.Finding
	for _, f := range m.findings {
		if f.TenantID == tenantID && f.AssetID == assetID && f.Track == track {
			cp := *f
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (m *MemoryStore) CountPresentOccurrences(ctx context.Context, tenantID uuid.UUID, findingID uuid.UUID) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, occ := range m.occurrences {
		if occ.TenantID == tenantID && occ.FindingID == findingID && occ.Present {
			count++
		}
	}
	return count, nil
}

// SaveSBOM stores an SBOM document and its extracted component inventory.
func (m *MemoryStore) SaveSBOM(ctx context.Context, sbom *domain.SBOM, components []domain.SBOMComponent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := sbom.TenantID.String() + ":" + sbom.AssetID.String()
	cp := *sbom
	m.sboms[key] = &cp
	m.sbomComponents[sbom.ID.String()] = components
	return nil
}

// GetSBOM retrieves the SBOM document and component inventory for an asset.
func (m *MemoryStore) GetSBOM(ctx context.Context, tenantID, assetID uuid.UUID) (*domain.SBOM, []domain.SBOMComponent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := tenantID.String() + ":" + assetID.String()
	sbom, exists := m.sboms[key]
	if !exists {
		return nil, nil, nil
	}
	comps := m.sbomComponents[sbom.ID.String()]
	cp := *sbom
	return &cp, comps, nil
}

// ListFindings returns all findings for a given tenant.
func (m *MemoryStore) ListFindings(ctx context.Context, tenantID uuid.UUID) ([]*domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*domain.Finding
	for _, f := range m.findings {
		if f.TenantID == tenantID {
			cp := *f
			result = append(result, &cp)
		}
	}
	return result, nil
}

// GetFinding retrieves a finding and its occurrences.
func (m *MemoryStore) GetFinding(ctx context.Context, tenantID, findingID uuid.UUID) (*domain.Finding, []*domain.Occurrence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var target *domain.Finding
	for _, f := range m.findings {
		if f.TenantID == tenantID && f.ID == findingID {
			cp := *f
			target = &cp
			break
		}
	}
	if target == nil {
		return nil, nil, nil
	}

	var occs []*domain.Occurrence
	for _, occ := range m.occurrences {
		if occ.TenantID == tenantID && occ.FindingID == findingID {
			cp := *occ
			occs = append(occs, &cp)
		}
	}

	return target, occs, nil
}
