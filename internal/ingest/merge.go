package ingest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// ErrRunStale indicates that a run's scanFinished timestamp is older than the last applied scan for this scope (D13 line 204).
var ErrRunStale = errors.New("ingest: run is stale (scanFinished is older than last applied scan for this scope)")

// CloseScope uniquely identifies the rescan closure boundary (normative D13).
type CloseScope = domain.CloseScope

// StagedRecord represents a normalized record ready for batch merge (D13).
type StagedRecord struct {
	ScannerFamily string // the scanner (semgrep, trivy...), which defines the close scope (D11, D13)
	FindingKey    string
	Category      domain.FindingCategory
	RuleID        string
	Title         string
	Description   string
	ToolSeverity  string
	Severity      domain.Severity
	Location      domain.Location
	CWEs          []int
	VulnID        string
	CVSSVector    string
	ContentHash   string
	SeenAt        time.Time
	RawPayload    []byte
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
type Store = store.Store

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
// The whole batch runs in one transaction under the scope's advisory lock (D13): it
// commits or rolls back as a unit, and two runs on the same scope are serialised.
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
	err := e.store.InTenantTx(ctx, scope.TenantID, func(st Store) error {
		if err := st.LockScope(ctx, scope); err != nil {
			return fmt.Errorf("ingest: locking scope failed: %w", err)
		}
		var err error
		outcome, err = e.mergeBatch(ctx, st, scope, runID, applicationID, records, opts)
		return err
	})
	return outcome, err
}

func (e *Engine) mergeBatch(
	ctx context.Context,
	st Store,
	scope CloseScope,
	runID uuid.UUID,
	applicationID uuid.UUID,
	records []StagedRecord,
	opts MergeOptions,
) (MergeOutcome, error) {
	var outcome MergeOutcome
	var events []*domain.FindingEvent
	addEvent := func(f *domain.Finding, typ string, at time.Time) {
		events = append(events, &domain.FindingEvent{
			ID: domain.NewID(), FindingID: f.ID, At: at, Actor: "system:parser", Type: typ,
			Note: "ingest_run " + runID.String(),
		})
	}

	// 0. Verify ordering per D13 line 204: late-arriving older scan is marked stale
	if !opts.ScanFinished.IsZero() {
		isStale, err := st.CheckScopeOrdering(scope, opts.ScanFinished)
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
	existingFindings, err := st.GetFindingsByKeys(ctx, scope.TenantID, keys)
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
				VulnerabilityID:   vulnPtr(rec.VulnID),
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
			addEvent(targetFinding, "created", rec.SeenAt)
		} else {
			targetFinding = existing
			if rec.SeenAt.After(targetFinding.LastSeen) {
				targetFinding.LastSeen = rec.SeenAt
			}
			targetFinding.Detection = domain.DetectionPresent
			if targetFinding.VulnerabilityID == nil {
				targetFinding.VulnerabilityID = vulnPtr(rec.VulnID)
			}

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
					addEvent(targetFinding, "reactivated", rec.SeenAt)
				}
			} else if existing.State == domain.StateNotAffected && existing.ContentHash != rec.ContentHash {
				// Code changed at location: flag not_affected finding for re-review (D18 line 358)
				targetFinding.StateReason = "code_changed_recheck_needed"
				targetFinding.ContentHash = rec.ContentHash
				targetFinding.Version++
				outcome.Updated++
				addEvent(targetFinding, "recheck_needed", rec.SeenAt)
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
				addEvent(targetFinding, "updated", rec.SeenAt)
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
	if err := st.UpsertFindings(ctx, scope.TenantID, findingsToUpsert); err != nil {
		return outcome, fmt.Errorf("ingest: upserting findings failed: %w", err)
	}
	if err := st.UpsertOccurrences(ctx, occurrencesToUpsert); err != nil {
		return outcome, fmt.Errorf("ingest: upserting occurrences failed: %w", err)
	}
	// D12: counters are recomputed from rows, never incremented.
	ids := make([]uuid.UUID, 0, len(findingsToUpsert))
	for _, f := range findingsToUpsert {
		ids = append(ids, f.ID)
	}
	if err := st.RecomputeOccurrenceCounts(ctx, scope.TenantID, ids); err != nil {
		return outcome, fmt.Errorf("ingest: recomputing occurrence counts failed: %w", err)
	}
	if err := st.RecordFindingEvents(ctx, scope.TenantID, events); err != nil {
		return outcome, fmt.Errorf("ingest: recording finding events failed: %w", err)
	}

	return outcome, nil
}

func vulnPtr(id string) *string {
	if id == "" {
		return nil
	}
	return &id
}

// D22 defaults for ingestionPolicy.maxClosePercent and the minimum size of a held close.
const (
	massClosePercent     = 50
	massCloseMinFindings = 20
)

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
	err := e.store.InTenantTx(ctx, scope.TenantID, func(st Store) error {
		if err := st.LockScope(ctx, scope); err != nil {
			return fmt.Errorf("ingest: locking scope failed: %w", err)
		}
		var err error
		res, err = e.closeScope(ctx, st, scope, currentRunID, enableMassCloseGuard)
		if err == nil && res.HeldForConfirmation {
			return errCloseHeld // roll back: a held close must not flip occurrences either
		}
		return err
	})
	if errors.Is(err, errCloseHeld) {
		return res, nil
	}
	return res, err
}

var errCloseHeld = errors.New("ingest: close held for confirmation")

func (e *Engine) closeScope(
	ctx context.Context,
	st Store,
	scope CloseScope,
	currentRunID uuid.UUID,
	enableMassCloseGuard bool,
) (CloseScopeResult, error) {
	var res CloseScopeResult

	// Occurrences of this scope not seen in the current run (D13 step 1).
	existingOccs, err := st.GetActiveScopeOccurrences(ctx, scope)
	if err != nil {
		return res, fmt.Errorf("ingest: querying scope occurrences failed: %w", err)
	}
	var absentIDs []uuid.UUID
	absentByFinding := make(map[uuid.UUID]int)
	for _, occ := range existingOccs {
		if occ.IngestRunID != currentRunID && occ.Present {
			absentIDs = append(absentIDs, occ.ID)
			absentByFinding[occ.FindingID]++
		}
	}

	// D13 step 2, decided BEFORE any write so a held close changes nothing: an active
	// finding closes when no present occurrence is left once the absent ones are removed.
	// A finding reported by two sources stays open until both stop reporting it.
	activeFindings, err := st.GetActiveScopeFindings(ctx, scope.TenantID, scope.AssetID, scope.Track)
	if err != nil {
		return res, fmt.Errorf("ingest: querying active findings failed: %w", err)
	}
	activeIDs := make([]uuid.UUID, 0, len(activeFindings))
	for _, f := range activeFindings {
		activeIDs = append(activeIDs, f.ID)
	}
	presentCounts, err := st.CountPresentOccurrencesBatch(ctx, scope.TenantID, activeIDs)
	if err != nil {
		return res, fmt.Errorf("ingest: counting occurrences failed: %w", err)
	}

	now := time.Now().UTC()
	var fixedFindings []*domain.Finding
	var events []*domain.FindingEvent
	for _, f := range activeFindings {
		// Only active dispositions are auto-closed (D18: not_affected/risk_accepted stay as-is).
		if f.State != domain.StateOpen && f.State != domain.StateUnderInvestigation && f.State != domain.StateAffected {
			continue
		}
		if presentCounts[f.ID]-absentByFinding[f.ID] > 0 {
			continue
		}
		resFixed := domain.ResolutionFixed
		f.PreviousState = f.State // D18: restored on reactivation
		f.State = domain.StateFixed
		f.Detection = domain.DetectionAbsent
		f.Resolution = &resFixed
		f.ResolvedAt = &now
		f.Version++
		fixedFindings = append(fixedFindings, f)
		events = append(events, &domain.FindingEvent{
			ID: domain.NewID(), FindingID: f.ID, At: now, Actor: "system:parser", Type: "closed_by_rescan",
			Note: "ingest_run " + currentRunID.String(),
		})
	}
	closedCount := len(fixedFindings)

	// Mass-close guard (D22): hold the close when it would close more than
	// maxClosePercent (default 50%) of the scope's open findings AND more than 20.
	if enableMassCloseGuard && closedCount > massCloseMinFindings && closedCount*100 > len(activeFindings)*massClosePercent {
		return CloseScopeResult{HeldForConfirmation: true}, nil
	}

	if err := st.UpdateOccurrencesPresence(ctx, scope.TenantID, absentIDs, false); err != nil {
		return res, fmt.Errorf("ingest: updating occurrences presence failed: %w", err)
	}
	if len(fixedFindings) > 0 {
		if err := st.UpsertFindings(ctx, scope.TenantID, fixedFindings); err != nil {
			return res, fmt.Errorf("ingest: closing findings failed: %w", err)
		}
		if err := st.RecordFindingEvents(ctx, scope.TenantID, events); err != nil {
			return res, fmt.Errorf("ingest: recording finding events failed: %w", err)
		}
	}
	// D12: recompute counters of every finding whose occurrences changed.
	changed := make([]uuid.UUID, 0, len(absentByFinding))
	for id := range absentByFinding {
		changed = append(changed, id)
	}
	if err := st.RecomputeOccurrenceCounts(ctx, scope.TenantID, changed); err != nil {
		return res, fmt.Errorf("ingest: recomputing occurrence counts failed: %w", err)
	}

	return CloseScopeResult{Closed: closedCount}, nil
}

// MemoryStore provides a thread-safe, in-memory store for unit tests and local execution.
type MemoryStore struct {
	mu                    sync.RWMutex
	findings              map[string]*domain.Finding
	occurrences           map[string]*domain.Occurrence
	sboms                 map[string]*domain.SBOM
	sbomComponents        map[string][]domain.SBOMComponent
	scopeLastScanFinished map[string]time.Time
	findingEvents         map[string][]*domain.FindingEvent
	assets                map[string]*domain.Asset
	applications          map[string]*domain.Application
	ingestRuns            map[string]*domain.IngestRun
	ingestRunScopes       map[string]*domain.IngestRunScope
	ingestRunResults      map[string][]*domain.IngestRunResult
	tokens                map[string]*auth.TokenRecord
	tenants               map[uuid.UUID]*domain.Tenant
	scanSources           map[string]uuid.UUID
	users                 map[uuid.UUID]auth.User
	userIDs               map[string]uuid.UUID
	members               map[string]memMember
	sessions              map[string]auth.SessionRecord
	localAdmins           map[string]*auth.LocalAdmin
	audits                []auth.AuditEvent
}

// NewMemoryStore initializes a new MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		scanSources:           make(map[string]uuid.UUID),
		findings:              make(map[string]*domain.Finding),
		occurrences:           make(map[string]*domain.Occurrence),
		sboms:                 make(map[string]*domain.SBOM),
		sbomComponents:        make(map[string][]domain.SBOMComponent),
		scopeLastScanFinished: make(map[string]time.Time),
		findingEvents:         make(map[string][]*domain.FindingEvent),
		assets:                make(map[string]*domain.Asset),
		applications:          make(map[string]*domain.Application),
		ingestRuns:            make(map[string]*domain.IngestRun),
		ingestRunScopes:       make(map[string]*domain.IngestRunScope),
		ingestRunResults:      make(map[string][]*domain.IngestRunResult),
		tokens:                make(map[string]*auth.TokenRecord),
		tenants:               make(map[uuid.UUID]*domain.Tenant),
		users:                 make(map[uuid.UUID]auth.User),
		userIDs:               make(map[string]uuid.UUID),
		members:               make(map[string]memMember),
		sessions:              make(map[string]auth.SessionRecord),
		localAdmins:           make(map[string]*auth.LocalAdmin),
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

func (m *MemoryStore) UpdateOccurrencesPresence(ctx context.Context, tenantID uuid.UUID, occurrenceIDs []uuid.UUID, present bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	idMap := make(map[uuid.UUID]bool)
	for _, id := range occurrenceIDs {
		idMap[id] = true
	}

	for _, occ := range m.occurrences {
		if occ.TenantID == tenantID && idMap[occ.ID] {
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

// RecordFindingEvents stores audit trail events in memory.
func (m *MemoryStore) RecordFindingEvents(ctx context.Context, tenantID uuid.UUID, events []*domain.FindingEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ev := range events {
		key := tenantID.String() + ":" + ev.FindingID.String()
		cp := *ev
		if cp.ID == domain.NilID {
			cp.ID = domain.NewID()
		}
		if cp.At.IsZero() {
			cp.At = time.Now().UTC()
		}
		m.findingEvents[key] = append(m.findingEvents[key], &cp)
	}
	return nil
}

// GetFindingEvents retrieves chronological events for a finding.
func (m *MemoryStore) GetFindingEvents(ctx context.Context, tenantID, findingID uuid.UUID) ([]*domain.FindingEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := tenantID.String() + ":" + findingID.String()
	events := m.findingEvents[key]
	var res []*domain.FindingEvent
	for _, ev := range events {
		cp := *ev
		res = append(res, &cp)
	}
	return res, nil
}

// LookupAsset queries an asset by type and key.
func (m *MemoryStore) LookupAsset(ctx context.Context, tenantID uuid.UUID, assetType domain.AssetType, key string) (*domain.Asset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	composite := fmt.Sprintf("%s:%s:%s", tenantID, assetType, key)
	if a, exists := m.assets[composite]; exists {
		cp := *a
		return &cp, nil
	}
	return nil, store.ErrNotFound
}

// CreateAsset persists a new asset.
func (m *MemoryStore) CreateAsset(ctx context.Context, asset *domain.Asset) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	composite := fmt.Sprintf("%s:%s:%s", asset.TenantID, asset.Type, asset.Key)
	cp := *asset
	m.assets[composite] = &cp
	return nil
}

// LookupApplication queries an application by slug.
func (m *MemoryStore) LookupApplication(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Application, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	composite := fmt.Sprintf("%s:%s", tenantID, slug)
	if app, exists := m.applications[composite]; exists {
		cp := *app
		return &cp, nil
	}
	return nil, store.ErrNotFound
}

// CreateApplication inserts or updates an application.
func (m *MemoryStore) CreateApplication(ctx context.Context, app *domain.Application) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	composite := fmt.Sprintf("%s:%s", app.TenantID, app.Slug)
	cp := *app
	m.applications[composite] = &cp
	return nil
}

// CreateIngestRun records an ingestion run.
func (m *MemoryStore) CreateIngestRun(ctx context.Context, run *domain.IngestRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	composite := fmt.Sprintf("%s:%s", run.TenantID, run.ID)
	cp := *run
	m.ingestRuns[composite] = &cp
	return nil
}

// GetIngestRun fetches an ingest run by id.
func (m *MemoryStore) GetIngestRun(ctx context.Context, tenantID, runID uuid.UUID) (*domain.IngestRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	composite := fmt.Sprintf("%s:%s", tenantID, runID)
	if run, exists := m.ingestRuns[composite]; exists {
		cp := *run
		return &cp, nil
	}
	return nil, errors.New("store: ingest run not found")
}

// UpdateIngestRun updates an ingest run status and statistics.
func (m *MemoryStore) UpdateIngestRun(ctx context.Context, run *domain.IngestRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	composite := fmt.Sprintf("%s:%s", run.TenantID, run.ID)
	cp := *run
	m.ingestRuns[composite] = &cp
	return nil
}

// RecordRunScope links an asset/track scope to an ingest run.
func (m *MemoryStore) RecordRunScope(ctx context.Context, scope *domain.IngestRunScope) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	composite := fmt.Sprintf("%s:%s:%s:%s", scope.TenantID, scope.IngestRunID, scope.AssetID, scope.Track)
	cp := *scope
	m.ingestRunScopes[composite] = &cp
	return nil
}

// RecordRunResult records ephemeral scan run findings.
func (m *MemoryStore) RecordRunResult(ctx context.Context, result *domain.IngestRunResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	composite := fmt.Sprintf("%s:%s", result.TenantID, result.IngestRunID)
	cp := *result
	m.ingestRunResults[composite] = append(m.ingestRunResults[composite], &cp)
	return nil
}

// LookupTokenByHash retrieves an API token record by its SHA-256 hash.
func (m *MemoryStore) LookupTokenByHash(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*auth.TokenRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if rec, exists := m.tokens[tokenHash]; exists && rec.TenantID == tenantID {
		cp := *rec
		return &cp, nil
	}
	return nil, auth.ErrUnauthorized
}

// SaveToken persists or updates an API token record.
func (m *MemoryStore) SaveToken(ctx context.Context, record *auth.TokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *record
	m.tokens[record.TokenHash] = &cp
	return nil
}

// CreateTenant inserts a new tenant into memory.
func (m *MemoryStore) CreateTenant(ctx context.Context, tenant *domain.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *tenant
	m.tenants[tenant.ID] = &cp
	return nil
}

// GetTenant fetches a tenant by UUID.
func (m *MemoryStore) GetTenant(ctx context.Context, tenantID uuid.UUID) (*domain.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if t, exists := m.tenants[tenantID]; exists {
		cp := *t
		return &cp, nil
	}
	return nil, errors.New("store: tenant not found")
}

// InTenantTx runs fn directly: the in-memory store has no transactions, only locks per call.
func (m *MemoryStore) InTenantTx(ctx context.Context, tenantID uuid.UUID, fn func(Store) error) error {
	return fn(m)
}

// LockScope is a no-op in memory.
func (m *MemoryStore) LockScope(ctx context.Context, scope CloseScope) error { return nil }

// RecomputeOccurrenceCounts sets occurrence_count from present occurrences (D12).
func (m *MemoryStore) RecomputeOccurrenceCounts(ctx context.Context, tenantID uuid.UUID, findingIDs []uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := make(map[uuid.UUID]bool, len(findingIDs))
	for _, id := range findingIDs {
		want[id] = true
	}
	counts := make(map[uuid.UUID]int)
	for _, o := range m.occurrences {
		if o.TenantID == tenantID && o.Present && want[o.FindingID] {
			counts[o.FindingID]++
		}
	}
	for _, f := range m.findings {
		if f.TenantID == tenantID && want[f.ID] {
			f.OccurrenceCount = counts[f.ID]
		}
	}
	return nil
}

// EnsureScanSource mirrors PostgresStore: empty ref means the built-in default source.
// A UUID ref is accepted as given (the memory store has no source configuration).
func (m *MemoryStore) EnsureScanSource(ctx context.Context, tenantID uuid.UUID, ref string) (uuid.UUID, error) {
	if ref == "" {
		ref = "default"
	}
	if id, err := uuid.Parse(ref); err == nil {
		return id, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID.String() + ":" + ref
	if id, ok := m.scanSources[key]; ok {
		return id, nil
	}
	if ref != "default" {
		return uuid.Nil, store.ErrNotFound
	}
	id := domain.NewID()
	m.scanSources[key] = id
	return id, nil
}

// CountPresentOccurrencesBatch counts present occurrences per finding.
func (m *MemoryStore) CountPresentOccurrencesBatch(ctx context.Context, tenantID uuid.UUID, findingIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	want := make(map[uuid.UUID]bool, len(findingIDs))
	for _, id := range findingIDs {
		want[id] = true
	}
	out := make(map[uuid.UUID]int)
	for _, o := range m.occurrences {
		if o.TenantID == tenantID && o.Present && want[o.FindingID] {
			out[o.FindingID]++
		}
	}
	return out, nil
}

// --- identity (auth.IdentityStore) for the in-memory store -------------------------------------

type memMember struct {
	role auth.Role
}

// UpsertUser creates or updates a person by (issuer, subject).
func (m *MemoryStore) UpsertUser(ctx context.Context, u auth.User) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := u.Issuer + "\x1f" + u.Subject
	if id, ok := m.userIDs[key]; ok {
		cp := u
		cp.ID = id
		m.users[id] = cp
		return id, nil
	}
	u.ID = domain.NewID()
	m.userIDs[key] = u.ID
	m.users[u.ID] = u
	return u.ID, nil
}

func (m *MemoryStore) UpsertMember(ctx context.Context, tenantID, userID uuid.UUID, role auth.Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.members[tenantID.String()+":"+userID.String()] = memMember{role: role}
	return nil
}

func (m *MemoryStore) GetMemberRole(ctx context.Context, tenantID, userID uuid.UUID) (auth.Role, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	mm, ok := m.members[tenantID.String()+":"+userID.String()]
	return mm.role, ok, nil
}

func (m *MemoryStore) ListUserTenants(ctx context.Context, userID uuid.UUID) ([]auth.TenantRef, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []auth.TenantRef{}
	for _, t := range m.tenants {
		if _, ok := m.members[t.ID.String()+":"+userID.String()]; ok {
			out = append(out, auth.TenantRef{ID: t.ID, Slug: t.Slug, Name: t.DisplayName})
		}
	}
	return out, nil
}

func (m *MemoryStore) CreateSession(ctx context.Context, r auth.SessionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[r.TenantID.String()+":"+r.TokenHash] = r
	return nil
}

func (m *MemoryStore) LookupSession(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*auth.SessionPrincipal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.sessions[tenantID.String()+":"+tokenHash]
	if !ok {
		return nil, auth.ErrUnauthorized
	}
	mm, member := m.members[tenantID.String()+":"+r.UserID.String()]
	u := m.users[r.UserID]
	if !member {
		return nil, auth.ErrUnauthorized
	}
	return &auth.SessionPrincipal{Session: r, Email: u.Email, Name: u.Name, Role: mm.role}, nil
}

func (m *MemoryStore) TouchSession(ctx context.Context, tenantID, sessionID uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, r := range m.sessions {
		if r.ID == sessionID && r.TenantID == tenantID {
			r.LastSeenAt = at
			m.sessions[k] = r
		}
	}
	return nil
}

func (m *MemoryStore) DeleteSession(ctx context.Context, tenantID, sessionID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, r := range m.sessions {
		if r.ID == sessionID && r.TenantID == tenantID {
			delete(m.sessions, k)
		}
	}
	return nil
}

// GetTenantBySlug lets the in-memory store back the auth handlers' tenant lookup.
func (m *MemoryStore) GetTenantBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tenants {
		if t.Slug == slug {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

// --- local administrator and audit log for the in-memory store ---------------------------------

func (m *MemoryStore) GetLocalAdmin(ctx context.Context, tenantID uuid.UUID, username string) (*auth.LocalAdmin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if a, ok := m.localAdmins[tenantID.String()+":"+username]; ok {
		cp := *a
		return &cp, nil
	}
	return nil, nil
}

func (m *MemoryStore) CreateLocalAdmin(ctx context.Context, a auth.LocalAdmin) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := a.TenantID.String() + ":" + a.Username
	if _, ok := m.localAdmins[key]; ok {
		return false, nil
	}
	cp := a
	m.localAdmins[key] = &cp
	return true, nil
}

func (m *MemoryStore) RecordLocalLogin(ctx context.Context, tenantID, id uuid.UUID, success bool, now time.Time, maxFailures int, lock time.Duration) (*time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.localAdmins {
		if a.TenantID != tenantID || a.ID != id {
			continue
		}
		if success {
			a.FailedAttempts, a.LockedUntil = 0, nil
			return nil, nil
		}
		a.FailedAttempts++
		if a.FailedAttempts >= maxFailures {
			until := now.Add(lock)
			a.FailedAttempts, a.LockedUntil = 0, &until
			return &until, nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) SetLocalAdminPassword(ctx context.Context, tenantID uuid.UUID, username, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.localAdmins[tenantID.String()+":"+username]
	if !ok {
		return store.ErrNotFound
	}
	a.PasswordHash, a.FailedAttempts, a.LockedUntil = passwordHash, 0, nil
	for k, sess := range m.sessions { // a password change ends the account's sessions
		if sess.TenantID == tenantID && sess.UserID == a.UserID {
			delete(m.sessions, k)
		}
	}
	return nil
}

func (m *MemoryStore) RecordAudit(ctx context.Context, e auth.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audits = append(m.audits, e)
	return nil
}

// AuditEvents returns the recorded audit events; for tests.
func (m *MemoryStore) AuditEvents() []auth.AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]auth.AuditEvent(nil), m.audits...)
}
