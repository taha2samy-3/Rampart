package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"rampart/internal/analyzer/matcher"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/store"
)

// ErrRunStale indicates that a run's scanFinished timestamp is older than the last applied scan for this scope (D13 line 204).
var ErrRunStale = errors.New("ingest: run is stale (scanFinished is older than last applied scan for this scope)")

// CloseScope uniquely identifies the rescan closure boundary (normative D13).
type CloseScope = domain.CloseScope

// StagedRecord represents a normalized record ready for batch merge (D13).
type StagedRecord struct {
	ScannerFamily  string // the scanner (semgrep, trivy...), which defines the close scope (D11, D13)
	FindingKey     string
	LineageKey     string // the key without the track (D57)
	Category       domain.FindingCategory
	RuleID         string
	Title          string
	Description    string
	ToolSeverity   string
	Severity       domain.Severity
	Location       domain.Location
	CWEs           []int
	VulnID         string
	CVSSVector     string
	SecretVerified bool // the scanner says the credential is live
	ContentHash    string
	SeenAt         time.Time
	Attributes     map[string]any
	RawPayload     []byte
}

// MergeOutcome records the result breakdown of a batch merge.
type MergeOutcome struct {
	Created     int
	Updated     int
	Untouched   int
	Reactivated int
	Closed      int
	// Fresh lists the findings this batch created or reactivated: what is new in the run (D26). The CI gate
	// reads it back as ingest_run_result rows, so "new" never depends on a clock.
	Fresh []*domain.IngestRunResult
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
	Closed              int         `json:"closed"`
	HeldForConfirmation bool        `json:"held_for_confirmation"`
	HeldFindingIDs      []uuid.UUID `json:"held_finding_ids,omitempty"`
}

// Store abstracts the persistence layer for the merge engine.
type Store = store.Store

// Engine implements the normative D13 deduplication and reimport merge algorithm.
type Engine struct {
	store  Store
	scorer Scorer
}

// Scorer computes the risk score, band and SLA of findings before they are stored (internal/scoring).
type Scorer interface {
	ScoreBatch(ctx context.Context, tenantID, applicationID uuid.UUID, fs []*domain.Finding) error
	// Policy is the SLA policy of the tenant: reactivation restarts the clock when it says so.
	Policy(ctx context.Context, tenantID uuid.UUID) domain.SLAPolicy
}

// SetScorer makes the engine score the findings it creates, reactivates or updates.
func (e *Engine) SetScorer(s Scorer) { e.scorer = s }

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
	sort.Strings(keys)

	// 2. Fetch existing findings for update
	existingFindings, err := st.GetFindingsByKeys(ctx, scope.TenantID, keys)
	if err != nil {
		return outcome, fmt.Errorf("ingest: failed to query existing findings: %w", err)
	}

	var findingsToUpsert []*domain.Finding
	var occurrencesToUpsert []*domain.Occurrence
	var toScore []*domain.Finding // created, reactivated or changed: their score or SLA may have moved

	// D24: identifiers that are aliases of a CVE correlate under the CVE.
	var vulnIDs []string
	for _, rec := range dedupMap {
		if rec.Category == domain.CategorySCA && rec.VulnID != "" {
			vulnIDs = append(vulnIDs, rec.VulnID)
		}
	}
	canon, err := st.CanonicalVulnIDs(ctx, scope.TenantID, vulnIDs)
	if err != nil {
		return outcome, fmt.Errorf("ingest: failed to resolve aliases: %w", err)
	}

	for _, key := range keys {
		rec := dedupMap[key]
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
				LineageKey:        rec.LineageKey,
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
				SecretVerified:    rec.SecretVerified,
				CorrelationKey:    CorrelationKey(rec, firstNonEmptyStr(canon[rec.VulnID], rec.VulnID), scope.AssetID, scope.Track),
				Location:          rec.Location,
				Severity:          rec.Severity,
				ToolSeverity:      rec.ToolSeverity,
				CVSSVector:        rec.CVSSVector,
				RiskBand:          domain.SeverityLow,
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
			toScore = append(toScore, targetFinding)
			addEvent(targetFinding, "created", rec.SeenAt)
			outcome.Fresh = append(outcome.Fresh, freshResult(scope.TenantID, runID, rec))
		} else {
			targetFinding = existing
			if rec.SeenAt.After(targetFinding.LastSeen) {
				targetFinding.LastSeen = rec.SeenAt
			}
			targetFinding.Detection = domain.DetectionPresent
			targetFinding.LineageKey = rec.LineageKey // findings older than D57 learn it here
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
					toScore = append(toScore, targetFinding)
					if e.scorer != nil && e.scorer.Policy(ctx, scope.TenantID).RestartOnReactivation { // docs/06 section 4
						start := rec.SeenAt
						targetFinding.SLAStart, targetFinding.SLABreachedAt = &start, nil
					}
					addEvent(targetFinding, "reactivated", rec.SeenAt)
					outcome.Fresh = append(outcome.Fresh, freshResult(scope.TenantID, runID, rec))
				}
			} else if existing.State == domain.StateNotAffected && existing.ContentHash != rec.ContentHash {
				// Code changed at location: flag not_affected finding for re-review (D18 line 358)
				targetFinding.StateReason = "code_changed_recheck_needed"
				targetFinding.ContentHash = rec.ContentHash
				targetFinding.Version++
				outcome.Updated++
				addEvent(targetFinding, "recheck_needed", rec.SeenAt)
			} else if existing.SecretVerified != rec.SecretVerified && rec.Category == domain.CategorySecret {
				// The credential became live, or stopped being live: it changes the score, not the identity.
				targetFinding.SecretVerified = rec.SecretVerified
				if opts.FieldMerge != "keep" {
					targetFinding.Severity = rec.Severity
					targetFinding.ToolSeverity = rec.ToolSeverity
					targetFinding.Description = rec.Description
				}
				targetFinding.ContentHash = rec.ContentHash
				targetFinding.Version++
				outcome.Updated++
				toScore = append(toScore, targetFinding)
				addEvent(targetFinding, "updated", rec.SeenAt)
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
				toScore = append(toScore, targetFinding)
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

		var normalizedJSON []byte
		if len(rec.Attributes) > 0 {
			normalizedJSON, _ = json.Marshal(rec.Attributes)
		} else if len(rec.RawPayload) > 0 {
			var m map[string]any
			if err := json.Unmarshal(rec.RawPayload, &m); err == nil && len(m) > 0 {
				delete(m, "secret")
				delete(m, "Secret")
				delete(m, "secret_value")
				normalizedJSON, _ = json.Marshal(m)
			}
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
			Normalized:    normalizedJSON,
			Raw:           rec.RawPayload,
		}
		occurrencesToUpsert = append(occurrencesToUpsert, occ)
	}

	// Ephemeral runs (e.g. untracked PR branches per D10, D13) do not mutate the long-lived inventory
	if opts.IsEphemeral {
		return outcome, nil
	}

	// D57 (01 C6): a finding this run creates starts with the decision a person made about the same issue on
	// another track of the asset, when the evidence is the same.
	carried, carriedKeys, err := carryDecisions(ctx, st, scope, findingsToUpsert, existingFindings)
	if err != nil {
		return outcome, err
	}
	events = append(events, carried...)
	// A finding that arrives already decided is not "new" for the CI gate: the decision a person made about the
	// same issue on another branch stands, as it does for a decided finding that was already on this track.
	if len(carriedKeys) > 0 {
		kept := outcome.Fresh[:0]
		for _, r := range outcome.Fresh {
			if !carriedKeys[r.FindingKey] {
				kept = append(kept, r)
			}
		}
		outcome.Fresh = kept
	}

	// Score what is new or changed before it is stored, so the explorer can filter and sort on it (D28).
	if e.scorer != nil && len(toScore) > 0 {
		if err := e.scorer.ScoreBatch(ctx, scope.TenantID, applicationID, toScore); err != nil {
			return outcome, fmt.Errorf("ingest: scoring failed: %w", err)
		}
	}

	// Ticket-on-critical automation (docs/09, docs/16 D25, D29, D66):
	// A critical finding reserves ticket creation in action_ledger so duplicate tickets are prevented.
	for _, f := range findingsToUpsert {
		if f.State.IsActive() && (f.Severity == domain.SeverityCritical || f.RiskBand == domain.SeverityCritical) {
			reserved, err := st.ReserveAction(ctx, scope.TenantID, domain.PolicyTicketOnCriticalID, f.ID, domain.ActionCreateTicket)
			if err == nil && reserved {
				// The reservation is all that happens in the transaction. The call to the tracker is made afterwards by the
				// ticket sweeper (D70): a slow tracker must not hold this transaction open, and a failed call must be
				// tried again, which a reservation that already looks done would prevent.
				events = append(events, &domain.FindingEvent{
					ID:        domain.NewID(),
					FindingID: f.ID,
					At:        f.LastSeen,
					Actor:     "system:policy",
					Type:      "ticket_requested",
					Note:      "A ticket is requested for this critical finding",
					To:        json.RawMessage(`{"action":"create_ticket","rule":"ticket-on-critical","status":"reserved"}`),
				})
			}
		}
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

	// D18: a finding a person decided on is not closed when no scanner reports it any more, but it is no longer
	// detected. Its disposition stays (an acceptance is resolved when it expires, not before).
	decided, err := st.GetDispositionedScopeFindings(ctx, scope.TenantID, scope.AssetID, scope.Track)
	if err != nil {
		return res, fmt.Errorf("ingest: querying decided findings failed: %w", err)
	}
	decidedIDs := make([]uuid.UUID, 0, len(decided))
	for _, f := range decided {
		decidedIDs = append(decidedIDs, f.ID)
	}
	decidedCounts, err := st.CountPresentOccurrencesBatch(ctx, scope.TenantID, decidedIDs)
	if err != nil {
		return res, fmt.Errorf("ingest: counting occurrences failed: %w", err)
	}
	var undetected []*domain.Finding
	for _, f := range decided {
		if decidedCounts[f.ID]-absentByFinding[f.ID] > 0 {
			continue
		}
		f.Detection = domain.DetectionAbsent
		undetected = append(undetected, f)
		events = append(events, &domain.FindingEvent{
			ID: domain.NewID(), FindingID: f.ID, At: now, Actor: "system:parser", Type: "no_longer_detected",
			Note: "ingest_run " + currentRunID.String(),
		})
	}

	// Mass-close guard (D22): hold the close when it would close more than
	// maxClosePercent (default 50%) of the scope's open findings AND more than minHeldClose (default 20).
	thresholdPercent := float64(massClosePercent)
	minFindings := massCloseMinFindings
	if scope.ScanSourceID != uuid.Nil {
		if policy, err := st.GetScanSourceIngestionPolicy(ctx, scope.TenantID, scope.ScanSourceID); err == nil && policy != nil {
			if policy.MaxClosePercent != nil {
				thresholdPercent = *policy.MaxClosePercent
			}
			if policy.MinHeldClose != nil {
				minFindings = *policy.MinHeldClose
			}
		}
	}

	scopeFamilyFindingsCount := 0
	for _, f := range activeFindings {
		if scope.ScannerFamily == "" || f.RuleScannerFamily == scope.ScannerFamily {
			scopeFamilyFindingsCount++
		}
	}
	if scopeFamilyFindingsCount == 0 {
		scopeFamilyFindingsCount = len(activeFindings)
	}

	if enableMassCloseGuard && closedCount > minFindings && float64(closedCount)*100.0 > float64(scopeFamilyFindingsCount)*thresholdPercent {
		heldIDs := make([]uuid.UUID, 0, len(fixedFindings))
		for _, f := range fixedFindings {
			heldIDs = append(heldIDs, f.ID)
		}
		return CloseScopeResult{
			HeldForConfirmation: true,
			HeldFindingIDs:      heldIDs,
		}, nil
	}

	if err := st.UpdateOccurrencesPresence(ctx, scope.TenantID, absentIDs, false); err != nil {
		return res, fmt.Errorf("ingest: updating occurrences presence failed: %w", err)
	}
	if len(fixedFindings) > 0 || len(undetected) > 0 {
		if err := st.UpsertFindings(ctx, scope.TenantID, append(fixedFindings, undetected...)); err != nil {
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
	domain.PackageMap     // installed IntegrationPackages (D94)
	mu                    sync.RWMutex
	findings              map[string]*domain.Finding
	occurrences           map[string]*domain.Occurrence
	sboms                 map[string]*domain.SBOM
	sourcePolicies        map[string]*domain.IngestionPolicy
	sbomComponents        map[string][]domain.SBOMComponent
	scopeLastScanFinished map[string]time.Time
	findingEvents         map[string][]*domain.FindingEvent
	assets                map[string]*domain.Asset
	applications          map[string]*domain.Application
	ingestRuns            map[string]*domain.IngestRun
	ingestRunScopes       map[string]*domain.IngestRunScope
	ingestRunResults      map[string][]*domain.IngestRunResult
	acceptances           map[uuid.UUID]*domain.RiskAcceptance
	tenantSettings        map[uuid.UUID]domain.TenantSettings
	tokens                map[string]*auth.TokenRecord
	tenants               map[uuid.UUID]*domain.Tenant
	scanSources           map[string]uuid.UUID
	scanSourceRecords     map[string]*domain.ScanSource
	users                 map[uuid.UUID]auth.User
	userIDs               map[string]uuid.UUID
	members               map[string]memMember
	sessions              map[string]auth.SessionRecord
	localAdmins           map[string]*auth.LocalAdmin
	audits                []auth.AuditEvent
	uploads               map[string]*domain.Upload
	actionLedger          map[string]bool
	bindings              map[uuid.UUID]memBinding
	idps                  map[string]*domain.IdentityProvider
	connectors            map[string]*domain.Connector
	trustRules            map[uuid.UUID][]domain.TrustRuleRecord
	federationJTIs        map[string]time.Time
	quotaUsage            map[string]int64
	groups                map[uuid.UUID]*domain.FindingGroup
	groupMembers          map[uuid.UUID][]uuid.UUID
	feedMirror            *domain.FeedMirrorSpec
	feedStates            map[string]domain.FeedState
	clusterParsers        []domain.StoredParserObject
	clusterAnalyzers      []domain.StoredAnalyzerObject
	tenantAnalyzers       map[uuid.UUID][]domain.StoredAnalyzerObject
	sbomAnalyses          map[string]*domain.SBOMAnalysis
	advisoryRows          []matcher.Advisory
	notifications         []*domain.Notification
	analyzerEvents        []memoryAnalyzerEvent
	advisories            domain.AdvisorySummary
	tenantParsers         map[uuid.UUID][]domain.StoredParserObject
}

type memBinding struct {
	TenantID uuid.UUID
	Binding  domain.AccessBinding
}

// NewMemoryStore initializes a new MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		scanSources:           make(map[string]uuid.UUID),
		scanSourceRecords:     make(map[string]*domain.ScanSource),
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
		acceptances:           make(map[uuid.UUID]*domain.RiskAcceptance),
		tenantSettings:        make(map[uuid.UUID]domain.TenantSettings),
		tokens:                make(map[string]*auth.TokenRecord),
		tenants:               make(map[uuid.UUID]*domain.Tenant),
		users:                 make(map[uuid.UUID]auth.User),
		userIDs:               make(map[string]uuid.UUID),
		members:               make(map[string]memMember),
		sessions:              make(map[string]auth.SessionRecord),
		localAdmins:           make(map[string]*auth.LocalAdmin),
		uploads:               make(map[string]*domain.Upload),
		actionLedger:          make(map[string]bool),
		bindings:              make(map[uuid.UUID]memBinding),
		idps:                  make(map[string]*domain.IdentityProvider),
		connectors:            make(map[string]*domain.Connector),
		trustRules:            make(map[uuid.UUID][]domain.TrustRuleRecord),
		federationJTIs:        make(map[string]time.Time),
		quotaUsage:            make(map[string]int64),
		groups:                make(map[uuid.UUID]*domain.FindingGroup),
		groupMembers:          make(map[uuid.UUID][]uuid.UUID),
		feedStates:            make(map[string]domain.FeedState),
		tenantParsers:         make(map[uuid.UUID][]domain.StoredParserObject),
		tenantAnalyzers:       make(map[uuid.UUID][]domain.StoredAnalyzerObject),
	}
}

type memoryAnalyzerEvent struct {
	tenant uuid.UUID
	ev     domain.AnalyzerEvent
}

// SaveClusterAnalyzer adds a cluster-scoped analyzer (kind domain.AnalyzerKindExternal or AnalyzerKindSBOM) to the in-memory store.
func (m *MemoryStore) SaveClusterAnalyzer(kind, name string, spec []byte, refused string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clusterAnalyzers = append(m.clusterAnalyzers, domain.StoredAnalyzerObject{Kind: kind, Origin: "cluster", Name: name, Spec: spec, Error: refused})
}

// SaveTenantAnalyzer adds a tenant's analyzer to the in-memory store.
func (m *MemoryStore) SaveTenantAnalyzer(tenantID uuid.UUID, kind, namespace, name string, spec []byte, refused string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenantAnalyzers[tenantID] = append(m.tenantAnalyzers[tenantID], domain.StoredAnalyzerObject{Kind: kind, Origin: "tenant", Namespace: namespace, Name: name, Spec: spec, Error: refused})
}

// ListAnalyzers lists the cluster's analyzers and the tenant's own.
func (m *MemoryStore) ListAnalyzers(_ context.Context, tenantID uuid.UUID) ([]domain.StoredAnalyzerObject, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := append([]domain.StoredAnalyzerObject{}, m.clusterAnalyzers...)
	return append(out, m.tenantAnalyzers[tenantID]...), nil
}

// RecordAnalyzerEvent keeps an event for the tenant that caused it.
func (m *MemoryStore) RecordAnalyzerEvent(_ context.Context, tenantID uuid.UUID, ev domain.AnalyzerEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ev.ID == uuid.Nil {
		ev.ID = domain.NewID()
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	m.analyzerEvents = append(m.analyzerEvents, memoryAnalyzerEvent{tenant: tenantID, ev: ev})
	return nil
}

// ListAnalyzerEvents lists the tenant's events of one analyzer, newest first.
func (m *MemoryStore) ListAnalyzerEvents(_ context.Context, tenantID uuid.UUID, kind, scope, namespace, name string, limit int) ([]domain.AnalyzerEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	var out []domain.AnalyzerEvent
	for i := len(m.analyzerEvents) - 1; i >= 0 && len(out) < limit; i-- {
		e := m.analyzerEvents[i]
		if e.tenant == tenantID && e.ev.Kind == kind && e.ev.Scope == scope && e.ev.Namespace == namespace && e.ev.Name == name {
			out = append(out, e.ev)
		}
	}
	return out, nil
}

// SetAdvisorySummary sets what AdvisorySummary answers, for tests.
func (m *MemoryStore) SetAdvisorySummary(s domain.AdvisorySummary) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.advisories = s
}

// AdvisorySummary answers what SetAdvisorySummary was given.
func (m *MemoryStore) AdvisorySummary(context.Context) (domain.AdvisorySummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.advisories, nil
}

// SaveClusterParser adds a cluster-scoped parser to the in-memory store.
func (m *MemoryStore) SaveClusterParser(name string, spec []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clusterParsers = append(m.clusterParsers, domain.StoredParserObject{
		Origin: "cluster",
		Name:   name,
		Spec:   spec,
	})
}

// SaveTenantParser adds a tenant-scoped parser to the in-memory store.
func (m *MemoryStore) SaveTenantParser(tenantID uuid.UUID, name string, spec []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenantParsers[tenantID] = append(m.tenantParsers[tenantID], domain.StoredParserObject{
		Origin: "tenant",
		Name:   name,
		Spec:   spec,
	})
}

// ListParsers lists cluster and tenant parsers.
func (m *MemoryStore) ListParsers(ctx context.Context, tenantID uuid.UUID) ([]domain.StoredParserObject, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []domain.StoredParserObject
	out = append(out, m.clusterParsers...)
	if tenantID != uuid.Nil {
		out = append(out, m.tenantParsers[tenantID]...)
	}
	return out, nil
}

// UpsertAccessBinding gives subject the role on the application, hierarchy, or tenant.
func (m *MemoryStore) UpsertAccessBinding(ctx context.Context, tenantID uuid.UUID, b *domain.AccessBinding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if b.ID == uuid.Nil {
		b.ID = domain.NewID()
	}
	if b.ManagedBy == "" {
		b.ManagedBy = "api"
	}
	if b.SubjectKind == "" {
		b.SubjectKind = "user"
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}

	for id, mb := range m.bindings {
		if mb.TenantID == tenantID && strings.EqualFold(mb.Binding.Subject, b.Subject) {
			match := false
			if b.TenantScope && mb.Binding.TenantScope {
				match = true
			} else if b.HierarchyPath != "" && mb.Binding.HierarchyPath == b.HierarchyPath {
				match = true
			} else if b.ApplicationID != uuid.Nil && mb.Binding.ApplicationID == b.ApplicationID {
				match = true
			}
			if match {
				b.ID = id
				m.bindings[id] = memBinding{TenantID: tenantID, Binding: *b}
				return nil
			}
		}
	}
	m.bindings[b.ID] = memBinding{TenantID: tenantID, Binding: *b}
	return nil
}

func (m *MemoryStore) ListAccessBindings(ctx context.Context, tenantID uuid.UUID, appID *uuid.UUID) ([]domain.AccessBinding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []domain.AccessBinding{}
	for _, mb := range m.bindings {
		if mb.TenantID == tenantID {
			if appID == nil || mb.Binding.ApplicationID == *appID {
				out = append(out, mb.Binding)
			}
		}
	}
	return out, nil
}

func (m *MemoryStore) GetAccessBinding(ctx context.Context, tenantID, id uuid.UUID) (*domain.AccessBinding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	mb, ok := m.bindings[id]
	if !ok || mb.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	cp := mb.Binding
	return &cp, nil
}

func (m *MemoryStore) DeleteAccessBinding(ctx context.Context, tenantID, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mb, ok := m.bindings[id]
	if !ok || mb.TenantID != tenantID {
		return store.ErrNotFound
	}
	delete(m.bindings, id)
	return nil
}

func (m *MemoryStore) BindingsFor(ctx context.Context, tenantID uuid.UUID, subjects []string) ([]domain.AccessBinding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []domain.AccessBinding{}
	for _, mb := range m.bindings {
		if mb.TenantID == tenantID {
			for _, s := range subjects {
				if strings.EqualFold(mb.Binding.Subject, s) {
					out = append(out, mb.Binding)
					break
				}
			}
		}
	}
	return out, nil
}

func idpKey(tenantID *uuid.UUID, name string) string {
	if tenantID == nil {
		return "cluster:" + name
	}
	return tenantID.String() + ":" + name
}

func (m *MemoryStore) SaveIdentityProvider(ctx context.Context, tenantID *uuid.UUID, idp domain.IdentityProvider) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idp.ID == uuid.Nil {
		idp.ID = domain.NewID()
	}
	idp.TenantID = tenantID
	now := time.Now().UTC()
	if idp.CreatedAt.IsZero() {
		idp.CreatedAt = now
	}
	idp.UpdatedAt = now
	cp := idp
	m.idps[idpKey(tenantID, idp.Name)] = &cp
	return nil
}

func (m *MemoryStore) GetIdentityProvider(ctx context.Context, tenantID *uuid.UUID, name string) (*domain.IdentityProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if idp, ok := m.idps[idpKey(tenantID, name)]; ok {
		cp := *idp
		return &cp, nil
	}
	if tenantID != nil {
		if idp, ok := m.idps[idpKey(nil, name)]; ok {
			cp := *idp
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) ListIdentityProviders(ctx context.Context, tenantID *uuid.UUID) ([]domain.IdentityProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.IdentityProvider
	if tenantID != nil {
		prefix := tenantID.String() + ":"
		for k, idp := range m.idps {
			if strings.HasPrefix(k, prefix) || strings.HasPrefix(k, "cluster:") {
				res = append(res, *idp)
			}
		}
	} else {
		for k, idp := range m.idps {
			if strings.HasPrefix(k, "cluster:") {
				res = append(res, *idp)
			}
		}
	}
	return res, nil
}

func (m *MemoryStore) DeleteIdentityProvider(ctx context.Context, tenantID *uuid.UUID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.idps, idpKey(tenantID, name))
	return nil
}

func (m *MemoryStore) ApproveDomainClaim(ctx context.Context, tenantID *uuid.UUID, name, domainName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	idp, ok := m.idps[idpKey(tenantID, name)]
	if !ok {
		return store.ErrNotFound
	}
	now := time.Now().UTC()
	found := false
	for i := range idp.Status.Domains {
		if idp.Status.Domains[i].Domain == domainName {
			idp.Status.Domains[i].Approved = true
			idp.Status.Domains[i].VerifiedAt = &now
			found = true
			break
		}
	}
	if !found {
		idp.Status.Domains = append(idp.Status.Domains, domain.DomainClaimStatus{
			Domain:     domainName,
			Approved:   true,
			VerifiedAt: &now,
		})
	}
	return nil
}

func connKey(tenantID uuid.UUID, name string) string {
	return tenantID.String() + ":" + name
}

func (m *MemoryStore) SaveConnector(ctx context.Context, tenantID uuid.UUID, conn domain.Connector) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if conn.ID == uuid.Nil {
		conn.ID = domain.NewID()
	}
	conn.TenantID = tenantID
	if prev, ok := m.connectors[connKey(tenantID, conn.Name)]; ok && prev.ID != uuid.Nil {
		conn.ID = prev.ID // the id is stable across saves, as in PostgreSQL (ON CONFLICT keeps it)
	} else if conn.ID == uuid.Nil {
		conn.ID = domain.NewID()
	}
	now := time.Now().UTC()
	if conn.CreatedAt.IsZero() {
		conn.CreatedAt = now
	}
	conn.UpdatedAt = now
	cp := conn
	m.connectors[connKey(tenantID, conn.Name)] = &cp
	return nil
}

func (m *MemoryStore) GetConnector(ctx context.Context, tenantID uuid.UUID, name string) (*domain.Connector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	conn, ok := m.connectors[connKey(tenantID, name)]
	if !ok {
		return nil, store.ErrConnectorNotFound
	}
	cp := *conn
	return &cp, nil
}

// GetConnectorByID finds a connector by its id alone (inbound webhooks, D78).
func (m *MemoryStore) GetConnectorByID(ctx context.Context, id uuid.UUID) (*domain.Connector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.connectors {
		if id != uuid.Nil && c.ID == id {
			cp := *c
			return &cp, nil
		}
	}
	return nil, store.ErrConnectorNotFound
}

func (m *MemoryStore) ListConnectors(ctx context.Context, tenantID uuid.UUID, connType ...domain.ConnectorType) ([]domain.Connector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := tenantID.String() + ":"
	var res []domain.Connector
	targetType := ""
	if len(connType) > 0 && connType[0] != "" {
		targetType = string(connType[0])
	}
	for k, c := range m.connectors {
		if strings.HasPrefix(k, prefix) {
			if targetType == "" || string(c.Type) == targetType {
				res = append(res, *c)
			}
		}
	}
	return res, nil
}

func (m *MemoryStore) DeleteConnector(ctx context.Context, tenantID uuid.UUID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := connKey(tenantID, name)
	if _, ok := m.connectors[key]; !ok {
		return store.ErrConnectorNotFound
	}
	delete(m.connectors, key)
	return nil
}

func (m *MemoryStore) UpdateConnectorStatus(ctx context.Context, tenantID uuid.UUID, name string, status domain.ConnectorStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	conn, ok := m.connectors[connKey(tenantID, name)]
	if !ok {
		return store.ErrConnectorNotFound
	}
	conn.Status = status
	conn.UpdatedAt = time.Now().UTC()
	return nil
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

	key := sbom.TenantID.String() + ":" + sbom.AssetID.String() + ":" + sbom.Track
	cp := *sbom
	m.sboms[key] = &cp
	m.sbomComponents[sbom.ID.String()] = components
	return nil
}

// GetSBOM retrieves the SBOM document and component inventory for an asset.
func (m *MemoryStore) GetSBOM(ctx context.Context, tenantID, assetID uuid.UUID) (*domain.SBOM, []domain.SBOMComponent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// The primary track first (main, then default), else the newest: the same rule as PostgreSQL.
	var best *domain.SBOM
	rank := func(t string) int {
		switch t {
		case "main":
			return 0
		case "default":
			return 1
		}
		return 2
	}
	prefix := tenantID.String() + ":" + assetID.String() + ":"
	for k, v := range m.sboms {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if best == nil || rank(v.Track) < rank(best.Track) || (rank(v.Track) == rank(best.Track) && v.CreatedAt.After(best.CreatedAt)) {
			best = v
		}
	}
	if best == nil {
		return nil, nil, nil
	}
	comps := m.sbomComponents[best.ID.String()]
	cp := *best
	return &cp, comps, nil
}

// ListFindings returns all findings for a given tenant.
// CanonicalVulnIDs: the in-memory store has no alias table.
func (m *MemoryStore) CanonicalVulnIDs(ctx context.Context, tenantID uuid.UUID, ids []string) (map[string]string, error) {
	return map[string]string{}, nil
}

// ListCorrelated returns the other findings that share the correlation key of a finding.
func (m *MemoryStore) ListCorrelated(ctx context.Context, tenantID, findingID uuid.UUID) ([]*domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var self *domain.Finding
	for _, f := range m.findings {
		if f.TenantID == tenantID && f.ID == findingID {
			self = f
			break
		}
	}
	if self == nil || self.CorrelationKey == "" {
		return nil, nil
	}
	var out []*domain.Finding
	for _, f := range m.findings {
		if f.TenantID == tenantID && f.ID != findingID && f.CorrelationKey == self.CorrelationKey {
			cp := *f
			out = append(out, &cp)
		}
	}
	return out, nil
}

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

// ListApplicationAssets lists the assets attached to an application.
func (m *MemoryStore) ListApplicationAssets(_ context.Context, tenantID, appID uuid.UUID) ([]store.AppAsset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []store.AppAsset
	for _, a := range m.assets {
		if a.TenantID == tenantID && a.ApplicationID != nil && *a.ApplicationID == appID {
			out = append(out, store.AppAsset{
				ID:   a.ID,
				Name: a.DisplayName,
			})
		}
	}
	return out, nil
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

	composite := fmt.Sprintf("%s:%s:%s:%s:%s", scope.TenantID, scope.IngestRunID, scope.ScannerFamily, scope.AssetID, scope.Track)
	cp := *scope
	m.ingestRunScopes[composite] = &cp
	return nil
}

func copyAcceptance(ra *domain.RiskAcceptance) *domain.RiskAcceptance {
	cp := *ra
	cp.FindingIDs = append([]uuid.UUID{}, ra.FindingIDs...)
	return &cp
}

// CreateRiskAcceptance stores an acceptance.
func (m *MemoryStore) CreateRiskAcceptance(ctx context.Context, tenantID uuid.UUID, ra *domain.RiskAcceptance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := copyAcceptance(ra)
	cp.TenantID = tenantID
	m.acceptances[ra.ID] = cp
	return nil
}

// GetRiskAcceptance returns one acceptance.
func (m *MemoryStore) GetRiskAcceptance(ctx context.Context, tenantID, id uuid.UUID) (*domain.RiskAcceptance, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ra, ok := m.acceptances[id]
	if !ok || ra.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	return copyAcceptance(ra), nil
}

// ListRiskAcceptances returns acceptances newest first.
func (m *MemoryStore) ListRiskAcceptances(ctx context.Context, tenantID uuid.UUID, status domain.RiskAcceptanceStatus, limit int) ([]*domain.RiskAcceptance, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*domain.RiskAcceptance
	for _, ra := range m.acceptances {
		if ra.TenantID == tenantID && (status == "" || ra.Status == status) {
			out = append(out, copyAcceptance(ra))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// SetRiskAcceptanceStatus moves an acceptance between statuses, only from the expected one.
func (m *MemoryStore) SetRiskAcceptanceStatus(ctx context.Context, tenantID, id uuid.UUID, from, to domain.RiskAcceptanceStatus, by, note string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ra, ok := m.acceptances[id]
	if !ok || ra.TenantID != tenantID {
		return store.ErrNotFound
	}
	if ra.Status != from {
		return store.ErrVersionConflict
	}
	ra.Status, ra.DecidedAt = to, &at
	if by != "" {
		ra.Approver = by
	}
	if note != "" {
		ra.DecisionNote = note
	}
	return nil
}

// FindingsUnderAcceptance maps findings to the pending or approved acceptance that covers them.
func (m *MemoryStore) FindingsUnderAcceptance(ctx context.Context, tenantID uuid.UUID, findingIDs []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	want := map[uuid.UUID]bool{}
	for _, id := range findingIDs {
		want[id] = true
	}
	out := map[uuid.UUID]uuid.UUID{}
	for _, ra := range m.acceptances {
		if ra.TenantID != tenantID || (ra.Status != domain.AcceptancePending && ra.Status != domain.AcceptanceApproved) {
			continue
		}
		for _, fid := range ra.FindingIDs {
			if want[fid] {
				out[fid] = ra.ID
			}
		}
	}
	return out, nil
}

// ListDueAcceptances returns approved acceptances past their expiry.
func (m *MemoryStore) ListDueAcceptances(ctx context.Context, tenantID uuid.UUID, now time.Time) ([]*domain.RiskAcceptance, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*domain.RiskAcceptance
	for _, ra := range m.acceptances {
		if ra.TenantID == tenantID && ra.Status == domain.AcceptanceApproved && !ra.ExpiresAt.After(now) {
			out = append(out, copyAcceptance(ra))
		}
	}
	return out, nil
}

// TenantsWithDueAcceptances lists tenants that have an approved acceptance past its expiry.
func (m *MemoryStore) TenantsWithDueAcceptances(ctx context.Context, now time.Time) ([]uuid.UUID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, ra := range m.acceptances {
		if ra.Status == domain.AcceptanceApproved && !ra.ExpiresAt.After(now) && !seen[ra.TenantID] {
			seen[ra.TenantID] = true
			out = append(out, ra.TenantID)
		}
	}
	return out, nil
}

// GetTenantSettings returns the tenant's settings, with defaults.
func (m *MemoryStore) GetTenantSettings(ctx context.Context, tenantID uuid.UUID) (domain.TenantSettings, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.tenantSettings[tenantID]; ok {
		return s, nil
	}
	return domain.ParseTenantSettings(nil), nil
}

// SaveTenantSettings stores the tenant's settings.
func (m *MemoryStore) SaveTenantSettings(ctx context.Context, tenantID uuid.UUID, settings domain.TenantSettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenantSettings[tenantID] = settings
	return nil
}

// UpdateFindingTriage applies a human decision if the finding is still at expectedVersion.
func (m *MemoryStore) UpdateFindingTriage(ctx context.Context, tenantID uuid.UUID, f *domain.Finding, expectedVersion int, events []*domain.FindingEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, cur := range m.findings {
		if cur.TenantID != tenantID || cur.ID != f.ID {
			continue
		}
		if cur.Version != expectedVersion {
			return store.ErrVersionConflict
		}
		cp := *f
		cp.Version = expectedVersion + 1
		m.findings[key] = &cp
		f.Version = cp.Version
		evKey := tenantID.String() + ":" + f.ID.String()
		for _, ev := range events {
			e := *ev
			if e.ID == domain.NilID {
				e.ID = domain.NewID()
			}
			m.findingEvents[evKey] = append(m.findingEvents[evKey], &e)
		}
		return nil
	}
	return store.ErrNotFound
}

// FindFindingsForVEX implements VEXMatcher for tests using MemoryStore.
func (m *MemoryStore) FindFindingsForVEX(ctx context.Context, tenantID uuid.UUID, vulnIDs, purlBases []string, appID *uuid.UUID) ([]*domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vulnSet := make(map[string]bool, len(vulnIDs)*3)
	for _, v := range vulnIDs {
		vulnSet[v] = true
		vulnSet[strings.ToUpper(v)] = true
		vulnSet[strings.ToLower(v)] = true
	}

	baseSet := make(map[string]bool, len(purlBases))
	for _, b := range purlBases {
		baseSet[b] = true
	}

	var out []*domain.Finding
	for _, f := range m.findings {
		if f.TenantID != tenantID {
			continue
		}
		if appID != nil && f.ApplicationID != *appID {
			continue
		}
		vulnMatch := vulnSet[f.RuleID] || vulnSet[strings.ToUpper(f.RuleID)] || vulnSet[strings.ToLower(f.RuleID)]
		if !vulnMatch && f.VulnerabilityID != nil {
			v := *f.VulnerabilityID
			if vulnSet[v] || vulnSet[strings.ToUpper(v)] || vulnSet[strings.ToLower(v)] {
				vulnMatch = true
			}
		}
		if !vulnMatch {
			continue
		}

		if len(baseSet) > 0 {
			if f.Location.Package == nil {
				continue
			}
			purl := f.Location.Package.Purl
			purlBase := f.Location.Package.PurlBase
			if purlBase == "" && purl != "" {
				_, purlBase, _ = normalize.CanonicalPURL(purl)
			}
			if !baseSet[purlBase] && !baseSet[purl] {
				continue
			}
		}

		out = append(out, f)
	}
	return out, nil
}

// ListIngestRuns returns runs newest first, after the given position.
func (m *MemoryStore) ListIngestRuns(ctx context.Context, tenantID uuid.UUID, limit int, after *store.RunPosition) ([]*domain.IngestRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var all []*domain.IngestRun
	for _, r := range m.ingestRuns {
		if r.TenantID != tenantID {
			continue
		}
		if after != nil {
			older := r.CreatedAt.Before(after.CreatedAt) || (r.CreatedAt.Equal(after.CreatedAt) && r.ID.String() < after.ID.String())
			if !older {
				continue
			}
		}
		cp := *r
		all = append(all, &cp)
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.After(all[j].CreatedAt)
		}
		return all[i].ID.String() > all[j].ID.String()
	})
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

// ListRunScopes returns the scanner families a run reported on.
func (m *MemoryStore) ListRunScopes(ctx context.Context, tenantID, runID uuid.UUID) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for _, sc := range m.ingestRunScopes {
		if sc.TenantID == tenantID && sc.IngestRunID == runID {
			out = append(out, sc.ScannerFamily)
		}
	}
	return out, nil
}

// ReplaceRunResults stores the ephemeral results of a run, replacing earlier rows of the same run.
func (m *MemoryStore) ReplaceRunResults(ctx context.Context, tenantID, runID uuid.UUID, results []*domain.IngestRunResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var list []*domain.IngestRunResult
	for _, r := range results {
		cp := *r
		list = append(list, &cp)
	}
	m.ingestRunResults[fmt.Sprintf("%s:%s", tenantID, runID)] = list
	return nil
}

// ListRunResults returns the ephemeral results of a run.
func (m *MemoryStore) ListRunResults(ctx context.Context, tenantID, runID uuid.UUID) ([]*domain.IngestRunResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*domain.IngestRunResult
	for _, r := range m.ingestRunResults[fmt.Sprintf("%s:%s", tenantID, runID)] {
		cp := *r
		out = append(out, &cp)
	}
	return out, nil
}

// ListRunsForGate returns the runs of a source that carry the commit or image digest.
func (m *MemoryStore) ListRunsForGate(ctx context.Context, tenantID, scanSourceID uuid.UUID, commit, imageDigest string) ([]*domain.IngestRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*domain.IngestRun
	for _, r := range m.ingestRuns {
		if r.TenantID != tenantID || (scanSourceID != uuid.Nil && r.ScanSourceID != scanSourceID) {
			continue
		}
		if (commit != "" && r.Context.Commit == commit) || (imageDigest != "" && r.Context.ImageDigest == imageDigest) {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out, nil
}

// GetDispositionedScopeFindings returns decided findings that are still detected.
func (m *MemoryStore) GetDispositionedScopeFindings(ctx context.Context, tenantID, assetID uuid.UUID, track string) ([]*domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*domain.Finding
	for _, f := range m.findings {
		if f.TenantID != tenantID || f.AssetID != assetID || f.Track != track || f.Detection != domain.DetectionPresent {
			continue
		}
		switch f.State {
		case domain.StateRiskAccepted, domain.StateNotAffected, domain.StateOutOfScope, domain.StateDuplicate:
			cp := *f
			out = append(out, &cp)
		}
	}
	return out, nil
}

// GetRiskPolicySpec: the in-memory store has no policy objects.
func (m *MemoryStore) GetRiskPolicySpec(ctx context.Context, tenantID uuid.UUID) ([]byte, bool, error) {
	return nil, false, nil
}

// EnsureHierarchyPath: memory store stub.
func (m *MemoryStore) EnsureHierarchyPath(ctx context.Context, tenantID uuid.UUID, segments []string) (*domain.HierarchyNode, error) {
	if len(segments) == 0 {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	path := strings.Join(segments, ".")
	node := &domain.HierarchyNode{
		ID: domain.NewID(), TenantID: tenantID, Name: segments[len(segments)-1],
		Slug: segments[len(segments)-1], Path: path,
	}
	return node, nil
}

// ListHierarchyNodes: memory store stub.
func (m *MemoryStore) ListHierarchyNodes(ctx context.Context, tenantID uuid.UUID) ([]*domain.HierarchyNode, error) {
	return nil, nil
}

// HierarchyRollups: memory store stub.
func (m *MemoryStore) HierarchyRollups(ctx context.Context, tenantID uuid.UUID) ([]domain.HierarchyRollup, error) {
	return nil, nil
}

// GetSLAPolicySpec: the in-memory store has no policy objects.
func (m *MemoryStore) GetSLAPolicySpec(ctx context.Context, tenantID uuid.UUID) ([]byte, bool, error) {
	return nil, false, nil
}

// TenantsNeedingSLARecompute: none.
func (m *MemoryStore) TenantsNeedingSLARecompute(ctx context.Context) ([]uuid.UUID, error) {
	return nil, nil
}

// ClearSLARecompute: nothing to clear.
func (m *MemoryStore) ClearSLARecompute(ctx context.Context, tenantID uuid.UUID) error { return nil }

// ListActiveFindings pages the active findings of a tenant.
func (m *MemoryStore) ListActiveFindings(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]*domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*domain.Finding
	for _, f := range m.findings {
		if f.TenantID == tenantID && f.State.IsActive() && f.ID.String() > after.String() {
			cp := *f
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// GetApplication returns an application by id.
func (m *MemoryStore) GetApplication(ctx context.Context, tenantID, id uuid.UUID) (*domain.Application, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.applications {
		if a.TenantID == tenantID && a.ID == id {
			cp := *a
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

// ListTenantIDs lists the tenants the in-memory store knows.
func (m *MemoryStore) ListTenantIDs(ctx context.Context) ([]uuid.UUID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	add := func(id uuid.UUID) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, f := range m.findings {
		add(f.TenantID)
	}
	for _, b := range m.sboms {
		add(b.TenantID)
	}
	for id := range m.tenantAnalyzers {
		add(id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

// ListFindingsForRescore pages active or accepted findings that carry a vulnerability id.
func (m *MemoryStore) ListFindingsForRescore(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]*domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*domain.Finding
	for _, f := range m.findings {
		if f.TenantID != tenantID || f.VulnerabilityID == nil || f.ID.String() <= after.String() {
			continue
		}
		if f.State.IsActive() || f.State == domain.StateRiskAccepted {
			cp := *f
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// UpdateFindingRisk stores the scoring fields of findings.
func (m *MemoryStore) UpdateFindingRisk(ctx context.Context, tenantID uuid.UUID, fs []*domain.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range fs {
		for _, cur := range m.findings {
			if cur.TenantID == tenantID && cur.ID == f.ID {
				cur.RiskScore, cur.RiskBand, cur.KEV, cur.EPSSBucket, cur.SLAStart, cur.SLADue = f.RiskScore, f.RiskBand, f.KEV, f.EPSSBucket, f.SLAStart, f.SLADue
			}
		}
	}
	return nil
}

// MarkSLABreaches marks active, unpaused findings whose due date has passed.
func (m *MemoryStore) MarkSLABreaches(ctx context.Context, tenantID uuid.UUID, now time.Time) ([]uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []uuid.UUID
	for _, f := range m.findings {
		if f.TenantID == tenantID && f.State.IsActive() && f.SLADue != nil && !f.SLADue.After(now) && f.SLABreachedAt == nil && f.SLAPausedAt == nil {
			t := now
			f.SLABreachedAt = &t
			ids = append(ids, f.ID)
		}
	}
	return ids, nil
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
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.scanSourceRecords == nil {
			m.scanSourceRecords = make(map[string]*domain.ScanSource)
		}
		recKey := tenantID.String() + ":" + id.String()
		if src, ok := m.scanSourceRecords[recKey]; ok {
			if src.DisabledAt != nil {
				return uuid.Nil, store.ErrSourceDisabled
			}
			return id, nil
		}
		m.scanSourceRecords[recKey] = &domain.ScanSource{
			ID:         id,
			TenantID:   tenantID,
			Name:       id.String(),
			Type:       "upload",
			Categories: []string{"all"},
		}
		return id, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID.String() + ":" + ref
	if id, ok := m.scanSources[key]; ok {
		recKey := tenantID.String() + ":" + id.String()
		if src, ok := m.scanSourceRecords[recKey]; ok && src.DisabledAt != nil {
			return uuid.Nil, store.ErrSourceDisabled
		}
		return id, nil
	}
	if ref != "default" {
		return uuid.Nil, store.ErrNotFound
	}
	id := domain.NewID()
	m.scanSources[key] = id
	if m.scanSourceRecords == nil {
		m.scanSourceRecords = make(map[string]*domain.ScanSource)
	}
	recKey := tenantID.String() + ":" + id.String()
	m.scanSourceRecords[recKey] = &domain.ScanSource{
		ID:            id,
		TenantID:      tenantID,
		Name:          "default",
		Type:          "upload",
		ScannerFamily: "generic",
		Categories:    []string{"all"},
	}
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

// --- uploads for the in-memory store ------------------------------------------------------------

func (m *MemoryStore) CreateUpload(ctx context.Context, u *domain.Upload) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u.IdempotencyKey != "" {
		for _, o := range m.uploads {
			if o.TenantID == u.TenantID && o.IdempotencyKey == u.IdempotencyKey {
				return store.ErrUploadExists
			}
		}
	}
	cp := *u
	m.uploads[u.TenantID.String()+":"+u.ID.String()] = &cp
	return nil
}

func (m *MemoryStore) GetUpload(ctx context.Context, tenantID, id uuid.UUID) (*domain.Upload, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if u, ok := m.uploads[tenantID.String()+":"+id.String()]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, store.ErrNotFound
}

func (m *MemoryStore) FindUploadByKey(ctx context.Context, tenantID uuid.UUID, key string) (*domain.Upload, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.uploads {
		if u.TenantID == tenantID && u.IdempotencyKey == key {
			cp := *u
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) DeleteUpload(ctx context.Context, tenantID, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.uploads, tenantID.String()+":"+id.String())
	return nil
}

func (m *MemoryStore) CompleteUpload(ctx context.Context, tenantID, id uuid.UUID, sha256 string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.uploads[tenantID.String()+":"+id.String()]
	if !ok || u.Status != "created" {
		return false, nil
	}
	u.Status, u.SHA256 = "completed", sha256
	return true, nil
}

func (m *MemoryStore) FindRunByUpload(ctx context.Context, tenantID, uploadID uuid.UUID) (*domain.IngestRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.ingestRuns {
		if r.TenantID == tenantID && r.UploadID != nil && *r.UploadID == uploadID {
			cp := *r
			return &cp, nil
		}
	}
	return nil, nil
}

// ReserveAction reserves an action in the memory store action ledger (docs/16 D25).
func (m *MemoryStore) ReserveAction(ctx context.Context, tenantID, policyID, findingID uuid.UUID, action string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s:%s:%s:%s", tenantID, policyID, findingID, action)
	if m.actionLedger[key] {
		return false, nil
	}
	m.actionLedger[key] = true
	return true, nil
}

func (m *MemoryStore) ListPendingTickets(ctx context.Context, now time.Time, limit int) ([]store.PendingTicket, error) {
	return nil, nil
}

func (m *MemoryStore) CompleteTicket(ctx context.Context, tenantID, findingID uuid.UUID, connector, ticketRef, url string) error {
	return nil
}

func (m *MemoryStore) RetryTicket(ctx context.Context, tenantID, findingID uuid.UUID, errMsg string, next time.Time, giveUp bool) error {
	return nil
}

func (m *MemoryStore) DeferTicket(ctx context.Context, tenantID, findingID uuid.UUID, next time.Time) error {
	return nil
}

func (m *MemoryStore) SkipTicket(ctx context.Context, tenantID, findingID uuid.UUID, reason string) error {
	return nil
}

func (m *MemoryStore) FindingHasTicket(ctx context.Context, tenantID, findingID uuid.UUID, _ /* connector */, ticketRef string) (bool, error) {
	return false, nil
}

func (m *MemoryStore) CreateTicket(ctx context.Context, tenantID uuid.UUID, t *domain.Ticket) (*domain.Ticket, error) {
	return t, nil
}

func (m *MemoryStore) LinkFinding(ctx context.Context, tenantID, ticketID, findingID uuid.UUID) error {
	return nil
}

func (m *MemoryStore) TicketsOfFinding(ctx context.Context, tenantID, findingID uuid.UUID) ([]*domain.Ticket, error) {
	return nil, nil
}

func (m *MemoryStore) SetTicketState(ctx context.Context, tenantID, ticketID uuid.UUID, state string) error {
	return nil
}

func (m *MemoryStore) CountTicketsCreatedSince(ctx context.Context, tenantID uuid.UUID, connector string, since time.Time) (int, error) {
	return 0, nil
}

func (m *MemoryStore) RecordWebhookDelivery(ctx context.Context, tenantID uuid.UUID, connector, deliveryID string, expiresAt time.Time) (bool, error) {
	return true, nil
}

func (m *MemoryStore) GetScanSourceIngestionPolicy(ctx context.Context, tenantID, sourceID uuid.UUID) (*domain.IngestionPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sourcePolicies[tenantID.String()+":"+sourceID.String()], nil
}

func (m *MemoryStore) GetScanSource(ctx context.Context, tenantID, sourceID uuid.UUID) (*domain.ScanSource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := tenantID.String() + ":" + sourceID.String()
	if src, ok := m.scanSourceRecords[key]; ok {
		return src, nil
	}
	// Fallback check if it was known in scanSources map
	for k, id := range m.scanSources {
		if id == sourceID {
			parts := strings.SplitN(k, ":", 2)
			if len(parts) == 2 && parts[0] == tenantID.String() {
				return &domain.ScanSource{
					ID:         sourceID,
					TenantID:   tenantID,
					Name:       parts[1],
					Categories: []string{"all"},
				}, nil
			}
		}
	}
	if sourceID != uuid.Nil {
		return &domain.ScanSource{
			ID:         sourceID,
			TenantID:   tenantID,
			Name:       "default",
			Categories: []string{"all"},
		}, nil
	}
	return nil, store.ErrNotFound
}

func (m *MemoryStore) SaveScanSourceRecord(ctx context.Context, src *domain.ScanSource) (uuid.UUID, error) {
	if src == nil {
		return uuid.Nil, errors.New("scansource cannot be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if src.ID == uuid.Nil {
		src.ID = domain.NewID()
	}
	if len(src.Categories) == 0 {
		src.Categories = []string{"all"}
	}
	if m.scanSourceRecords == nil {
		m.scanSourceRecords = make(map[string]*domain.ScanSource)
	}
	if m.scanSources == nil {
		m.scanSources = make(map[string]uuid.UUID)
	}
	key := src.TenantID.String() + ":" + src.ID.String()
	m.scanSourceRecords[key] = src
	nameKey := src.TenantID.String() + ":" + src.Name
	m.scanSources[nameKey] = src.ID
	if src.IngestionPolicy != nil {
		if m.sourcePolicies == nil {
			m.sourcePolicies = make(map[string]*domain.IngestionPolicy)
		}
		m.sourcePolicies[key] = src.IngestionPolicy
	}
	return src.ID, nil
}

func (m *MemoryStore) SetScanSource(src *domain.ScanSource) {
	_, _ = m.SaveScanSourceRecord(context.Background(), src)
}

func (m *MemoryStore) GetApplicationScanSources(ctx context.Context, tenantID, appID uuid.UUID) ([]domain.ApplicationScanSource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var res []domain.ApplicationScanSource
	for _, src := range m.scanSourceRecords {
		if src.TenantID == tenantID && src.ApplicationID == appID {
			authType := "token"
			hasToken := src.Auth.TokenSecretRef != nil
			feds := src.Auth.AllFederations()
			if hasToken && len(feds) > 0 {
				authType = "multi"
			} else if len(feds) > 0 {
				authType = "federation"
			}

			var trackedRefs []string
			if src.IngestionPolicy != nil {
				trackedRefs = src.IngestionPolicy.TrackedRefs
			}

			totalRuns := 0
			var lastScan *time.Time
			for _, run := range m.ingestRuns {
				if run.TenantID == tenantID && run.ScanSourceID == src.ID {
					totalRuns++
					if lastScan == nil || run.CreatedAt.After(*lastScan) {
						t := run.CreatedAt
						lastScan = &t
					}
				}
			}

			res = append(res, domain.ApplicationScanSource{
				ID:            src.ID,
				Name:          src.Name,
				Type:          src.Type,
				ScannerFamily: src.ScannerFamily,
				Categories:    src.Categories,
				AuthType:      authType,
				Active:        src.DisabledAt == nil,
				TrackedRefs:   trackedRefs,
				CreatedAt:     src.CreatedAt,
				DisabledAt:    src.DisabledAt,
				TotalRuns:     totalRuns,
				LastScanAt:    lastScan,
			})
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].Name < res[j].Name
	})
	return res, nil
}

// SetIngestionPolicy sets the policy of a scan source, as the operator does for a ScanSource resource.
func (m *MemoryStore) SetIngestionPolicy(tenantID, sourceID uuid.UUID, p *domain.IngestionPolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sourcePolicies == nil {
		m.sourcePolicies = map[string]*domain.IngestionPolicy{}
	}
	m.sourcePolicies[tenantID.String()+":"+sourceID.String()] = p
}

func (m *MemoryStore) CreateHeldClose(ctx context.Context, tenantID uuid.UUID, hc *domain.HeldClose) error {
	return nil
}

func (m *MemoryStore) GetHeldClose(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.HeldClose, error) {
	return nil, nil
}

func (m *MemoryStore) ListHeldCloses(ctx context.Context, tenantID uuid.UUID, decision string) ([]domain.HeldClose, error) {
	return nil, nil
}

func (m *MemoryStore) DecideHeldClose(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, decision string, decidedBy string) error {
	return nil
}

func (m *MemoryStore) ApplyHeldClose(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, decidedBy string) (int, error) {
	return 0, nil
}

// SupersedeHeldCloses: the in-memory store keeps no held closes (D83 is a PostgreSQL behaviour).
func (m *MemoryStore) SupersedeHeldCloses(ctx context.Context, tenantID uuid.UUID, scope domain.CloseScope, byRunID uuid.UUID) (int, error) {
	return 0, nil
}

func (m *MemoryStore) SaveTrustRules(ctx context.Context, tenantID, scanSourceID uuid.UUID, rules []domain.TrustRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var kept []domain.TrustRuleRecord
	for _, tr := range m.trustRules[tenantID] {
		if tr.ScanSourceID != scanSourceID {
			kept = append(kept, tr)
		}
	}
	for _, r := range rules {
		kept = append(kept, domain.TrustRuleRecord{
			ID:           domain.NewID(),
			TenantID:     tenantID,
			ScanSourceID: scanSourceID,
			Rule:         r,
			CreatedAt:    time.Now().UTC(),
		})
	}
	m.trustRules[tenantID] = kept
	return nil
}

func (m *MemoryStore) ListTrustRules(ctx context.Context, tenantID uuid.UUID) ([]domain.TrustRuleRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]domain.TrustRuleRecord, len(m.trustRules[tenantID]))
	copy(res, m.trustRules[tenantID])
	return res, nil
}

func (m *MemoryStore) ListTrustRulesByIssuer(ctx context.Context, tenantID uuid.UUID, issuer string) ([]domain.TrustRuleRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.TrustRuleRecord
	for _, tr := range m.trustRules[tenantID] {
		if tr.Rule.Issuer == issuer {
			res = append(res, tr)
		}
	}
	return res, nil
}

func (m *MemoryStore) RecordFederationJTI(ctx context.Context, issuer, jti string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := issuer + ":" + jti
	if _, exists := m.federationJTIs[key]; exists {
		return store.ErrJTIReplay
	}
	m.federationJTIs[key] = expiresAt
	return nil
}

func (m *MemoryStore) PurgeExpiredFederationJTIs(ctx context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var purged int64
	for k, exp := range m.federationJTIs {
		if exp.Before(now) {
			delete(m.federationJTIs, k)
			purged++
		}
	}
	return purged, nil
}

func (m *MemoryStore) IncrementQuota(ctx context.Context, tenantID uuid.UUID, key string, windowStart time.Time, amount int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mapKey := tenantID.String() + ":" + key + ":" + windowStart.UTC().Format(time.RFC3339)
	m.quotaUsage[mapKey] += amount
	return m.quotaUsage[mapKey], nil
}

func (m *MemoryStore) GetQuotaUsage(ctx context.Context, tenantID uuid.UUID, key string, windowStart time.Time) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	mapKey := tenantID.String() + ":" + key + ":" + windowStart.UTC().Format(time.RFC3339)
	return m.quotaUsage[mapKey], nil
}

func (m *MemoryStore) LookupScanSource(ctx context.Context, sourceID uuid.UUID) (uuid.UUID, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for k, id := range m.scanSources {
		if id == sourceID {
			parts := strings.SplitN(k, ":", 2)
			if len(parts) == 2 {
				tID, _ := uuid.Parse(parts[0])
				return tID, parts[1], nil
			}
		}
	}
	return uuid.Nil, "", store.ErrNotFound
}

func (m *MemoryStore) CreateFindingGroup(ctx context.Context, g *domain.FindingGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	g.CreatedAt = time.Now()
	g.UpdatedAt = g.CreatedAt
	cp := *g
	m.groups[g.ID] = &cp
	return nil
}

func (m *MemoryStore) GetFindingGroup(ctx context.Context, tenantID, id uuid.UUID) (*domain.FindingGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.groups[id]
	if !ok || g.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	cp := *g
	cp.MemberCount = len(m.groupMembers[id])
	return &cp, nil
}

func (m *MemoryStore) ListFindingGroups(ctx context.Context, tenantID uuid.UUID) ([]domain.FindingGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []domain.FindingGroup
	for id, g := range m.groups {
		if g.TenantID == tenantID {
			cp := *g
			cp.MemberCount = len(m.groupMembers[id])
			out = append(out, cp)
		}
	}
	return out, nil
}

func (m *MemoryStore) DeleteFindingGroup(ctx context.Context, tenantID, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g, ok := m.groups[id]; ok && g.TenantID == tenantID {
		delete(m.groups, id)
		delete(m.groupMembers, id)
	}
	return nil
}

func (m *MemoryStore) AddGroupMembers(ctx context.Context, tenantID, groupID uuid.UUID, findingIDs []uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g, ok := m.groups[groupID]; !ok || g.TenantID != tenantID {
		return store.ErrNotFound
	}
	have := map[uuid.UUID]bool{}
	for _, id := range m.groupMembers[groupID] {
		have[id] = true
	}
	for _, id := range findingIDs {
		if !have[id] {
			have[id] = true
			m.groupMembers[groupID] = append(m.groupMembers[groupID], id)
		}
	}
	return nil
}

func (m *MemoryStore) RemoveGroupMembers(ctx context.Context, tenantID, groupID uuid.UUID, findingIDs []uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	drop := map[uuid.UUID]bool{}
	for _, id := range findingIDs {
		drop[id] = true
	}
	var keep []uuid.UUID
	for _, id := range m.groupMembers[groupID] {
		if !drop[id] {
			keep = append(keep, id)
		}
	}
	m.groupMembers[groupID] = keep
	return nil
}

func (m *MemoryStore) ListGroupFindings(ctx context.Context, tenantID, groupID uuid.UUID) ([]uuid.UUID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if g, ok := m.groups[groupID]; !ok || g.TenantID != tenantID {
		return nil, nil
	}
	return append([]uuid.UUID(nil), m.groupMembers[groupID]...), nil
}

func (m *MemoryStore) GroupMemberApplications(ctx context.Context, tenantID, groupID uuid.UUID) ([]uuid.UUID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, fid := range m.groupMembers[groupID] {
		for _, f := range m.findings {
			if f.TenantID == tenantID && f.ID == fid && !seen[f.ApplicationID] {
				seen[f.ApplicationID] = true
				out = append(out, f.ApplicationID)
			}
		}
	}
	return out, nil
}

func (m *MemoryStore) RequestGroupTicket(ctx context.Context, tenantID, groupID uuid.UUID, requestedBy string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[groupID]
	if !ok || g.TenantID != tenantID {
		return false, nil
	}
	if g.Ticket != nil && g.Ticket.Status != "failed" {
		return false, nil
	}
	g.Ticket = &domain.GroupTicket{Status: "reserved", RequestedBy: requestedBy}
	return true, nil
}

func (m *MemoryStore) CreateSavedView(ctx context.Context, v *domain.SavedView) error {
	return nil
}

func (m *MemoryStore) GetSavedView(ctx context.Context, tenantID, id uuid.UUID) (*domain.SavedView, error) {
	return &domain.SavedView{ID: id, TenantID: tenantID, Name: "default-view", Query: "is:open"}, nil
}

func (m *MemoryStore) ListSavedViews(ctx context.Context, tenantID uuid.UUID, owner string) ([]domain.SavedView, error) {
	return nil, nil
}

func (m *MemoryStore) DeleteSavedView(ctx context.Context, tenantID, id uuid.UUID) error {
	return nil
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func freshResult(tenant, run uuid.UUID, rec StagedRecord) *domain.IngestRunResult {
	return &domain.IngestRunResult{TenantID: tenant, IngestRunID: run, FindingKey: rec.FindingKey, IsNew: true,
		Severity: rec.Severity, Category: rec.Category, Location: rec.Location, CreatedAt: rec.SeenAt}
}

// decisionStore finds decisions on other tracks (PostgreSQL; the in-memory store has none).
type decisionStore interface {
	DecisionsOnOtherTracks(ctx context.Context, tenantID, assetID uuid.UUID, track string, lineageKeys []string) (map[string]*domain.Finding, error)
}

// carryDecisions gives each newly created finding the not_affected or out_of_scope decision made about the same
// issue (the same lineage key) on another track of the same asset (D57). Only those two states carry: they are
// statements about the code or the component, which another branch of the same asset shares; a risk acceptance
// has its own owner, expiry and scope (D39) and does not. The decision carries only when the content hash is
// the same: the same evidence gets the same decision, and changed code is looked at again (the rule D18 applies
// to a decided finding whose code changed). Existing findings are never changed: nothing is retroactive.
func carryDecisions(ctx context.Context, st Store, scope CloseScope, findings []*domain.Finding, existing map[string]*domain.Finding) ([]*domain.FindingEvent, map[string]bool, error) {
	ds, ok := st.(decisionStore)
	if !ok {
		return nil, nil, nil
	}
	var fresh []*domain.Finding
	var keys []string
	for _, f := range findings {
		if _, old := existing[f.FindingKey]; old || f.LineageKey == "" {
			continue
		}
		fresh = append(fresh, f)
		keys = append(keys, f.LineageKey)
	}
	if len(keys) == 0 {
		return nil, nil, nil
	}
	decided, err := ds.DecisionsOnOtherTracks(ctx, scope.TenantID, scope.AssetID, scope.Track, keys)
	if err != nil {
		return nil, nil, fmt.Errorf("ingest: reading decisions on other tracks: %w", err)
	}
	var events []*domain.FindingEvent
	carriedKeys := map[string]bool{}
	for _, f := range fresh {
		src, ok := decided[f.LineageKey]
		if !ok || src.ContentHash != f.ContentHash {
			continue
		}
		f.PreviousState = f.State
		f.State = src.State
		f.Justification = src.Justification
		f.ImpactStatement = src.ImpactStatement
		f.StateReason = "carried from track " + src.Track
		note := fmt.Sprintf("decision carried from finding %s on track %s", src.ID, src.Track)
		if src.Justification != "" {
			note += " (" + src.Justification + ")"
		}
		events = append(events, &domain.FindingEvent{
			ID: domain.NewID(), FindingID: f.ID, At: f.FirstSeen, Actor: "system:parser", Type: "decision_carried",
			From: mustJSON(map[string]any{"state": string(f.PreviousState)}), To: mustJSON(map[string]any{"state": string(f.State), "from_finding": src.ID.String()}),
			Note: note,
		})
		carriedKeys[f.FindingKey] = true
	}
	return events, carriedKeys, nil
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

// Feeds & Mirror support in MemoryStore (D86, D88).
func (m *MemoryStore) GetClusterFeedMirror(ctx context.Context) (*domain.FeedMirrorSpec, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.feedMirror, nil
}

func (m *MemoryStore) SetClusterFeedMirror(mirror *domain.FeedMirrorSpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.feedMirror = mirror
}

func (m *MemoryStore) ListFeedStates(ctx context.Context) ([]domain.FeedState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.FeedState, 0, len(m.feedStates))
	for _, s := range m.feedStates {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Feed < out[j].Feed })
	return out, nil
}

func (m *MemoryStore) SetFeedState(state domain.FeedState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.feedStates == nil {
		m.feedStates = make(map[string]domain.FeedState)
	}
	m.feedStates[state.Feed] = state
}
