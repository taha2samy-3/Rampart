package domain

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNoSuchAnalyzer is returned when an analyzer to run is not one the tenant has.
var ErrNoSuchAnalyzer = errors.New("no such analyzer")

// AnalysisState is where one analysis of one SBOM by one analyzer stands. The set is Dependency-Track's workflow step states
// (PENDING, COMPLETED, FAILED, CANCELLED, NOT_APPLICABLE, TIMED_OUT) with "running" added, because Rampart shows it.
type AnalysisState string

const (
	AnalysisPending       AnalysisState = "pending"        // claimed and queued; nothing has called the analyzer yet
	AnalysisRunning       AnalysisState = "running"        // a worker is calling the analyzer or merging its answer
	AnalysisCompleted     AnalysisState = "completed"      // the analyzer answered and its findings were merged
	AnalysisFailed        AnalysisState = "failed"         // the analyzer did not answer, or its answer could not be merged: nothing was closed
	AnalysisTimedOut      AnalysisState = "timed_out"      // as failed, because the analyzer did not answer in time
	AnalysisCancelled     AnalysisState = "cancelled"      // the SBOM was replaced by a newer one, or the analyzer was removed
	AnalysisNotApplicable AnalysisState = "not_applicable" // the analyzer is switched off or refused
)

// Settled reports whether the analysis is over, one way or another.
func (s AnalysisState) Settled() bool { return s != AnalysisPending && s != AnalysisRunning }

// AnalysisTrigger is why an analysis was started. It sets the order the queue serves them in, as in Dependency-Track:
// a person asking comes first, an upload next, the scheduled sweep last.
type AnalysisTrigger string

const (
	TriggerUpload    AnalysisTrigger = "upload"
	TriggerManual    AnalysisTrigger = "manual"
	TriggerScheduled AnalysisTrigger = "scheduled"
)

// Priority is the River priority of a trigger: 1 is served first.
func (t AnalysisTrigger) Priority() int {
	switch t {
	case TriggerManual:
		return 1
	case TriggerUpload:
		return 2
	default:
		return 3
	}
}

// AnalyzerRef names one analyzer the way the API and the events do: its kind (external or sbom), whose it is (cluster or tenant),
// the namespace for a tenant's, and the name.
type AnalyzerRef struct {
	Kind      string `json:"kind"`
	Scope     string `json:"scope"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Family is the scanner family the findings of this analyzer carry. It is what keeps analyzers apart: a finding is closed only
// by the analyzer that reported it, and only when that analyzer has just answered.
func (r AnalyzerRef) Family() string {
	if r.Scope == "tenant" && r.Namespace != "" {
		return "analyzer:" + r.Namespace + "/" + r.Name
	}
	return "analyzer:" + r.Name
}

// SBOMAnalysis is the record of one analyzer's work on one SBOM.
type SBOMAnalysis struct {
	TenantID   uuid.UUID
	SBOMID     uuid.UUID
	Analyzer   AnalyzerRef
	State      AnalysisState
	Trigger    AnalysisTrigger
	Attempts   int
	Error      string
	Components int // the components sent to the analyzer
	Findings   int // the findings it returned
	Created    int // new findings after the merge
	Closed     int // findings it no longer reports
	StartedAt  *time.Time
	FinishedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	// LastManualAt is when a person last asked for this analysis; a later claim by an upload or the sweep keeps it (the cooldown
	// of docs/39 D.2 reads it).
	LastManualAt *time.Time
}

// AnalysisStore keeps what the analysis of SBOMs needs: the SBOMs by id, and the record of each analysis.
type AnalysisStore interface {
	// GetSBOMByID returns an SBOM and its components.
	GetSBOMByID(ctx context.Context, tenantID, sbomID uuid.UUID) (*SBOM, []SBOMComponent, error)
	// LatestSBOMs returns the newest SBOM of every asset and track (of one asset when assetID is set), without components.
	LatestSBOMs(ctx context.Context, tenantID uuid.UUID, assetID *uuid.UUID) ([]SBOM, error)
	// ClaimSBOMAnalysis records a pending analysis, and reports whether it did. It does not when one is already pending or
	// running for the same SBOM and analyzer (younger than staleAfter): only one runs at a time.
	ClaimSBOMAnalysis(ctx context.Context, a SBOMAnalysis, staleAfter time.Duration) (bool, error)
	// SaveSBOMAnalysis writes the state of an analysis that was claimed.
	SaveSBOMAnalysis(ctx context.Context, a SBOMAnalysis) error
	GetSBOMAnalysis(ctx context.Context, tenantID, sbomID uuid.UUID, ref AnalyzerRef) (*SBOMAnalysis, error)
	// ListSBOMAnalyses returns the records of all analyses for an SBOM.
	ListSBOMAnalyses(ctx context.Context, tenantID, sbomID uuid.UUID) ([]SBOMAnalysis, error)
	// ListDueSBOMs returns the newest SBOMs that this analyzer has not analysed since the cutoff, oldest analysis first: those
	// never analysed, those completed before completedBefore, and those that failed before failedBefore.
	ListDueSBOMs(ctx context.Context, tenantID uuid.UUID, ref AnalyzerRef, completedBefore, failedBefore time.Time, limit int) ([]uuid.UUID, error)
	// CountAnalysesInFlight counts the analyses pending or running, in every tenant, that are younger than staleAfter.
	CountAnalysesInFlight(ctx context.Context, staleAfter time.Duration) (int, error)
}
