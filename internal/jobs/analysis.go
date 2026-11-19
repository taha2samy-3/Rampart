package jobs

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"rampart/internal/domain"
)

// AnalyzeSBOMArgs is one analyzer's work on one SBOM. Dependency-Track runs the same unit as a workflow step: one call to one
// analyzer with the whole BOM.
type AnalyzeSBOMArgs struct {
	TenantID          uuid.UUID `json:"tenant_id"`
	SBOMID            uuid.UUID `json:"sbom_id"`
	AnalyzerKind      string    `json:"analyzer_kind"` // external or sbom
	AnalyzerScope     string    `json:"analyzer_scope"`
	AnalyzerNamespace string    `json:"analyzer_namespace,omitempty"`
	AnalyzerName      string    `json:"analyzer_name"`
	Trigger           string    `json:"trigger"` // upload, manual or scheduled
}

// Kind returns the job kind for River.
func (AnalyzeSBOMArgs) Kind() string { return "analyze_sbom" }

// Ref is the analyzer the job names.
func (a AnalyzeSBOMArgs) Ref() domain.AnalyzerRef {
	return domain.AnalyzerRef{Kind: a.AnalyzerKind, Scope: a.AnalyzerScope, Namespace: a.AnalyzerNamespace, Name: a.AnalyzerName}
}

const (
	// AnalysisQueue is the analysis queue. An analyzer that is slow or down holds one of its workers, never an ingest worker.
	AnalysisQueue = "analysis"
	// AnalysisMaxAttempts is Dependency-Track's retry budget for an analyzer. River spaces the attempts out with its default
	// backoff, a few seconds at first and some minutes by the last.
	AnalysisMaxAttempts = 5
	// AnalysisJobTimeout bounds one attempt: the longest an analyzer may take (ten minutes) and the merge after it.
	AnalysisJobTimeout = 20 * time.Minute
)

// AnalyzeSBOMHandler runs one analysis. attempt starts at 1; the handler is told the budget so that it can say the last failure is the last.
type AnalyzeSBOMHandler func(ctx context.Context, args AnalyzeSBOMArgs, attempt, maxAttempts int) error

// AnalyzeSBOMWorker runs analyze_sbom jobs.
type AnalyzeSBOMWorker struct {
	river.WorkerDefaults[AnalyzeSBOMArgs]
	Handle AnalyzeSBOMHandler
}

func (w *AnalyzeSBOMWorker) Work(ctx context.Context, job *river.Job[AnalyzeSBOMArgs]) error {
	if w.Handle == nil {
		return ErrNoHandler
	}
	err := w.Handle(ctx, job.Args, job.Attempt, job.MaxAttempts)
	if IsPermanent(err) {
		return river.JobCancel(err)
	}
	return err
}

// Timeout bounds one attempt.
func (w *AnalyzeSBOMWorker) Timeout(*river.Job[AnalyzeSBOMArgs]) time.Duration {
	return AnalysisJobTimeout
}

// EnqueueAnalysis inserts one analysis job. Which analyses may be queued at once is decided before this, by claiming the analysis in the
// database (domain.AnalysisStore.ClaimSBOMAnalysis), not by River's unique jobs: River keeps a finished job as a duplicate until its
// cleaner removes it, which would refuse a person who asks again.
func (q *RiverQueue) EnqueueAnalysis(ctx context.Context, args AnalyzeSBOMArgs) error {
	_, err := q.client.Insert(ctx, args, &river.InsertOpts{
		Queue:       AnalysisQueue,
		MaxAttempts: AnalysisMaxAttempts,
		Priority:    domain.AnalysisTrigger(args.Trigger).Priority(),
	})
	return err
}
