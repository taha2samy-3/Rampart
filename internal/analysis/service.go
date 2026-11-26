// Package analysis runs the analyzers on SBOMs the way Dependency-Track does: when an SBOM is uploaded, when a person asks, and on a schedule.
//
// One analysis is one analyzer's work on one SBOM: one call with the whole SBOM, one record of how it went, and one ingest run
// that merges what it found. Findings carry the analyzer as their scanner family ("analyzer:<name>"), so an analyzer closes only what it
// reported itself, and only when it has just answered. An analyzer that fails closes nothing; the job is retried, and the last failure tells
// the tenant.
package analysis

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"rampart/internal/analyzer/client"
	"rampart/internal/analyzer/matcher"
	"rampart/internal/cron"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/integrations"
	"rampart/internal/jobs"
	"rampart/internal/store"
)

// Config sets how often and how much. The zero value is replaced by Dependency-Track's own numbers.
type Config struct {
	// MaxAge is how long an analysis stands before the sweep asks again (Dependency-Track: 24 hours).
	MaxAge time.Duration
	// FailedRetryAfter is how long the sweep waits before it tries an SBOM whose analysis failed through every retry.
	FailedRetryAfter time.Duration
	// MaxInFlight is how many analyses may be queued or running at once, in every tenant (Dependency-Track: 50).
	MaxInFlight int
	// StaleAfter frees an analysis that has been pending or running longer than this: a worker that died leaves one behind.
	StaleAfter time.Duration
	// ManualCooldown is the minimum cooldown between manual analyses of the same application.
	ManualCooldown time.Duration
}

func (c Config) withDefaults() Config {
	if c.MaxAge <= 0 {
		c.MaxAge = 24 * time.Hour
	}
	if c.FailedRetryAfter <= 0 {
		c.FailedRetryAfter = time.Hour
	}
	if c.MaxInFlight <= 0 {
		c.MaxInFlight = 50
	}
	if c.StaleAfter <= 0 {
		c.StaleAfter = time.Hour
	}
	if c.ManualCooldown <= 0 {
		c.ManualCooldown = 5 * time.Minute
	}
	return c
}

// Store is what the service reads and writes.
type Store interface {
	domain.AnalyzerStore
	domain.AnalyzerEvents
	domain.AnalysisStore
	GetIngestRun(ctx context.Context, tenantID, runID uuid.UUID) (*domain.IngestRun, error)
	CreateIngestRun(ctx context.Context, run *domain.IngestRun) error
	ListTenantIDs(ctx context.Context) ([]uuid.UUID, error)
}

// Merger merges findings into the inventory. *ingest.Processor is one.
type Merger interface {
	Process(ctx context.Context, pp ingest.ProcessParams) (ingest.Result, error)
	Finish(ctx context.Context, run *domain.IngestRun, status domain.IngestRunStatus, reason string)
}

// Enqueuer puts an analysis on the queue. *jobs.RiverQueue is one.
type Enqueuer interface {
	EnqueueAnalysis(ctx context.Context, args jobs.AnalyzeSBOMArgs) error
}

// ExternalAnalyzer is the connection to an analyzer service.
type ExternalAnalyzer interface {
	Analyze(ctx context.Context, scanID, assetID string, components []domain.SBOMComponent, options map[string]string) ([]domain.RawFinding, error)
	Close() error
}

// Dialer connects to the analyzer at target; secure asks for TLS.
type Dialer func(target string, secure bool) (ExternalAnalyzer, error)

func dialGRPC(target string, secure bool) (ExternalAnalyzer, error) {
	return client.Dial(target, secure)
}

// Service analyses SBOMs.
type Service struct {
	store      Store
	merger     Merger
	enqueuer   Enqueuer
	advisories matcher.AdvisoryStore
	dial       Dialer
	cfg        Config
	log        *slog.Logger
	now        func() time.Time
}

// New builds the service. advisories is where the built-in matcher reads the advisories from.
func New(store Store, merger Merger, enqueuer Enqueuer, advisories matcher.AdvisoryStore, cfg Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: store, merger: merger, enqueuer: enqueuer, advisories: advisories, dial: dialGRPC, cfg: cfg.withDefaults(), log: log, now: func() time.Time { return time.Now().UTC() }}
}

// SetDialer replaces how analyzer services are reached (a test serves one in the process).
func (s *Service) SetDialer(d Dialer) { s.dial = d }

// SetClock replaces the clock (a test moves time).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// entry is an analyzer the tenant can use, with its spec read.
type entry struct {
	ref      domain.AnalyzerRef
	object   domain.StoredAnalyzerObject
	external *domain.ExternalAnalyzerSpec
	sbom     *domain.SBOMAnalyzerSpec
	enabled  bool
	problem  string // why it cannot be used: the server refused its resource
}

func refOf(o domain.StoredAnalyzerObject) domain.AnalyzerRef {
	kind := "sbom"
	if o.Kind == domain.AnalyzerKindExternal {
		kind = "external"
	}
	return domain.AnalyzerRef{Kind: kind, Scope: o.Origin, Namespace: o.Namespace, Name: o.Name}
}

func readEntry(o domain.StoredAnalyzerObject) entry {
	e := entry{ref: refOf(o), object: o}
	if o.Error != "" {
		e.problem = o.Error
		return e
	}
	if o.Kind == domain.AnalyzerKindExternal {
		spec, err := domain.ParseExternalAnalyzerSpec(o.Spec, o.Origin == "tenant")
		if err != nil {
			e.problem = err.Error()
			return e
		}
		e.external, e.enabled = &spec, spec.IsEnabled()
		return e
	}
	spec, err := domain.ParseSBOMAnalyzerSpec(o.Spec)
	if err != nil {
		e.problem = err.Error()
		return e
	}
	e.sbom, e.enabled = &spec, spec.IsEnabled()
	return e
}

// analyzers returns the analyzers of a tenant, read.
func (s *Service) analyzers(ctx context.Context, tenantID uuid.UUID) ([]entry, error) {
	objs, err := s.store.ListAnalyzers(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]entry, 0, len(objs))
	for _, o := range objs {
		out = append(out, readEntry(o))
	}
	return out, nil
}

// usable keeps the analyzers that are switched on and accepted.
func usable(all []entry) []entry {
	var out []entry
	for _, e := range all {
		if e.problem == "" && e.enabled {
			out = append(out, e)
		}
	}
	return out
}

// SBOMStored starts the analysis of an SBOM that was just stored, with every analyzer the tenant has (ingest.AnalysisTrigger). The upload is not
// held up by it, and a failure to queue is logged, not returned: the sweep picks the SBOM up.
func (s *Service) SBOMStored(ctx context.Context, tenantID, sbomID uuid.UUID) {
	if _, err := s.DispatchSBOM(ctx, tenantID, sbomID, domain.TriggerUpload); err != nil {
		s.log.Warn("analysis: could not queue the analysis of a new SBOM; the scheduled sweep will", "tenant", tenantID, "sbom", sbomID, "error", err)
	}
}

// DispatchSBOM queues the analysis of one SBOM by every analyzer of the tenant that is on, and returns how many it queued: an analysis
// already pending or running is not queued twice.
func (s *Service) DispatchSBOM(ctx context.Context, tenantID, sbomID uuid.UUID, trigger domain.AnalysisTrigger) (int, error) {
	all, err := s.analyzers(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	queued := 0
	var errs []error
	for _, e := range usable(all) {
		ok, err := s.enqueueOne(ctx, tenantID, sbomID, e.ref, trigger)
		if err != nil {
			errs = append(errs, err)
		}
		if ok {
			queued++
		}
	}
	return queued, errors.Join(errs...)
}

// DispatchAsset queues the newest SBOM of an asset (of every track) for every analyzer that is on: what a person asks for on one application.
func (s *Service) DispatchAsset(ctx context.Context, tenantID, assetID uuid.UUID, trigger domain.AnalysisTrigger) (int, error) {
	boms, err := s.store.LatestSBOMs(ctx, tenantID, &assetID)
	if err != nil {
		return 0, err
	}
	queued := 0
	var errs []error
	for _, b := range boms {
		n, err := s.DispatchSBOM(ctx, tenantID, b.ID, trigger)
		queued += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	return queued, errors.Join(errs...)
}

// ErrNoSuchAnalyzer is returned when an analyzer to run is not one the tenant has.
var ErrNoSuchAnalyzer = domain.ErrNoSuchAnalyzer

// DispatchAnalyzer queues the newest SBOM of every asset for one analyzer: what a person asks for after adding or changing an analyzer.
func (s *Service) DispatchAnalyzer(ctx context.Context, tenantID uuid.UUID, ref domain.AnalyzerRef, trigger domain.AnalysisTrigger) (int, error) {
	all, err := s.analyzers(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	var found *entry
	for i := range all {
		if all[i].ref == ref {
			found = &all[i]
		}
	}
	if found == nil {
		return 0, ErrNoSuchAnalyzer
	}
	if found.problem != "" || !found.enabled {
		return 0, nil
	}
	boms, err := s.store.LatestSBOMs(ctx, tenantID, nil)
	if err != nil {
		return 0, err
	}
	queued := 0
	var errs []error
	for _, b := range boms {
		ok, err := s.enqueueOne(ctx, tenantID, b.ID, ref, trigger)
		if err != nil {
			errs = append(errs, err)
		}
		if ok {
			queued++
		}
	}
	return queued, errors.Join(errs...)
}

// enqueueOne claims the analysis and queues its job. It reports false, with no error, when one is already pending or running.
func (s *Service) enqueueOne(ctx context.Context, tenantID, sbomID uuid.UUID, ref domain.AnalyzerRef, trigger domain.AnalysisTrigger) (bool, error) {
	rec := domain.SBOMAnalysis{TenantID: tenantID, SBOMID: sbomID, Analyzer: ref, Trigger: trigger}
	claimed, err := s.store.ClaimSBOMAnalysis(ctx, rec, s.cfg.StaleAfter)
	if err != nil || !claimed {
		return false, err
	}
	err = s.enqueuer.EnqueueAnalysis(ctx, jobs.AnalyzeSBOMArgs{
		TenantID: tenantID, SBOMID: sbomID, AnalyzerKind: ref.Kind, AnalyzerScope: ref.Scope, AnalyzerNamespace: ref.Namespace, AnalyzerName: ref.Name, Trigger: string(trigger),
	})
	if err != nil {
		// The claim must not hold the SBOM for an hour for a job that was never queued.
		rec.State, rec.Error, rec.Trigger = domain.AnalysisFailed, "could not be queued: "+err.Error(), trigger
		now := s.now()
		rec.FinishedAt = &now
		if serr := s.store.SaveSBOMAnalysis(ctx, rec); serr != nil {
			s.log.Warn("analysis: releasing a claim that could not be queued failed", "error", serr)
		}
		return false, fmt.Errorf("queueing the analysis by %s: %w", ref.Name, err)
	}
	return true, nil
}

// Sweep queues the analyses that are due, the way Dependency-Track's scheduled task does: it asks, oldest first, for the newest SBOMs that an analyzer has
// not analysed within its time, never more than MaxInFlight at once across tenants. It returns how many it queued.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	inflight, err := s.store.CountAnalysesInFlight(ctx, s.cfg.StaleAfter)
	if err != nil {
		return 0, err
	}
	budget := s.cfg.MaxInFlight - inflight
	if budget <= 0 {
		return 0, nil
	}
	tenants, err := s.store.ListTenantIDs(ctx)
	if err != nil {
		return 0, err
	}
	now := s.now()
	queued := 0
	for _, tenantID := range tenants {
		all, err := s.analyzers(ctx, tenantID)
		if err != nil {
			s.log.Warn("analysis sweep: listing the analyzers failed", "tenant", tenantID, "error", err)
			continue
		}
		for _, e := range usable(all) {
			if budget <= 0 {
				return queued, nil
			}
			due, err := s.store.ListDueSBOMs(ctx, tenantID, e.ref, s.completedBefore(e, now), now.Add(-s.cfg.FailedRetryAfter), budget)
			if err != nil {
				s.log.Warn("analysis sweep: finding the SBOMs that are due failed", "tenant", tenantID, "analyzer", e.ref.Name, "error", err)
				continue
			}
			for _, id := range due {
				ok, err := s.enqueueOne(ctx, tenantID, id, e.ref, domain.TriggerScheduled)
				if err != nil {
					s.log.Warn("analysis sweep: queueing failed", "tenant", tenantID, "analyzer", e.ref.Name, "error", err)
					break
				}
				if ok {
					queued++
					budget--
				}
			}
		}
	}
	return queued, nil
}

// completedBefore is the time before which a completed analysis is due again. An analyzer with a schedule is due when the schedule has fired
// since; any other, when the analysis is older than MaxAge. A schedule was read when the resource was accepted, so it parses.
func (s *Service) completedBefore(e entry, now time.Time) time.Time {
	if e.sbom != nil && e.sbom.Schedule != "" {
		if sched, err := cron.Parse(e.sbom.Schedule); err == nil {
			if prev := sched.Prev(now); !prev.IsZero() {
				return prev
			}
			return now.Add(-s.cfg.MaxAge)
		}
	}
	return now.Add(-s.cfg.MaxAge)
}

// Run is one analysis: the body of the River job. attempt starts at 1.
func (s *Service) Run(ctx context.Context, args jobs.AnalyzeSBOMArgs, attempt, maxAttempts int) error {
	ref := args.Ref()
	rec := domain.SBOMAnalysis{TenantID: args.TenantID, SBOMID: args.SBOMID, Analyzer: ref, Trigger: domain.AnalysisTrigger(args.Trigger), Attempts: attempt}
	settle := func(state domain.AnalysisState, why string) error {
		now := s.now()
		rec.State, rec.Error, rec.FinishedAt = state, why, &now
		return s.save(ctx, rec)
	}

	all, err := s.analyzers(ctx, args.TenantID)
	if err != nil {
		return err // the store is down: try again
	}
	var found *entry
	for i := range all {
		if all[i].ref == ref {
			found = &all[i]
		}
	}
	switch {
	case found == nil:
		return settle(domain.AnalysisCancelled, "the analyzer no longer exists")
	case found.problem != "":
		return settle(domain.AnalysisNotApplicable, "the analyzer's resource was refused: "+found.problem)
	case !found.enabled:
		return settle(domain.AnalysisNotApplicable, "the analyzer is switched off")
	}

	sbom, comps, err := s.store.GetSBOMByID(ctx, args.TenantID, args.SBOMID)
	if err != nil {
		if isNotFound(err) {
			return settle(domain.AnalysisCancelled, "the SBOM no longer exists")
		}
		return err
	}
	// Only the newest SBOM of an asset and track is analysed: the findings of an older one would reopen what the newer one dropped.
	newest, err := s.store.LatestSBOMs(ctx, args.TenantID, &sbom.AssetID)
	if err != nil {
		return err
	}
	for _, b := range newest {
		if b.Track == sbom.Track && b.ID != sbom.ID {
			return settle(domain.AnalysisCancelled, "a newer SBOM of the same application replaced it")
		}
	}
	src, err := s.sourceRun(ctx, sbom)
	if err != nil {
		if isNotFound(err) || errors.Is(err, errNoSourceRun) {
			return settle(domain.AnalysisCancelled, "the upload that stored this SBOM is no longer recorded, so its findings have nowhere to go")
		}
		return err
	}

	started := s.now()
	rec.State, rec.StartedAt, rec.Components, rec.Error, rec.FinishedAt = domain.AnalysisRunning, &started, len(comps), "", nil
	if err := s.save(ctx, rec); err != nil {
		return err
	}

	findings, callErr := s.call(ctx, *found, sbom, comps)
	if callErr != nil {
		return s.failed(ctx, rec, args, attempt, maxAttempts, started, "analyzer", callErr)
	}
	rec.Findings = len(findings)

	res, run, mergeErr := s.merge(ctx, src, sbom, ref, findings)
	if mergeErr != nil {
		return s.failed(ctx, rec, args, attempt, maxAttempts, started, "merge", mergeErr)
	}
	rec.Created, rec.Closed = res.Stats.Created, res.Stats.Closed
	finished := s.now()
	rec.State, rec.FinishedAt = domain.AnalysisCompleted, &finished
	if err := s.save(ctx, rec); err != nil {
		return err
	}
	msg := fmt.Sprintf("Analysed %d components: %d %s, %d new, %d no longer reported", rec.Components, rec.Findings, plural(rec.Findings, "finding", "findings"), rec.Created, rec.Closed)
	detail := map[string]string{
		"sbom": args.SBOMID.String(), "trigger": args.Trigger, "components": fmt.Sprint(rec.Components), "findings": fmt.Sprint(rec.Findings),
		"created": fmt.Sprint(rec.Created), "closed": fmt.Sprint(rec.Closed), "run": run.ID.String(), "attempt": fmt.Sprintf("%d of %d", attempt, maxAttempts),
	}
	if res.Reason == "close_held" {
		msg += "; a close of findings is held for confirmation"
		detail["close_held"] = "true"
	}
	s.event(ctx, args.TenantID, ref, "succeeded", msg, detail, finished.Sub(started), "")
	return nil
}

var errNoSourceRun = errors.New("the SBOM has no ingest run")

// sourceRun is the ingest run that stored the SBOM: where the findings of its analysis belong (source, application, context).
func (s *Service) sourceRun(ctx context.Context, sbom *domain.SBOM) (*domain.IngestRun, error) {
	if sbom.IngestRunID == uuid.Nil {
		return nil, errNoSourceRun
	}
	return s.store.GetIngestRun(ctx, sbom.TenantID, sbom.IngestRunID)
}

// failed records a failure and returns it for the job to retry. Nothing is closed. When it is the last attempt the tenant is told.
func (s *Service) failed(ctx context.Context, rec domain.SBOMAnalysis, args jobs.AnalyzeSBOMArgs, attempt, maxAttempts int, started time.Time, stage string, cause error) error {
	state := domain.AnalysisFailed
	if errors.Is(cause, context.DeadlineExceeded) || status.Code(cause) == codes.DeadlineExceeded {
		state = domain.AnalysisTimedOut
	}
	finished := s.now()
	last := attempt >= maxAttempts
	rec.State, rec.Error, rec.FinishedAt = state, cause.Error(), &finished
	if !last {
		// River retries this job after a backoff. Until then the row stays claimed (pending, with the error), so a person or the
		// sweep cannot claim it again and run a second merge of the same SBOM and analyzer beside the retry (docs/51 step 2.3).
		// A worker that dies leaves it stale after an hour, which frees it as before.
		rec.State, rec.FinishedAt = domain.AnalysisPending, nil
	}
	if err := s.save(ctx, rec); err != nil {
		s.log.Warn("analysis: recording a failure failed", "error", err)
	}
	msg := fmt.Sprintf("%s failed on attempt %d of %d: %s", map[string]string{"analyzer": "The analyzer", "merge": "Merging its findings"}[stage], attempt, maxAttempts, cause)
	if state == domain.AnalysisTimedOut {
		msg = fmt.Sprintf("The analyzer did not answer in time on attempt %d of %d: %s", attempt, maxAttempts, cause)
	}
	if last {
		msg += ". It will not be retried; its findings are kept as they were"
	} else {
		msg += ". It will be retried; its findings are kept as they were"
	}
	s.event(ctx, args.TenantID, args.Ref(), "failed", msg, map[string]string{
		"sbom": args.SBOMID.String(), "trigger": args.Trigger, "stage": stage, "state": string(state), "attempt": fmt.Sprintf("%d of %d", attempt, maxAttempts),
	}, finished.Sub(started), "")
	if last {
		s.notifyFailure(ctx, args, cause)
	}
	return cause
}

func (s *Service) save(ctx context.Context, rec domain.SBOMAnalysis) error {
	return s.store.SaveSBOMAnalysis(ctx, rec)
}

func (s *Service) event(ctx context.Context, tenantID uuid.UUID, ref domain.AnalyzerRef, outcome, msg string, detail map[string]string, took time.Duration, actor string) {
	err := s.store.RecordAnalyzerEvent(ctx, tenantID, domain.AnalyzerEvent{
		ID: domain.NewID(), Kind: ref.Kind, Scope: ref.Scope, Namespace: ref.Namespace, Name: ref.Name, Event: "analysis", Outcome: outcome,
		Message: msg, Detail: detail, Duration: took, Actor: actor, CreatedAt: s.now(),
	})
	if err != nil {
		s.log.Warn("analysis: recording an event failed", "analyzer", ref.Name, "error", err)
	}
}

// notifyFailure tells the tenant that an analyzer gave up on an SBOM (Dependency-Track's ANALYZER_ERROR).
func (s *Service) notifyFailure(ctx context.Context, args jobs.AnalyzeSBOMArgs, cause error) {
	n, ok := s.store.(interface {
		CreateNotification(ctx context.Context, tenantID uuid.UUID, n *domain.Notification) error
	})
	if !ok {
		return
	}
	err := n.CreateNotification(ctx, args.TenantID, &domain.Notification{
		ID: domain.NewID(), TenantID: args.TenantID, Kind: domain.NotifyAnalyzerError,
		Title:     fmt.Sprintf("Analyzer %s failed on an SBOM", args.AnalyzerName),
		Body:      fmt.Sprintf("It was tried %d times and gave up: %s. Its findings were kept. Test it on the Analyzers tab.", jobs.AnalysisMaxAttempts, cause),
		Link:      "/ingestion",
		CreatedAt: s.now(),
	})
	if err != nil {
		s.log.Warn("analysis: creating the notification failed", "error", err)
	}
}

// call asks the analyzer for the findings of the components.
func (s *Service) call(ctx context.Context, e entry, sbom *domain.SBOM, comps []domain.SBOMComponent) ([]domain.RawFinding, error) {
	if e.sbom != nil {
		if s.advisories == nil {
			return nil, errors.New("this server has no advisory data to match against")
		}
		return matcher.New(s.advisories).MatchComponentsWith(ctx, comps, matcher.Options{DirectOnly: e.sbom.Rules.MatchDirectOnly})
	}
	spec := e.external
	target := spec.Target(e.object.Namespace)
	cl, err := s.dial(target, spec.UseTLS())
	if err != nil {
		return nil, err
	}
	defer func() { _ = cl.Close() }()
	cctx, cancel := context.WithTimeout(ctx, spec.Timeout())
	defer cancel()
	found, err := cl.Analyze(cctx, sbom.ID.String(), sbom.AssetID.String(), comps, nil)
	if err != nil {
		return nil, err
	}
	return attach(found, comps), nil
}

// attach fills in the package of each finding from the component it names. An analyzer answers with the reference it was given; the
// finding needs the package's purl, name and installed version, which are what tell two findings of one vulnerability apart.
func attach(found []domain.RawFinding, comps []domain.SBOMComponent) []domain.RawFinding {
	byRef := make(map[string]domain.SBOMComponent, len(comps))
	byPurl := make(map[string]domain.SBOMComponent, len(comps))
	for _, c := range comps {
		if c.Ref != "" {
			byRef[c.Ref] = c
		}
		if c.Purl != "" {
			byPurl[c.Purl] = c
		}
	}
	for i := range found {
		pkg := found[i].Location.Package
		if pkg == nil {
			continue
		}
		c, ok := byRef[pkg.Purl]
		if !ok {
			c, ok = byPurl[pkg.Purl]
		}
		if !ok {
			continue
		}
		pkg.Purl, pkg.ComponentName, pkg.InstalledVersion = c.Purl, c.Name, c.Version
	}
	return found
}

// merge turns the answer into an ingest run and merges it. The analyzer is the scanner, so the close that follows reaches only what this
// analyzer reported before.
func (s *Service) merge(ctx context.Context, src *domain.IngestRun, sbom *domain.SBOM, ref domain.AnalyzerRef, found []domain.RawFinding) (ingest.Result, *domain.IngestRun, error) {
	now := s.now()
	family := ref.Family()
	run := &domain.IngestRun{
		ID: domain.NewID(), TenantID: sbom.TenantID, ScanSourceID: src.ScanSourceID, ApplicationID: src.ApplicationID, AssetID: sbom.AssetID, Track: sbom.Track,
		ScannerFamily: family, Format: "sbom-analysis", Context: src.Context, Status: domain.RunMerging, ScanStarted: now, ScanFinished: now, CreatedAt: now,
	}
	if err := s.store.CreateIngestRun(ctx, run); err != nil {
		return ingest.Result{}, run, err
	}
	res, err := s.merger.Process(ctx, ingest.ProcessParams{
		Run: run, Parser: findingsParser{family: family, findings: found}, ScannerOverride: family, ScanFinished: now,
		Open: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("")), nil },
	})
	if err != nil {
		s.merger.Finish(ctx, run, domain.RunFailed, err.Error())
		return res, run, err
	}
	run.Stats = res.Stats
	s.merger.Finish(ctx, run, res.Status, res.Reason)
	return res, run, nil
}

// findingsParser hands the merge the findings an analyzer returned, as if they had been read from a report.
type findingsParser struct {
	family   string
	findings []domain.RawFinding
}

func (p findingsParser) Descriptor() integrations.Descriptor {
	return integrations.Descriptor{ID: p.family, Name: p.family, Version: "1", Description: "findings returned by an analyzer"}
}

func (findingsParser) Detect([]byte, string, string) int { return 0 }

func (p findingsParser) Parse(context.Context, io.Reader, domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		for _, f := range p.findings {
			if !yield(f, nil) {
				return
			}
		}
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }
