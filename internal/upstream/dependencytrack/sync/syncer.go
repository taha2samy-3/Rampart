package sync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/normalize"
	"rampart/internal/parsers/dependencytrack"
	"rampart/internal/store"
	dtclient "rampart/internal/upstream/dependencytrack/client"
)

// Store defines the database operations needed by the Syncer.
type Store interface {
	store.DTrackStore
	LookupAsset(ctx context.Context, tenantID uuid.UUID, assetType domain.AssetType, key string) (*domain.Asset, error)
	CreateAsset(ctx context.Context, asset *domain.Asset) error
	GetScanSourceIngestionPolicy(ctx context.Context, tenantID, sourceID uuid.UUID) (*domain.IngestionPolicy, error)
}

// DecisionStore is what importing Dependency-Track's analysis needs (docs/23 DT5). The PostgreSQL store has it; a
// store without it imports no decisions.
type DecisionStore interface {
	GetFindingsByKeys(ctx context.Context, tenantID uuid.UUID, keys []string) (map[string]*domain.Finding, error)
	RecordDTrackDecision(ctx context.Context, tenantID uuid.UUID, d store.DTrackDecision) (bool, error)
	RecordFindingEvents(ctx context.Context, tenantID uuid.UUID, events []*domain.FindingEvent) error
	UpdateFindingTriage(ctx context.Context, tenantID uuid.UUID, f *domain.Finding, expectedVersion int, events []*domain.FindingEvent) error
}

// MergeEngine is the ingest merge engine (ingest.Engine). Its close step always runs with the mass-close guard,
// as an uploaded report's does (D22).
type MergeEngine interface {
	MergeBatchWithOptions(ctx context.Context, scope ingest.CloseScope, runID, appID uuid.UUID, records []ingest.StagedRecord, opts ingest.MergeOptions) (ingest.MergeOutcome, error)
	CloseScopeStepWithGuard(ctx context.Context, scope ingest.CloseScope, currentRunID uuid.UUID, enableMassCloseGuard bool) (ingest.CloseScopeResult, error)
}

// RunStore records a sync as an ingest run: occurrences reference their run, the Runs page lists it, and a held
// close is tied to it (D22, D92). A store without it (tests) records no run.
type RunStore interface {
	CreateIngestRun(ctx context.Context, run *domain.IngestRun) error
	UpdateIngestRun(ctx context.Context, run *domain.IngestRun) error
	CreateHeldClose(ctx context.Context, tenantID uuid.UUID, hc *domain.HeldClose) error
}

// Enqueuer schedules a project sync as a job (the dtrack-sync River queue, D92). Without one the syncer runs the
// trailing sync in the same call, which only tests use.
type Enqueuer interface {
	EnqueueDTrackProject(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string, delay time.Duration) error
}

// Settle bounds (docs/23 DT1): a job waits up to SettleWait for DT's analysis, then is rescheduled; once the
// BOM import is older than SettleBound the findings are read anyway and the run is marked unsettled.
const (
	SettleWait  = 2 * time.Minute
	SettleRetry = 5 * time.Minute
	SettleBound = 30 * time.Minute
)

// ErrCountMismatch fails a run whose parsed findings differ from Dependency-Track's X-Total-Count: closing what
// was not read would close live findings (docs/10 §5, docs/23 DT2).
var ErrCountMismatch = errors.New("dependency-track: the findings read differ from X-Total-Count; nothing was closed")

// Config is the per-source configuration (the ScanSource's connector and dependencyTrack block).
type Config struct {
	Connector string
	Spec      domain.DTrackSourceSpec
}

// Syncer orchestrates project sync (Flow B/C) and portfolio reconciliation (Flow C) (docs/10 §2, docs/21 §4.5).
type Syncer struct {
	client   *dtclient.Client
	store    Store
	engine   MergeEngine
	mapping  *MappingEngine
	settle   *SettleChecker
	parser   *dependencytrack.Parser
	logger   *slog.Logger
	cfg      Config
	nameRe   *regexp.Regexp
	enqueuer Enqueuer
	now      func() time.Time
}

// NewSyncer creates a new Syncer.
func NewSyncer(client *dtclient.Client, st Store, engine MergeEngine, mapping *MappingEngine) *Syncer {
	return &Syncer{
		client:  client,
		store:   st,
		engine:  engine,
		mapping: mapping,
		settle:  NewSettleChecker(client, 10*time.Second, SettleWait),
		parser:  dependencytrack.NewParser(),
		logger:  slog.Default().With("component", "dtrack_syncer"),
		cfg:     Config{Connector: "dtrack"},
		now:     time.Now,
	}
}

// Configure sets the source configuration and the job enqueuer.
func (s *Syncer) Configure(cfg Config, enq Enqueuer) {
	if cfg.Connector == "" {
		cfg.Connector = "dtrack"
	}
	s.cfg = cfg
	s.nameRe = nil
	if cfg.Spec.Projects.NameRegex != "" {
		s.nameRe = regexp.MustCompile(cfg.Spec.Projects.NameRegex) // validated by ParseDTrackSourceSpec
	}
	s.enqueuer = enq
}

// SetSettleChecker overrides the SettleChecker (e.g. for testing).
func (s *Syncer) SetSettleChecker(sc *SettleChecker) {
	s.settle = sc
}

// AssetKey is the one key of a Dependency-Track project (D10, docs/23 DT3): the connector and the project name. The
// version is a track when versions: all; with versions: latest only the latest version is read, on track main.
// Keying by scan source made two findings for one DT finding when two sources read one DT; keying by project UUID
// made every release a new asset, so findings of the previous release were never closed.
func AssetKey(connector, projectName string) string {
	return "dtrack://" + connector + "/" + projectName
}

func (s *Syncer) track(p dtclient.Project) string {
	if s.cfg.Spec.Versions() == "all" && p.Version != "" {
		return p.Version
	}
	return "main"
}

const whyNotLatest = "not the latest version"

// ImplicitLatest says whether p is the version to read for its name when versions is "latest" and Dependency-Track
// flags none of the versions as latest. DT only sets the flag when a BOM is uploaded with isLatest=true, and most
// pipelines never do: every project was then "not the latest version" and the whole portfolio was skipped, even a
// project with one version. Without a flag the version with the newest BOM wins (ties by UUID, so the pick is
// stable); when DT does name one, that one wins and this is false.
func ImplicitLatest(p dtclient.Project, sameName []dtclient.Project) bool {
	var best *dtclient.Project
	for i := range sameName {
		q := &sameName[i]
		if q.Name != p.Name {
			continue
		}
		if q.IsLatest != nil && *q.IsLatest {
			return false
		}
		if best == nil || q.LastBomImport > best.LastBomImport || (q.LastBomImport == best.LastBomImport && q.UUID < best.UUID) {
			best = q
		}
	}
	return best != nil && best.UUID == p.UUID
}

// wantedIn is wanted, with the implicit latest version of a name no version of which DT flags.
func (s *Syncer) wantedIn(ctx context.Context, p dtclient.Project) (bool, string) {
	ok, why := s.wanted(p)
	if ok || why != whyNotLatest {
		return ok, why
	}
	versions, err := s.client.ListProjectsByName(ctx, p.Name)
	if err != nil {
		s.logger.Warn("dependency-track: could not list the versions of a project", "project", p.Name, "error", err)
		return ok, why
	}
	if ImplicitLatest(p, versions) {
		p.IsLatest = ptr(true)
		return s.wanted(p)
	}
	return ok, why
}

func ptr[T any](v T) *T { return &v }

// wanted applies the project filters of the ScanSource. The reason is recorded on an unwanted project.
func (s *Syncer) wanted(p dtclient.Project) (bool, string) {
	spec := s.cfg.Spec
	if spec.OnlyActive() && !p.Active {
		return false, "inactive"
	}
	if spec.Versions() == "latest" {
		if p.IsLatest == nil {
			return false, "Dependency-Track does not say which version is the latest (before 4.12): use versions: all"
		}
		if !*p.IsLatest {
			return false, whyNotLatest
		}
	}
	if s.nameRe != nil && !s.nameRe.MatchString(p.Name) {
		return false, "name does not match nameRegex"
	}
	if len(spec.Projects.Classifiers) > 0 {
		ok := false
		for _, c := range spec.Projects.Classifiers {
			if strings.EqualFold(c, p.Classifier) {
				ok = true
			}
		}
		if !ok {
			return false, "classifier not selected"
		}
	}
	if len(spec.Projects.Tags) > 0 {
		ok := false
		for _, want := range spec.Projects.Tags {
			for _, t := range p.Tags {
				if strings.EqualFold(want, t.Name) {
					ok = true
				}
			}
		}
		if !ok {
			return false, "no selected tag"
		}
	}
	return true, ""
}

// trailing runs the sync the debounce owes: as a job when there is a queue, else in this call.
func (s *Syncer) trailing(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string, delay time.Duration) {
	if s.enqueuer != nil {
		if err := s.enqueuer.EnqueueDTrackProject(ctx, tenantID, sourceID, projectUUID, delay); err != nil {
			s.logger.Error("enqueuing the trailing dtrack sync failed", "project", projectUUID, "error", err)
		}
		return
	}
	_ = s.SyncProject(ctx, tenantID, sourceID, projectUUID)
}

func (s *Syncer) complete(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string, syncErr error) error {
	hasTrailing, err := s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, syncErr)
	if hasTrailing {
		s.trailing(ctx, tenantID, sourceID, projectUUID, 0)
	}
	if syncErr != nil {
		return syncErr
	}
	return err
}

// SyncProject executes a single project sync run.
func (s *Syncer) SyncProject(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string) error {
	proj, err := s.client.GetProject(ctx, projectUUID)
	if errors.Is(err, dtclient.ErrNotFound) {
		s.logger.Warn("dependency-track project not found", "project", projectUUID)
		_, _ = s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, nil)
		return nil
	}
	if err != nil {
		return s.complete(ctx, tenantID, sourceID, projectUUID, err)
	}

	props, _ := s.client.GetProjectProperties(ctx, projectUUID)
	res := s.mapping.Resolve(ctx, tenantID, *proj, props)
	if ok, why := s.wantedIn(ctx, *proj); !ok {
		res = MappingResult{UnmappedReason: "filtered out: " + why}
	}

	var lastBom *time.Time
	if proj.LastBomImport > 0 {
		t := time.UnixMilli(proj.LastBomImport).UTC()
		lastBom = &t
	}
	if err := s.store.UpsertDTrackProject(ctx, domain.DTrackProjectRecord{
		TenantID: tenantID, SourceID: sourceID, ProjectUUID: projectUUID, Name: proj.Name, Version: proj.Version,
		Purl: proj.Purl, Active: proj.Active, LastBomImport: lastBom, ApplicationID: res.ApplicationID,
		MappingRule: res.MatchedRule, UnmappedReason: res.UnmappedReason,
	}); err != nil {
		s.logger.Error("failed upserting dtrack project record", "project", projectUUID, "error", err)
	}
	if res.ApplicationID == nil {
		// Unmapped or filtered out: recorded with the reason, no finding is merged (docs/21 §4.5).
		return s.complete(ctx, tenantID, sourceID, projectUUID, nil)
	}

	// Settle (docs/23 DT1): wait for DT's analysis of the latest BOM; if it has not ended, reschedule this job
	// instead of holding a worker, until the import is older than the bound.
	settled, body, total, err := s.settle.CheckSettled(ctx, projectUUID, proj.LastBomImport)
	if err != nil {
		return s.complete(ctx, tenantID, sourceID, projectUUID, err)
	}
	if !settled {
		age := time.Duration(0)
		if lastBom != nil {
			age = s.now().Sub(*lastBom)
		}
		if age < SettleBound && s.enqueuer != nil {
			_, _ = s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, nil)
			s.trailing(ctx, tenantID, sourceID, projectUUID, SettleRetry)
			return nil
		}
		s.logger.Warn("dependency-track analysis did not settle within the bound; reading anyway", "project", projectUUID)
		if body, total, err = s.settle.ReadAnyway(ctx, projectUUID, s.cfg.Spec.IncludeSuppressed()); err != nil {
			return s.complete(ctx, tenantID, sourceID, projectUUID, err)
		}
	}

	// The asset: one per connector and project name (D10, DT3).
	assetKey := AssetKey(s.cfg.Connector, proj.Name)
	asset, err := s.store.LookupAsset(ctx, tenantID, domain.AssetSBOMProject, assetKey)
	if errors.Is(err, store.ErrNotFound) {
		asset = &domain.Asset{
			ID: domain.NewID(), TenantID: tenantID, ApplicationID: res.ApplicationID, Type: domain.AssetSBOMProject,
			Key: assetKey, DisplayName: proj.Name, Active: proj.Active, FirstSeen: s.now().UTC(), LastSeen: s.now().UTC(),
		}
		if err := s.store.CreateAsset(ctx, asset); err != nil {
			return s.complete(ctx, tenantID, sourceID, projectUUID, err)
		}
	} else if err != nil {
		return s.complete(ctx, tenantID, sourceID, projectUUID, err)
	}
	track := s.track(*proj)

	var staged []ingest.StagedRecord
	decisions := map[string]*domain.VEXStatement{}
	parsed := 0
	now := s.now().UTC()
	for raw, parseErr := range s.parser.Parse(ctx, bytes.NewReader(body), domain.ParseContext{}) {
		parsed++
		if parseErr != nil {
			// A record that cannot be read fails the run: the close step must not treat it as gone (docs/10 §5).
			return s.complete(ctx, tenantID, sourceID, projectUUID, fmt.Errorf("dependency-track finding %d: %w", parsed, parseErr))
		}
		fp := normalize.ComputeFingerprint(normalize.FingerprintParams{
			TenantID: tenantID, AssetID: asset.ID, ApplicationID: *res.ApplicationID, Track: track,
			Scope: normalize.ScopeAsset, Family: "dependency-track", Category: raw.Category, RuleID: raw.RuleID, RawFinding: raw,
		})
		staged = append(staged, ingest.StagedRecord{
			ScannerFamily: "dependency-track", FindingKey: fp.FindingKey, LineageKey: fp.LineageKey,
			Category: raw.Category, RuleID: raw.RuleID, Title: raw.Title, Description: raw.Description,
			ToolSeverity: raw.ToolSeverity, Severity: raw.Severity, Location: raw.Location, CWEs: raw.CWEs,
			VulnID: raw.RuleID, CVSSVector: raw.CVSSVector,
			ContentHash: normalize.ComputeContentHash(raw.Title, raw.Description, raw.ToolSeverity, raw.CVSSVector, "", raw.Location.PrimaryPath()),
			SeenAt:      now, RawPayload: raw.RawPayload,
		})
		if raw.VEX != nil && s.cfg.Spec.TriageMode() == "import" {
			decisions[fp.FindingKey] = raw.VEX
		}
	}
	if total >= 0 && parsed != total {
		return s.complete(ctx, tenantID, sourceID, projectUUID, fmt.Errorf("%w (read %d, stated %d)", ErrCountMismatch, parsed, total))
	}

	runID := domain.NewID()
	run := &domain.IngestRun{
		ID: runID, TenantID: tenantID, ScanSourceID: sourceID, ApplicationID: *res.ApplicationID, AssetID: asset.ID,
		Track: track, ScannerFamily: "dependency-track", Format: "dependency-track/api", Status: domain.RunMerging,
		ScanStarted: now, ScanFinished: now, CreatedAt: now,
	}
	runs, _ := s.store.(RunStore)
	if runs != nil {
		if err := runs.CreateIngestRun(ctx, run); err != nil {
			return s.complete(ctx, tenantID, sourceID, projectUUID, err)
		}
	}
	finish := func(status domain.IngestRunStatus, reason string, err error) error {
		if runs != nil {
			t := s.now().UTC()
			run.Status, run.Error, run.FinishedAt = status, reason, &t
			if err != nil {
				run.Error = err.Error()
			}
			_ = runs.UpdateIngestRun(ctx, run)
		}
		return s.complete(ctx, tenantID, sourceID, projectUUID, err)
	}
	run.Stats.Parsed = parsed

	scope := ingest.CloseScope{TenantID: tenantID, ScanSourceID: sourceID, ScannerFamily: "dependency-track", AssetID: asset.ID, Track: track}
	if s.engine != nil && len(staged) > 0 {
		out, err := s.engine.MergeBatchWithOptions(ctx, scope, runID, *res.ApplicationID, staged, ingest.MergeOptions{FieldMerge: "scanner"})
		if err != nil {
			return finish(domain.RunFailed, "", err)
		}
		run.Stats.Created, run.Stats.Updated, run.Stats.Untouched, run.Stats.Reactivated = out.Created, out.Updated, out.Untouched, out.Reactivated
	}
	status, reason := domain.RunCompleted, ""
	if !settled {
		// Past the bound: read anyway, and say so on the run (docs/23 DT1).
		status, reason = domain.RunCompletedWithErrors, "analysis_unsettled"
	}
	if s.engine != nil {
		closed, err := s.engine.CloseScopeStepWithGuard(ctx, scope, runID, true)
		if err != nil {
			return finish(domain.RunFailed, "", err)
		}
		run.Stats.Closed = closed.Closed
		if closed.HeldForConfirmation && runs != nil {
			status, reason = domain.RunCompletedWithErrors, "close_held"
			_ = runs.CreateHeldClose(ctx, tenantID, &domain.HeldClose{
				ID: domain.NewID(), TenantID: tenantID, IngestRunID: runID, Scope: scope, FindingIDs: closed.HeldFindingIDs, CreatedAt: now,
			})
		}
	}
	if len(decisions) > 0 {
		s.importDecisions(ctx, tenantID, sourceID, decisions, now)
	}
	return finish(status, reason, nil)
}

// importDecisions records the analysis Dependency-Track carries (docs/23 DT5). A decision is a request until a
// person acts on it: it is stored as pending and written to the finding's timeline once, when it first appears or
// changes. With trustUpstreamDecisions it is applied as a triage decision instead, except a risk acceptance, which
// needs an owner and an expiry and so always stays a request (docs/01 C5).
func (s *Syncer) importDecisions(ctx context.Context, tenantID, sourceID uuid.UUID, decisions map[string]*domain.VEXStatement, now time.Time) {
	ds, ok := s.store.(DecisionStore)
	if !ok {
		return
	}
	keys := make([]string, 0, len(decisions))
	for k := range decisions {
		keys = append(keys, k)
	}
	findings, err := ds.GetFindingsByKeys(ctx, tenantID, keys)
	if err != nil {
		s.logger.Warn("reading findings for dtrack decisions failed", "error", err)
		return
	}
	actor := "dependency-track:" + s.cfg.Connector
	for key, vex := range decisions {
		f := findings[key]
		if f == nil || vex.State == "" || f.State == vex.State {
			continue
		}
		trusted := s.cfg.Spec.TriageSync.TrustUpstreamDecisions && vex.State != domain.StateRiskAccepted
		changed, err := ds.RecordDTrackDecision(ctx, tenantID, store.DTrackDecision{
			FindingID: f.ID, SourceID: sourceID, State: string(vex.State), Justification: vex.Justification, Detail: vex.Impact,
		})
		if err != nil || !changed {
			continue
		}
		if trusted {
			events, terr := domain.ApplyTriage(f, domain.TriageRequest{State: vex.State, Justification: vex.Justification,
				ImpactStatement: vex.Impact, Note: "Decided in Dependency-Track; this source trusts its decisions"}, actor, now)
			if terr == nil && ds.UpdateFindingTriage(ctx, tenantID, f, f.Version, events) == nil {
				_, _ = ds.RecordDTrackDecision(ctx, tenantID, store.DTrackDecision{
					FindingID: f.ID, SourceID: sourceID, State: string(vex.State), Justification: vex.Justification, Detail: vex.Impact, Applied: true,
				})
				continue
			}
		}
		_ = ds.RecordFindingEvents(ctx, tenantID, []*domain.FindingEvent{{
			ID: domain.NewID(), FindingID: f.ID, At: now, Actor: actor, Type: "upstream_decision",
			Note: fmt.Sprintf("Dependency-Track says %s%s. Not applied: decide it here, or set trustUpstreamDecisions on the source.",
				vex.State, func() string {
					if vex.Justification != "" {
						return " (" + vex.Justification + ")"
					}
					return ""
				}()),
		}})
	}
}

// SyncPortfolio pages through the projects, records each with its mapping, and enqueues a sync of every mapped
// project that passes the filters (docs/10 §2 Flow C).
func (s *Syncer) SyncPortfolio(ctx context.Context, tenantID, sourceID uuid.UUID) error {
	pageSize := 100
	for page := 1; ; page++ {
		projects, total, err := s.client.ListProjects(ctx, page, pageSize, s.cfg.Spec.OnlyActive())
		if err != nil {
			return fmt.Errorf("listing projects on page %d: %w", page, err)
		}
		for _, proj := range projects {
			props, _ := s.client.GetProjectProperties(ctx, proj.UUID)
			res := s.mapping.Resolve(ctx, tenantID, proj, props)
			if ok, why := s.wantedIn(ctx, proj); !ok {
				res = MappingResult{UnmappedReason: "filtered out: " + why}
			}
			var lastBom *time.Time
			if proj.LastBomImport > 0 {
				t := time.UnixMilli(proj.LastBomImport).UTC()
				lastBom = &t
			}
			_ = s.store.UpsertDTrackProject(ctx, domain.DTrackProjectRecord{
				TenantID: tenantID, SourceID: sourceID, ProjectUUID: proj.UUID, Name: proj.Name, Version: proj.Version,
				Purl: proj.Purl, Active: proj.Active, LastBomImport: lastBom, ApplicationID: res.ApplicationID,
				MappingRule: res.MatchedRule, UnmappedReason: res.UnmappedReason,
			})
			if res.ApplicationID == nil {
				continue
			}
			shouldStart, err := s.store.EnqueueDTrackSync(ctx, tenantID, sourceID, proj.UUID)
			if err == nil && shouldStart {
				s.trailing(ctx, tenantID, sourceID, proj.UUID, 0)
			}
		}
		if len(projects) == 0 || page*pageSize >= total {
			return nil
		}
	}
}
