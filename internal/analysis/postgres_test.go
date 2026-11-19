package analysis_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"rampart/internal/analysis"
	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/jobs"
	"rampart/internal/objectstore"
	"rampart/internal/store"
)

// pgEnv is the analysis on a real PostgreSQL: the merge, the close and the record of each analysis go through the real queries, with row-level
// security on. It needs RAMPART_TEST_POSTGRES_URL (the owner URL of a throwaway database) and is skipped without it.
type pgEnv struct {
	t      *testing.T
	ctx    context.Context
	app    *store.PostgresStore
	sys    *store.PostgresStore
	q      *queue
	svc    *analysis.Service
	tenant uuid.UUID
	asset  uuid.UUID
	sbom   uuid.UUID
	svcs   map[string]*fake
}

func withCreds(raw, user, password string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	u.User = url.UserPassword(user, password)
	return u.String()
}

func newPGEnv(t *testing.T) *pgEnv {
	t.Helper()
	direct := os.Getenv("RAMPART_TEST_POSTGRES_URL")
	if direct == "" {
		t.Skip("RAMPART_TEST_POSTGRES_URL is not set; skipping the PostgreSQL analysis test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	if err := store.AutoMigrate(ctx, direct); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	cfg, err := pgx.ParseConfig(direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for role, pw := range map[string]string{"rampart_app": "rampart_app_pw", "rampart_system": "rampart_system_pw"} {
		if _, err := conn.Exec(ctx, fmt.Sprintf("ALTER ROLE %s LOGIN PASSWORD '%s'", role, pw)); err != nil {
			t.Fatal(err)
		}
	}
	_ = conn.Close(ctx)
	appURL := withCreds(direct, "rampart_app", "rampart_app_pw")
	app, err := store.ConnectPostgres(ctx, appURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	sys, err := store.ConnectPostgres(ctx, withCreds(appURL, "rampart_system", "rampart_system_pw"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sys.Close)

	e := &pgEnv{t: t, ctx: ctx, app: app, sys: sys, q: &queue{}, tenant: uuid.New(), asset: uuid.New(), svcs: map[string]*fake{}}
	now := time.Now().UTC()
	if err := sys.CreateTenant(ctx, &domain.Tenant{ID: e.tenant, Slug: "an-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	application := &domain.Application{ID: uuid.New(), TenantID: e.tenant, Slug: "shop", Name: "Shop", BusinessCriticality: "high", Lifecycle: "production", CreatedAt: now}
	if err := app.CreateApplication(ctx, application); err != nil {
		t.Fatal(err)
	}
	asset := &domain.Asset{ID: e.asset, TenantID: e.tenant, ApplicationID: &application.ID, Type: domain.AssetRepository, Key: "github.com/acme/shop", DisplayName: "shop", Active: true, FirstSeen: now, LastSeen: now}
	if err := app.CreateAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	source, err := app.EnsureScanSource(ctx, e.tenant, "")
	if err != nil {
		t.Fatal(err)
	}
	run := &domain.IngestRun{ID: uuid.New(), TenantID: e.tenant, ScanSourceID: source, ApplicationID: application.ID, AssetID: asset.ID, Track: "main", ScannerFamily: "cyclonedx",
		Format: "cyclonedx", Status: domain.RunCompleted, CreatedAt: now, Context: domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main"}}
	if err := app.CreateIngestRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	e.sbom = uuid.New()
	var comps []domain.SBOMComponent
	for i := 0; i < 3; i++ {
		c := component(e.sbom, i)
		c.TenantID = e.tenant
		comps = append(comps, c)
	}
	if err := app.SaveSBOM(ctx, &domain.SBOM{ID: e.sbom, TenantID: e.tenant, AssetID: asset.ID, IngestRunID: run.ID, Track: "main", Format: "cyclonedx", SpecVersion: "1.5", ComponentCount: 3, CreatedAt: now}, comps); err != nil {
		t.Fatal(err)
	}

	proc := ingest.NewProcessor(app, nil, objectstore.NewMemory(), nil)
	e.svc = analysis.New(app, proc, e.q, app, analysis.Config{}, nil)
	e.svc.SetDialer(func(target string, secure bool) (analysis.ExternalAnalyzer, error) {
		f, ok := e.svcs[strings.SplitN(target, ".", 2)[0]]
		if !ok {
			return nil, fmt.Errorf("nothing at %s", target)
		}
		return f, nil
	})
	return e
}

func (e *pgEnv) analyzer(name string) domain.AnalyzerRef {
	e.t.Helper()
	// The cluster's analyzers are global rows; a name no other test uses keeps this one apart.
	if err := e.sys.SaveClusterPolicy(e.ctx, domain.AnalyzerKindExternal, apply.PolicyObject{Name: name, Spec: []byte(spec(name)), Generation: 1}); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = e.sys.DeleteClusterPolicy(context.Background(), domain.AnalyzerKindExternal, name) })
	e.svcs[name] = &fake{}
	return domain.AnalyzerRef{Kind: "external", Scope: "cluster", Name: name}
}

func (e *pgEnv) run(ref domain.AnalyzerRef, attempt int) error {
	e.t.Helper()
	if _, err := e.app.ClaimSBOMAnalysis(e.ctx, domain.SBOMAnalysis{TenantID: e.tenant, SBOMID: e.sbom, Analyzer: ref, Trigger: domain.TriggerManual}, time.Hour); err != nil {
		e.t.Fatal(err)
	}
	return e.svc.Run(e.ctx, jobs.AnalyzeSBOMArgs{TenantID: e.tenant, SBOMID: e.sbom, AnalyzerKind: ref.Kind, AnalyzerScope: ref.Scope, AnalyzerName: ref.Name, Trigger: "manual"}, attempt, jobs.AnalysisMaxAttempts)
}

func (e *pgEnv) states(family string) map[string]domain.FindingState {
	e.t.Helper()
	fs, err := e.app.ListFindings(e.ctx, e.tenant)
	if err != nil {
		e.t.Fatal(err)
	}
	out := map[string]domain.FindingState{}
	for _, f := range fs {
		if f.RuleScannerFamily == family {
			out[f.RuleID] = f.State
		}
	}
	return out
}

// The whole of a Dependency-Track-like lifecycle on the real database: an answer creates findings under the analyzer, a failure closes nothing,
// a later answer closes only what it no longer reports, and another analyzer's findings are not touched by any of it.
func TestAnalysisLifecycle_OnPostgreSQL(t *testing.T) {
	e := newPGEnv(t)
	suffix := uuid.NewString()[:8]
	alpha, beta := e.analyzer("alpha-"+suffix), e.analyzer("beta-"+suffix)
	famA, famB := alpha.Family(), beta.Family()
	e.svcs[alpha.Name].findings = finds("CVE-A1", "CVE-A2")
	e.svcs[beta.Name].findings = finds("CVE-B1")

	if err := e.run(alpha, 1); err != nil {
		t.Fatalf("alpha: %v", err)
	}
	if err := e.run(beta, 1); err != nil {
		t.Fatalf("beta: %v", err)
	}
	if st := e.states(famA); len(st) != 2 || st["CVE-A1"] != domain.StateOpen || st["CVE-A2"] != domain.StateOpen {
		t.Fatalf("alpha's findings: %v", st)
	}
	if st := e.states(famB); len(st) != 1 || st["CVE-B1"] != domain.StateOpen {
		t.Fatalf("beta's findings: %v", st)
	}
	rec, err := e.app.GetSBOMAnalysis(e.ctx, e.tenant, e.sbom, alpha)
	if err != nil || rec.State != domain.AnalysisCompleted || rec.Components != 3 || rec.Findings != 2 || rec.Created != 2 || rec.FinishedAt == nil {
		t.Fatalf("record: %+v %v", rec, err)
	}
	evs, err := e.app.ListAnalyzerEvents(e.ctx, e.tenant, "external", "cluster", "", alpha.Name, 10)
	if err != nil || len(evs) != 1 || evs[0].Event != "analysis" || evs[0].Outcome != "succeeded" {
		t.Fatalf("events: %+v %v", evs, err)
	}
	// the finding names the package, the analyzer as the one that reported it
	fs, _ := e.app.ListFindings(e.ctx, e.tenant)
	for _, f := range fs {
		if f.RuleID != "CVE-A1" {
			continue
		}
		_, occs, err := e.app.GetFinding(e.ctx, e.tenant, f.ID)
		if err != nil || len(occs) != 1 || occs[0].ScannerFamily != famA || occs[0].Location.Package == nil || occs[0].Location.Package.Purl != "pkg:npm/lib0@1.0.0" || occs[0].Location.Package.InstalledVersion != "1.0.0" {
			t.Fatalf("occurrence: %+v %v", occs, err)
		}
	}
	// the run that merged it is listed with the others, for the analyzer
	runs, err := e.app.ListIngestRuns(e.ctx, e.tenant, 20, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range runs {
		if r.Format == "sbom-analysis" && r.ScannerFamily == famA && r.Status == domain.RunCompleted && r.Stats.Created == 2 {
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("analysis runs of alpha: %d of %d runs", seen, len(runs))
	}

	// alpha is down: nothing is closed, and the record and the event say why
	e.svcs[alpha.Name].err = errors.New("rpc error: code = Unavailable desc = connection refused")
	if err := e.run(alpha, 1); err == nil {
		t.Fatal("a failed analysis returned no error")
	}
	if st := e.states(famA); st["CVE-A1"] != domain.StateOpen || st["CVE-A2"] != domain.StateOpen {
		t.Fatalf("a failing analyzer closed findings on PostgreSQL: %v", st)
	}
	rec, _ = e.app.GetSBOMAnalysis(e.ctx, e.tenant, e.sbom, alpha)
	if rec.State != domain.AnalysisFailed || !strings.Contains(rec.Error, "connection refused") {
		t.Fatalf("record: %+v", rec)
	}

	// alpha answers again, with one finding fewer: only that one closes
	e.svcs[alpha.Name].err = nil
	e.svcs[alpha.Name].findings = finds("CVE-A1")
	if err := e.run(alpha, 1); err != nil {
		t.Fatal(err)
	}
	if st := e.states(famA); st["CVE-A1"] != domain.StateOpen || st["CVE-A2"] != domain.StateFixed {
		t.Fatalf("alpha after an answer: %v", st)
	}
	if st := e.states(famB); st["CVE-B1"] != domain.StateOpen {
		t.Fatalf("beta's finding was closed by alpha's analysis: %v", st)
	}
	rec, _ = e.app.GetSBOMAnalysis(e.ctx, e.tenant, e.sbom, alpha)
	if rec.State != domain.AnalysisCompleted || rec.Closed != 1 {
		t.Fatalf("record: %+v", rec)
	}

	// and the finding that came back is reopened, not duplicated
	e.svcs[alpha.Name].findings = finds("CVE-A1", "CVE-A2")
	if err := e.run(alpha, 1); err != nil {
		t.Fatal(err)
	}
	if st := e.states(famA); len(st) != 2 || st["CVE-A2"] != domain.StateOpen {
		t.Fatalf("a finding that came back: %v", st)
	}
}

func TestDispatchAndSweep_OnPostgreSQL(t *testing.T) {
	e := newPGEnv(t)
	ref := e.analyzer("sweep-" + uuid.NewString()[:8])

	// Cluster analyzers are global, so other tests' analyzers may be in this database too: look at this analyzer's jobs only.
	mine := func() []jobs.AnalyzeSBOMArgs {
		var out []jobs.AnalyzeSBOMArgs
		for _, j := range e.q.jobs {
			if j.TenantID == e.tenant && j.AnalyzerName == ref.Name {
				out = append(out, j)
			}
		}
		return out
	}
	if _, err := e.svc.DispatchSBOM(e.ctx, e.tenant, e.sbom, domain.TriggerUpload); err != nil || len(mine()) != 1 {
		t.Fatalf("dispatch: %d jobs of this analyzer, %v", len(mine()), err)
	}
	if _, err := e.svc.DispatchSBOM(e.ctx, e.tenant, e.sbom, domain.TriggerUpload); err != nil || len(mine()) != 1 {
		t.Fatalf("queued twice: %d jobs of this analyzer, %v", len(mine()), err)
	}
	// a worker finishes it; the sweep (as the system role, across tenants) leaves a fresh analysis alone
	e.svcs[ref.Name].findings = finds("CVE-S")
	if err := e.svc.Run(e.ctx, mine()[0], 1, jobs.AnalysisMaxAttempts); err != nil {
		t.Fatal(err)
	}
	proc := ingest.NewProcessor(e.app, nil, objectstore.NewMemory(), nil)
	sweeper := analysis.New(e.sys, proc, e.q, e.sys, analysis.Config{}, nil)
	before := len(mine())
	if _, err := sweeper.Sweep(e.ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(mine()) != before {
		t.Fatalf("the sweep queued an analysis that had just finished: %+v", mine()[before:])
	}
	// a day and a bit later it is due, and the sweep, which sees every tenant, queues it as a scheduled analysis
	later := analysis.New(e.sys, proc, e.q, e.sys, analysis.Config{}, nil)
	later.SetClock(func() time.Time { return time.Now().UTC().Add(25 * time.Hour) })
	if _, err := later.Sweep(e.ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	added := mine()[before:]
	if len(added) != 1 || added[0].SBOMID != e.sbom || added[0].Trigger != "scheduled" {
		t.Fatalf("the sweep did not queue the analysis that is due: %+v", added)
	}
}
