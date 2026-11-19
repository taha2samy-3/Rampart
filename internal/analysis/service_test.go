package analysis_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"rampart/internal/analysis"
	"rampart/internal/analyzer/matcher"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/jobs"
	"rampart/internal/objectstore"
)

const (
	externalSpec = `{"service":{"name":"sonatype","namespace":"rampart-system","port":9090}}`
	matcherSpec  = `{"engine":"hybrid"}`
)

// queue records the jobs that would have gone to River.
type queue struct {
	mu   sync.Mutex
	jobs []jobs.AnalyzeSBOMArgs
	err  error
}

func (q *queue) EnqueueAnalysis(_ context.Context, a jobs.AnalyzeSBOMArgs) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return q.err
	}
	q.jobs = append(q.jobs, a)
	return nil
}

func (q *queue) names() []string {
	var out []string
	for _, j := range q.jobs {
		out = append(out, j.AnalyzerName)
	}
	return out
}

// fake is an analyzer service: it answers with what the test says, or fails.
type fake struct {
	findings func(comps []domain.SBOMComponent) []domain.RawFinding
	err      error
	calls    int
	target   string
	secure   bool
	got      []domain.SBOMComponent
}

func (f *fake) Analyze(_ context.Context, _, _ string, comps []domain.SBOMComponent, _ map[string]string) ([]domain.RawFinding, error) {
	f.calls++
	f.got = comps
	if f.err != nil {
		return nil, f.err
	}
	if f.findings == nil {
		return nil, nil
	}
	return f.findings(comps), nil
}
func (f *fake) Close() error { return nil }

type env struct {
	t      *testing.T
	ctx    context.Context
	st     *ingest.MemoryStore
	q      *queue
	svc    *analysis.Service
	tenant uuid.UUID
	asset  uuid.UUID
	app    uuid.UUID
	source uuid.UUID
	sbom   *domain.SBOM
	now    time.Time
	svcs   map[string]*fake // by analyzer service name
}

func newEnv(t *testing.T, cfg analysis.Config) *env {
	t.Helper()
	st := ingest.NewMemoryStore()
	proc := ingest.NewProcessor(st, nil, objectstore.NewMemory(), nil)
	e := &env{t: t, ctx: context.Background(), st: st, q: &queue{}, tenant: domain.NewID(), asset: domain.NewID(), app: domain.NewID(), source: domain.NewID(),
		now: time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC), svcs: map[string]*fake{}}
	e.svc = analysis.New(st, proc, e.q, st, cfg, nil)
	e.svc.SetClock(func() time.Time { return e.now })
	e.svc.SetDialer(func(target string, secure bool) (analysis.ExternalAnalyzer, error) {
		name := strings.SplitN(target, ".", 2)[0]
		f, ok := e.svcs[name]
		if !ok {
			return nil, fmt.Errorf("nothing at %s", target)
		}
		f.target, f.secure = target, secure
		return f, nil
	})
	e.sbom = e.storeSBOM(e.asset, "main", 3)
	return e
}

// storeSBOM stores an SBOM of n components, as an upload would: with the ingest run that carries its source and application.
func (e *env) storeSBOM(asset uuid.UUID, track string, n int) *domain.SBOM {
	run := &domain.IngestRun{ID: domain.NewID(), TenantID: e.tenant, ScanSourceID: e.source, ApplicationID: e.app, AssetID: asset, Track: track,
		Format: "cyclonedx", Status: domain.RunCompleted, CreatedAt: e.now, Context: domain.UploadContext{Repository: "github.com/acme/shop", Branch: track}}
	if err := e.st.CreateIngestRun(e.ctx, run); err != nil {
		e.t.Fatal(err)
	}
	b := &domain.SBOM{ID: domain.NewID(), TenantID: e.tenant, AssetID: asset, IngestRunID: run.ID, Track: track, Format: "cyclonedx", CreatedAt: e.now, ComponentCount: n}
	var comps []domain.SBOMComponent
	for i := 0; i < n; i++ {
		comps = append(comps, component(b.ID, i))
	}
	if err := e.st.SaveSBOM(e.ctx, b, comps); err != nil {
		e.t.Fatal(err)
	}
	return b
}

func component(sbom uuid.UUID, i int) domain.SBOMComponent {
	name := fmt.Sprintf("lib%d", i)
	return domain.SBOMComponent{SBOMID: sbom, Ref: "ref-" + name, Name: name, Version: "1.0.0", Purl: "pkg:npm/" + name + "@1.0.0", PurlBase: "pkg:npm/" + name, Direct: i == 0}
}

// finds answers for each component with a finding named after it.
func finds(ids ...string) func([]domain.SBOMComponent) []domain.RawFinding {
	return func(comps []domain.SBOMComponent) []domain.RawFinding {
		var out []domain.RawFinding
		for i, id := range ids {
			c := comps[i%len(comps)]
			out = append(out, domain.RawFinding{
				RuleID: id, Title: id + " in " + c.Name, ToolSeverity: "HIGH", Severity: domain.SeverityHigh, VulnIDs: []string{id}, Category: domain.CategorySCA,
				// as the real analyzer does: the reference it was given, not the purl
				Location: domain.Location{Package: &domain.PackageLocation{Purl: c.Ref, FixedVersion: "1.0.1"}},
			})
		}
		return out
	}
}

func (e *env) analyzer(name, spec string) domain.AnalyzerRef {
	e.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, name, []byte(spec), "")
	e.svcs[name] = &fake{}
	return domain.AnalyzerRef{Kind: "external", Scope: "cluster", Name: name}
}

func spec(name string) string {
	return fmt.Sprintf(`{"service":{"name":%q,"namespace":"rampart-system","port":9090}}`, name)
}

func (e *env) run(ref domain.AnalyzerRef, attempt int) error {
	e.t.Helper()
	// the same claim the queue makes before it hands out the job
	if _, err := e.st.ClaimSBOMAnalysis(e.ctx, domain.SBOMAnalysis{TenantID: e.tenant, SBOMID: e.sbom.ID, Analyzer: ref, Trigger: domain.TriggerManual}, time.Hour); err != nil {
		e.t.Fatal(err)
	}
	return e.svc.Run(e.ctx, jobs.AnalyzeSBOMArgs{TenantID: e.tenant, SBOMID: e.sbom.ID, AnalyzerKind: ref.Kind, AnalyzerScope: ref.Scope, AnalyzerNamespace: ref.Namespace,
		AnalyzerName: ref.Name, Trigger: "manual"}, attempt, jobs.AnalysisMaxAttempts)
}

func (e *env) state(ref domain.AnalyzerRef) domain.SBOMAnalysis {
	e.t.Helper()
	a, err := e.st.GetSBOMAnalysis(e.ctx, e.tenant, e.sbom.ID, ref)
	if err != nil {
		e.t.Fatalf("no analysis record: %v", err)
	}
	return *a
}

// stateOf maps finding keys to their state for one scanner family.
func (e *env) states(family string) map[string]domain.FindingState {
	e.t.Helper()
	fs, err := e.st.ListFindings(e.ctx, e.tenant)
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

func (e *env) lastEvent(ref domain.AnalyzerRef) domain.AnalyzerEvent {
	e.t.Helper()
	evs, err := e.st.ListAnalyzerEvents(e.ctx, e.tenant, ref.Kind, ref.Scope, ref.Namespace, ref.Name, 10)
	if err != nil || len(evs) == 0 {
		e.t.Fatalf("no event: %v", err)
	}
	return evs[0]
}

// --- dispatch ---

func TestAnUploadQueuesEveryAnalyzerThatIsOn(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	e.analyzer("sonatype", spec("sonatype"))
	e.st.SaveClusterAnalyzer(domain.AnalyzerKindSBOM, "default", []byte(matcherSpec), "")
	e.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, "off", []byte(`{"enabled":false,"service":{"name":"off","port":1}}`), "")
	e.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, "broken", []byte(`{"protocol":"http","endpoint":"a:1"}`), "spec.protocol: http is not supported")

	e.svc.SBOMStored(e.ctx, e.tenant, e.sbom.ID)

	got := e.q.names()
	if len(got) != 2 || !(got[0] == "sonatype" && got[1] == "default" || got[0] == "default" && got[1] == "sonatype") {
		t.Fatalf("queued %v, want the external analyzer and the matcher, not the switched-off or the refused one", got)
	}
	for _, j := range e.q.jobs {
		if j.Trigger != "upload" || j.SBOMID != e.sbom.ID || j.TenantID != e.tenant {
			t.Errorf("job %+v", j)
		}
	}
	a, err := e.st.GetSBOMAnalysis(e.ctx, e.tenant, e.sbom.ID, domain.AnalyzerRef{Kind: "external", Scope: "cluster", Name: "sonatype"})
	if err != nil || a.State != domain.AnalysisPending {
		t.Fatalf("a queued analysis is pending: %+v %v", a, err)
	}
}

func TestAnAnalysisAlreadyQueuedIsNotQueuedTwice(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	e.analyzer("sonatype", spec("sonatype"))
	if n, err := e.svc.DispatchSBOM(e.ctx, e.tenant, e.sbom.ID, domain.TriggerUpload); n != 1 || err != nil {
		t.Fatalf("first: %d %v", n, err)
	}
	if n, err := e.svc.DispatchSBOM(e.ctx, e.tenant, e.sbom.ID, domain.TriggerManual); n != 0 || err != nil {
		t.Fatalf("a second request while one is pending queued %d (%v)", n, err)
	}
	if len(e.q.jobs) != 1 {
		t.Fatalf("jobs = %d", len(e.q.jobs))
	}
}

func TestAFinishedAnalysisCanBeAskedForAgain(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	ref := e.analyzer("sonatype", spec("sonatype"))
	if err := e.run(ref, 1); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.svc.DispatchSBOM(e.ctx, e.tenant, e.sbom.ID, domain.TriggerManual); n != 1 {
		t.Fatalf("a person asking again after it finished queued %d, want 1", n)
	}
}

func TestAClaimThatCouldNotBeQueuedIsReleased(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	ref := e.analyzer("sonatype", spec("sonatype"))
	e.q.err = errors.New("river is down")
	n, err := e.svc.DispatchSBOM(e.ctx, e.tenant, e.sbom.ID, domain.TriggerUpload)
	if n != 0 || err == nil || !strings.Contains(err.Error(), "river is down") {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if a := e.state(ref); a.State != domain.AnalysisFailed || !strings.Contains(a.Error, "could not be queued") {
		t.Fatalf("the claim was left holding the SBOM: %+v", a)
	}
	e.q.err = nil
	if n, _ := e.svc.DispatchSBOM(e.ctx, e.tenant, e.sbom.ID, domain.TriggerManual); n != 1 {
		t.Fatalf("after the queue is back, queued %d", n)
	}
}

func TestDispatchAnalyzerAndAssetReachTheNewestSBOMs(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	ref := e.analyzer("sonatype", spec("sonatype"))
	e.analyzer("other", spec("other"))
	otherAsset := domain.NewID()
	second := e.storeSBOM(otherAsset, "main", 1)

	if n, err := e.svc.DispatchAnalyzer(e.ctx, e.tenant, ref, domain.TriggerManual); n != 2 || err != nil {
		t.Fatalf("one analyzer, every asset: %d %v", n, err)
	}
	if n, err := e.svc.DispatchAsset(e.ctx, e.tenant, otherAsset, domain.TriggerManual); n != 1 || err != nil { // "other" for it; sonatype is pending
		t.Fatalf("one asset, every analyzer that is free: %d %v", n, err)
	}
	for _, j := range e.q.jobs {
		if j.AnalyzerName == "other" && j.SBOMID != second.ID {
			t.Errorf("asset dispatch reached %v", j.SBOMID)
		}
	}
	if _, err := e.svc.DispatchAnalyzer(e.ctx, e.tenant, domain.AnalyzerRef{Kind: "external", Scope: "cluster", Name: "nope"}, domain.TriggerManual); !errors.Is(err, analysis.ErrNoSuchAnalyzer) {
		t.Fatalf("an analyzer that does not exist: %v", err)
	}
}

// --- running ---

func TestAnExternalAnalyzersFindingsAreMergedUnderItsOwnFamily(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	ref := e.analyzer("sonatype", spec("sonatype"))
	e.svcs["sonatype"].findings = finds("CVE-2024-0001", "CVE-2024-0002")

	if err := e.run(ref, 1); err != nil {
		t.Fatalf("Run: %v", err)
	}
	f := e.svcs["sonatype"]
	if f.calls != 1 || len(f.got) != 3 {
		t.Fatalf("one call with the whole SBOM: calls=%d components=%d", f.calls, len(f.got))
	}
	if f.target != "sonatype.rampart-system.svc.cluster.local:9090" || f.secure {
		t.Errorf("dialled %q secure=%v", f.target, f.secure)
	}
	st := e.states("analyzer:sonatype")
	if len(st) != 2 || st["CVE-2024-0001"] != domain.StateOpen || st["CVE-2024-0002"] != domain.StateOpen {
		t.Fatalf("findings of the analyzer: %v", st)
	}
	a := e.state(ref)
	if a.State != domain.AnalysisCompleted || a.Components != 3 || a.Findings != 2 || a.Created != 2 || a.Closed != 0 || a.Attempts != 1 || a.FinishedAt == nil {
		t.Fatalf("record: %+v", a)
	}
	ev := e.lastEvent(ref)
	if ev.Event != "analysis" || ev.Outcome != "succeeded" || !strings.Contains(ev.Message, "Analysed 3 components: 2 findings, 2 new, 0 no longer reported") || ev.Detail["sbom"] != e.sbom.ID.String() {
		t.Fatalf("event: %+v", ev)
	}
	// The run that merged it is an ingest run of the analyzer, in the SBOM's source and application.
	runs, _ := e.st.ListIngestRuns(e.ctx, e.tenant, 10, nil)
	var found *domain.IngestRun
	for _, r := range runs {
		if r.Format == "sbom-analysis" {
			found = r
		}
	}
	if found == nil || found.ScannerFamily != "analyzer:sonatype" || found.ScanSourceID != e.source || found.ApplicationID != e.app || found.Status != domain.RunCompleted || found.Context.Repository != "github.com/acme/shop" {
		t.Fatalf("analysis run: %+v", found)
	}
}

func TestTheFindingKnowsThePackageTheAnalyzerNamedByReference(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	ref := e.analyzer("sonatype", spec("sonatype"))
	e.svcs["sonatype"].findings = finds("CVE-2024-0001")
	if err := e.run(ref, 1); err != nil {
		t.Fatal(err)
	}
	fs, _ := e.st.ListFindings(e.ctx, e.tenant)
	_, occs, err := e.st.GetFinding(e.ctx, e.tenant, fs[0].ID)
	if err != nil || len(occs) != 1 {
		t.Fatalf("occurrences: %d %v", len(occs), err)
	}
	pkg := occs[0].Location.Package
	if pkg == nil || pkg.Purl != "pkg:npm/lib0@1.0.0" || pkg.ComponentName != "lib0" || pkg.InstalledVersion != "1.0.0" || pkg.FixedVersion != "1.0.1" {
		t.Fatalf("package: %+v", pkg)
	}
	if occs[0].ScannerFamily != "analyzer:sonatype" {
		t.Errorf("family %q", occs[0].ScannerFamily)
	}
}

func TestAnAnalyzerThatFailsClosesNothingAndSaysSo(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	ref := e.analyzer("sonatype", spec("sonatype"))
	f := e.svcs["sonatype"]
	f.findings = finds("CVE-2024-0001", "CVE-2024-0002")
	if err := e.run(ref, 1); err != nil {
		t.Fatal(err)
	}

	// It is down on the next analysis, which is asked for again and again.
	f.err = errors.New("rpc error: code = Unavailable desc = connection refused")
	e.now = e.now.Add(time.Hour)
	err := e.run(ref, 1)
	if err == nil || !strings.Contains(err.Error(), "Unavailable") {
		t.Fatalf("a failed analysis returns the error, for the queue to retry: %v", err)
	}
	st := e.states("analyzer:sonatype")
	if st["CVE-2024-0001"] != domain.StateOpen || st["CVE-2024-0002"] != domain.StateOpen {
		t.Fatalf("a failing analyzer closed findings: %v", st)
	}
	a := e.state(ref)
	if a.State != domain.AnalysisFailed || !strings.Contains(a.Error, "connection refused") || a.Attempts != 1 {
		t.Fatalf("record: %+v", a)
	}
	ev := e.lastEvent(ref)
	if ev.Outcome != "failed" || !strings.Contains(ev.Message, "failed on attempt 1 of 5") || !strings.Contains(ev.Message, "It will be retried; its findings are kept") {
		t.Fatalf("event: %+v", ev)
	}

	// And the analysis that follows, with a working analyzer, reports one of the two: only now is the other closed.
	f.err = nil
	f.findings = finds("CVE-2024-0001")
	if err := e.run(ref, 1); err != nil {
		t.Fatal(err)
	}
	st = e.states("analyzer:sonatype")
	if st["CVE-2024-0001"] != domain.StateOpen || st["CVE-2024-0002"] != domain.StateFixed {
		t.Fatalf("after an answer: %v", st)
	}
	if a := e.state(ref); a.Closed != 1 || a.Created != 0 {
		t.Fatalf("record: %+v", a)
	}
}

func TestAnAnalyzerThatTimesOutIsTimedOut(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	ref := e.analyzer("sonatype", spec("sonatype"))
	e.svcs["sonatype"].err = fmt.Errorf("analyzer rpc Analyze failed: %w", context.DeadlineExceeded)
	if err := e.run(ref, 2); err == nil {
		t.Fatal("no error")
	}
	if a := e.state(ref); a.State != domain.AnalysisTimedOut || a.Attempts != 2 {
		t.Fatalf("%+v", a)
	}
	if ev := e.lastEvent(ref); !strings.Contains(ev.Message, "did not answer in time on attempt 2 of 5") {
		t.Fatalf("event: %+v", ev)
	}
}

func TestOneAnalyzerNeverClosesWhatAnotherReported(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	a := e.analyzer("alpha", spec("alpha"))
	b := e.analyzer("beta", spec("beta"))
	e.svcs["alpha"].findings = finds("CVE-A")
	e.svcs["beta"].findings = finds("CVE-B")
	if err := e.run(a, 1); err != nil {
		t.Fatal(err)
	}
	if err := e.run(b, 1); err != nil {
		t.Fatal(err)
	}

	// alpha now reports nothing: its finding closes, beta's stays.
	e.svcs["alpha"].findings = finds()
	if err := e.run(a, 1); err != nil {
		t.Fatal(err)
	}
	if st := e.states("analyzer:alpha"); st["CVE-A"] != domain.StateFixed {
		t.Fatalf("alpha's own finding: %v", st)
	}
	if st := e.states("analyzer:beta"); st["CVE-B"] != domain.StateOpen {
		t.Fatalf("beta's finding was closed by alpha: %v", st)
	}
}

func TestAnAnalyzerThatSuddenlyAnswersNothingDoesNotWipeTheScope(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	ref := e.analyzer("sonatype", spec("sonatype"))
	var ids []string
	for i := 0; i < 30; i++ {
		ids = append(ids, fmt.Sprintf("CVE-2024-%04d", i))
	}
	e.svcs["sonatype"].findings = finds(ids...)
	if err := e.run(ref, 1); err != nil {
		t.Fatal(err)
	}
	// It answers, without an error, with an empty list: a feed outage on its side looks like this. The mass-close guard holds it.
	e.svcs["sonatype"].findings = finds()
	if err := e.run(ref, 1); err != nil {
		t.Fatal(err)
	}
	open := 0
	for _, s := range e.states("analyzer:sonatype") {
		if s == domain.StateOpen {
			open++
		}
	}
	if open != 30 {
		t.Fatalf("%d of 30 findings are still open; a close of that size should be held", open)
	}
	if ev := e.lastEvent(ref); !strings.Contains(ev.Message, "held for confirmation") || ev.Detail["close_held"] != "true" {
		t.Fatalf("event: %+v", ev)
	}
}

func TestAnAnalyzerThatIsGoneOrOffOrRefusedIsNotCalled(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	gone := domain.AnalyzerRef{Kind: "external", Scope: "cluster", Name: "gone"}
	e.svcs["gone"] = &fake{}
	if err := e.run(gone, 1); err != nil {
		t.Fatal(err)
	}
	if a := e.state(gone); a.State != domain.AnalysisCancelled || !strings.Contains(a.Error, "no longer exists") {
		t.Fatalf("gone: %+v", a)
	}

	e.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, "off", []byte(`{"enabled":false,"service":{"name":"off","port":1}}`), "")
	e.svcs["off"] = &fake{}
	off := domain.AnalyzerRef{Kind: "external", Scope: "cluster", Name: "off"}
	if err := e.run(off, 1); err != nil {
		t.Fatal(err)
	}
	if a := e.state(off); a.State != domain.AnalysisNotApplicable || !strings.Contains(a.Error, "switched off") {
		t.Fatalf("off: %+v", a)
	}

	e.st.SaveClusterAnalyzer(domain.AnalyzerKindExternal, "bad", []byte(`{}`), "spec has no address")
	e.svcs["bad"] = &fake{}
	bad := domain.AnalyzerRef{Kind: "external", Scope: "cluster", Name: "bad"}
	if err := e.run(bad, 1); err != nil {
		t.Fatal(err)
	}
	if a := e.state(bad); a.State != domain.AnalysisNotApplicable || !strings.Contains(a.Error, "spec has no address") {
		t.Fatalf("bad: %+v", a)
	}
	for name, f := range e.svcs {
		if f.calls != 0 {
			t.Errorf("%s was called", name)
		}
	}
}

func TestAnSBOMThatWasReplacedIsCancelledNotAnalysed(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	ref := e.analyzer("sonatype", spec("sonatype"))
	old := e.sbom
	e.sbom = e.storeSBOM(e.asset, "main", 2) // a newer upload of the same asset and track
	_ = old
	e.svcs["sonatype"].findings = finds("CVE-1")
	// Ask for the old one by id: the memory store keeps only the newest, as PostgreSQL's LatestSBOMs would pick it.
	err := e.svc.Run(e.ctx, jobs.AnalyzeSBOMArgs{TenantID: e.tenant, SBOMID: old.ID, AnalyzerKind: ref.Kind, AnalyzerScope: ref.Scope, AnalyzerName: ref.Name, Trigger: "scheduled"}, 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if e.svcs["sonatype"].calls != 0 {
		t.Fatal("an SBOM that was replaced was analysed")
	}
	a, err := e.st.GetSBOMAnalysis(e.ctx, e.tenant, old.ID, ref)
	if err != nil || a.State != domain.AnalysisCancelled {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestTheLastFailureTellsTheTenant(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	ref := e.analyzer("sonatype", spec("sonatype"))
	e.svcs["sonatype"].err = errors.New("connection refused")
	if err := e.run(ref, jobs.AnalysisMaxAttempts-1); err == nil {
		t.Fatal("no error")
	}
	if n := e.st.NotificationCount(e.tenant, domain.NotifyAnalyzerError); n != 0 {
		t.Fatalf("a failure that will be retried told the tenant (%d)", n)
	}
	if err := e.run(ref, jobs.AnalysisMaxAttempts); err == nil {
		t.Fatal("no error")
	}
	if n := e.st.NotificationCount(e.tenant, domain.NotifyAnalyzerError); n != 1 {
		t.Fatalf("notifications = %d, want 1 after the last attempt", n)
	}
	if ev := e.lastEvent(ref); !strings.Contains(ev.Message, "It will not be retried; its findings are kept as they were") {
		t.Fatalf("event: %+v", ev)
	}
}

func TestATenantsAnalyzerIsReachedAtItsNamespace(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	e.st.SaveTenantAnalyzer(e.tenant, domain.AnalyzerKindExternal, "acme", "mine", []byte(`{"service":{"name":"mine","port":7000}}`), "")
	e.svcs["mine"] = &fake{findings: finds("CVE-T")}
	ref := domain.AnalyzerRef{Kind: "external", Scope: "tenant", Namespace: "acme", Name: "mine"}
	if err := e.run(ref, 1); err != nil {
		t.Fatal(err)
	}
	if e.svcs["mine"].target != "mine.acme.svc.cluster.local:7000" {
		t.Errorf("target %q", e.svcs["mine"].target)
	}
	if st := e.states("analyzer:acme/mine"); st["CVE-T"] != domain.StateOpen {
		t.Fatalf("family of a tenant's analyzer carries its namespace: %v", st)
	}
}

// --- the built-in matcher ---

func TestTheBuiltInMatcherFindsWhatTheAdvisoriesName(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	e.st.SaveClusterAnalyzer(domain.AnalyzerKindSBOM, "default", []byte(matcherSpec), "")
	e.st.SetAdvisories([]matcher.Advisory{
		{ID: "CVE-2024-1111", PurlBase: "pkg:npm/lib0", Introduced: "0", Fixed: "1.0.1", Summary: "lib0 flaw", CVSSScore: 9.8, RangeType: "SEMVER"},
		{ID: "CVE-2024-2222", PurlBase: "pkg:npm/lib1", Introduced: "0", Fixed: "1.0.1", Summary: "lib1 flaw", CVSSScore: 5.0, RangeType: "SEMVER"},
		{ID: "CVE-2024-3333", PurlBase: "pkg:npm/lib2", Introduced: "2.0.0", Fixed: "3.0.0", RangeType: "SEMVER"}, // 1.0.0 is below it
		{ID: "CVE-2024-4444", PurlBase: "pkg:npm/lib2", Versions: []string{"1.0.0"}, RangeType: "VERSIONS", Summary: "exact"},
	})
	ref := domain.AnalyzerRef{Kind: "sbom", Scope: "cluster", Name: "default"}
	if err := e.run(ref, 1); err != nil {
		t.Fatal(err)
	}
	st := e.states("analyzer:default")
	if len(st) != 3 || st["CVE-2024-1111"] != domain.StateOpen || st["CVE-2024-2222"] != domain.StateOpen || st["CVE-2024-4444"] != domain.StateOpen {
		t.Fatalf("findings: %v", st)
	}
	if _, ok := st["CVE-2024-3333"]; ok {
		t.Fatal("a version below the range was reported")
	}
}

func TestTheMatcherCanLookAtDirectDependenciesOnly(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	e.st.SaveClusterAnalyzer(domain.AnalyzerKindSBOM, "direct", []byte(`{"rules":{"matchDirectOnly":true}}`), "")
	e.st.SetAdvisories([]matcher.Advisory{
		{ID: "CVE-D", PurlBase: "pkg:npm/lib0", Introduced: "0", Fixed: "2", RangeType: "SEMVER"}, // lib0 is the direct one
		{ID: "CVE-T", PurlBase: "pkg:npm/lib1", Introduced: "0", Fixed: "2", RangeType: "SEMVER"},
	})
	ref := domain.AnalyzerRef{Kind: "sbom", Scope: "cluster", Name: "direct"}
	if err := e.run(ref, 1); err != nil {
		t.Fatal(err)
	}
	st := e.states("analyzer:direct")
	if len(st) != 1 || st["CVE-D"] != domain.StateOpen {
		t.Fatalf("findings: %v", st)
	}
	if a := e.state(ref); a.Components != 3 || a.Findings != 1 {
		t.Fatalf("record: %+v", a)
	}
}

// --- the sweep ---

func TestTheSweepQueuesWhatIsDueOldestFirstWithinTheBudget(t *testing.T) {
	e := newEnv(t, analysis.Config{MaxInFlight: 2, MaxAge: 24 * time.Hour, FailedRetryAfter: time.Hour})
	ref := e.analyzer("sonatype", spec("sonatype"))
	// four assets, each with an SBOM; the analyzer last finished on them at different times
	boms := []*domain.SBOM{e.sbom}
	for i := 0; i < 3; i++ {
		boms = append(boms, e.storeSBOM(domain.NewID(), "main", 1))
	}
	ago := func(h int) *time.Time { t := e.now.Add(-time.Duration(h) * time.Hour); return &t }
	set := func(b *domain.SBOM, state domain.AnalysisState, finished *time.Time) {
		if _, err := e.st.ClaimSBOMAnalysis(e.ctx, domain.SBOMAnalysis{TenantID: e.tenant, SBOMID: b.ID, Analyzer: ref, Trigger: domain.TriggerUpload}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := e.st.SaveSBOMAnalysis(e.ctx, domain.SBOMAnalysis{TenantID: e.tenant, SBOMID: b.ID, Analyzer: ref, State: state, FinishedAt: finished}); err != nil {
			t.Fatal(err)
		}
	}
	set(boms[0], domain.AnalysisCompleted, ago(30)) // older than a day: due, the oldest
	set(boms[1], domain.AnalysisCompleted, ago(26)) // due
	set(boms[2], domain.AnalysisCompleted, ago(2))  // fresh
	// boms[3] was never analysed: due, and first
	n, err := e.svc.Sweep(e.ctx)
	if err != nil || n != 2 {
		t.Fatalf("queued %d (%v), want the budget of 2", n, err)
	}
	var queued []uuid.UUID
	for _, j := range e.q.jobs {
		queued = append(queued, j.SBOMID)
		if j.Trigger != "scheduled" {
			t.Errorf("trigger %q", j.Trigger)
		}
	}
	if queued[0] != boms[3].ID || queued[1] != boms[0].ID {
		t.Fatalf("queued %v, want the never-analysed first and then the oldest", queued)
	}
	// The two that are queued are in flight: with a budget of 2, the next sweep queues nothing until they finish.
	if n, _ := e.svc.Sweep(e.ctx); n != 0 {
		t.Fatalf("a full queue was added to: %d", n)
	}
}

func TestTheSweepWaitsBeforeTryingAFailedAnalysisAgain(t *testing.T) {
	e := newEnv(t, analysis.Config{FailedRetryAfter: time.Hour})
	ref := e.analyzer("sonatype", spec("sonatype"))
	e.svcs["sonatype"].err = errors.New("down")
	if err := e.run(ref, jobs.AnalysisMaxAttempts); err == nil {
		t.Fatal("no error")
	}
	if n, _ := e.svc.Sweep(e.ctx); n != 0 {
		t.Fatalf("a failure from a moment ago was queued again (%d)", n)
	}
	e.now = e.now.Add(2 * time.Hour)
	// the clock of the record is the store's own time, so move it by asking with the cutoff in the past
	e.svc.SetClock(func() time.Time { return e.now.Add(48 * time.Hour) })
	if n, _ := e.svc.Sweep(e.ctx); n != 1 {
		t.Fatalf("a failure from long ago was not tried again (%d)", n)
	}
}

func TestTheSweepFollowsTheMatchersCronSchedule(t *testing.T) {
	e := newEnv(t, analysis.Config{})
	e.st.SaveClusterAnalyzer(domain.AnalyzerKindSBOM, "nightly", []byte(`{"schedule":"0 3 * * *"}`), "")
	ref := domain.AnalyzerRef{Kind: "sbom", Scope: "cluster", Name: "nightly"}
	if _, err := e.st.ClaimSBOMAnalysis(e.ctx, domain.SBOMAnalysis{TenantID: e.tenant, SBOMID: e.sbom.ID, Analyzer: ref, Trigger: domain.TriggerUpload}, time.Hour); err != nil {
		t.Fatal(err)
	}
	finished := time.Date(2026, 11, 19, 4, 0, 0, 0, time.UTC) // after the 03:00 of the 19th
	if err := e.st.SaveSBOMAnalysis(e.ctx, domain.SBOMAnalysis{TenantID: e.tenant, SBOMID: e.sbom.ID, Analyzer: ref, State: domain.AnalysisCompleted, FinishedAt: &finished}); err != nil {
		t.Fatal(err)
	}
	at := func(s string) {
		e.svc.SetClock(func() time.Time { v, _ := time.Parse("2006-01-02 15:04", s); return v })
	}

	at("2026-11-19 23:00") // the schedule has not fired since 04:00
	if n, _ := e.svc.Sweep(e.ctx); n != 0 {
		t.Fatalf("queued %d before the schedule fired", n)
	}
	at("2026-11-20 03:30") // it fired at 03:00 on the 20th
	if n, _ := e.svc.Sweep(e.ctx); n != 1 {
		t.Fatalf("queued %d after the schedule fired, want 1", n)
	}
}
