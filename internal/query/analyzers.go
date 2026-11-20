package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"rampart/internal/analyzer/client"
	"rampart/internal/auth"
	"rampart/internal/domain"
)

// analyzerTestTimeout bounds one test of an analyzer, whatever its spec asks: a test is an answer to "is it up", not a job.
const analyzerTestTimeout = 30 * time.Second

// AnalyzerProbe is what the test of an external analyzer calls; a test gives the API its own.
type AnalyzerProbe func(ctx context.Context, target string, secure bool) (client.ProbeResult, error)

// AnalysisDispatcher queues the analysis of SBOMs (internal/analysis.Service).
type AnalysisDispatcher interface {
	DispatchAnalyzer(ctx context.Context, tenantID uuid.UUID, ref domain.AnalyzerRef, trigger domain.AnalysisTrigger) (int, error)
	DispatchAsset(ctx context.Context, tenantID, assetID uuid.UUID, trigger domain.AnalysisTrigger) (int, error)
}

// SetAnalysisDispatcher lets a person ask for an analysis. Without one (analysis switched off) the two endpoints answer 409.
func (a *API) SetAnalysisDispatcher(d AnalysisDispatcher) { a.analysis = d }

// SetAnalysisLimits sets the limits on manual analyses: max in-flight analyses across the platform and per-application cooldown.
func (a *API) SetAnalysisLimits(maxInFlight int, manualCooldown time.Duration) {
	if maxInFlight > 0 {
		a.maxInFlight = maxInFlight
	}
	if manualCooldown > 0 {
		a.manualCooldown = manualCooldown
	}
}

// SetAnalyzerProbe replaces the call that tests an external analyzer (the default dials it over gRPC).
func (a *API) SetAnalyzerProbe(p AnalyzerProbe) { a.analyzerProbe = p }

// analyzerItem is an analyzer as the Analyzers tab shows it. An external analyzer has a target and a protocol; the matcher inside the server has an
// engine, rules and sources. Ready is false when the spec was refused, and Error says why: the screen shows the reason, never a bare "invalid".
type analyzerItem struct {
	Kind      string `json:"kind"`  // "external": a service Rampart calls; "sbom": the matcher inside the server
	Scope     string `json:"scope"` // "cluster": every tenant's; "tenant": this tenant's
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Ready     bool   `json:"ready"`
	Error     string `json:"error,omitempty"`

	Protocol       string `json:"protocol,omitempty"`
	Target         string `json:"target,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	Secure         bool   `json:"secure,omitempty"`

	Engine            string          `json:"engine,omitempty"`
	MinConfidence     *float64        `json:"min_confidence,omitempty"`
	IncludePreRelease bool            `json:"include_pre_release,omitempty"`
	MatchDirectOnly   bool            `json:"match_direct_only,omitempty"`
	Sources           map[string]bool `json:"sources,omitempty"`
	Schedule          string          `json:"schedule,omitempty"`

	UpdatedAt time.Time          `json:"updated_at"`
	LastEvent *analyzerEventItem `json:"last_event,omitempty"`
}

type analyzerEventItem struct {
	ID         string            `json:"id"`
	Event      string            `json:"event"`   // "test" or "analysis"
	Outcome    string            `json:"outcome"` // "succeeded" or "failed"
	Message    string            `json:"message"`
	Detail     map[string]string `json:"detail,omitempty"`
	DurationMs int64             `json:"duration_ms"`
	Actor      string            `json:"actor,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

func eventItemOf(e domain.AnalyzerEvent) analyzerEventItem {
	return analyzerEventItem{ID: e.ID.String(), Event: e.Event, Outcome: e.Outcome, Message: e.Message, Detail: e.Detail,
		DurationMs: e.Duration.Milliseconds(), Actor: e.Actor, CreatedAt: e.CreatedAt}
}

func analyzerKindName(storeKind string) string {
	if storeKind == domain.AnalyzerKindSBOM {
		return "sbom"
	}
	return "external"
}

func analyzerItemOf(o domain.StoredAnalyzerObject) analyzerItem {
	it := analyzerItem{Kind: analyzerKindName(o.Kind), Scope: o.Origin, Namespace: o.Namespace, Name: o.Name, UpdatedAt: o.UpdatedAt, Error: o.Error}
	switch o.Kind {
	case domain.AnalyzerKindSBOM:
		s, err := domain.ParseSBOMAnalyzerSpec(o.Spec)
		if err != nil {
			it.Error = firstNonEmpty(it.Error, err.Error())
			break
		}
		it.Enabled, it.Engine, it.MinConfidence = s.IsEnabled(), s.Engine, s.Rules.MinConfidence
		it.IncludePreRelease, it.MatchDirectOnly, it.Schedule = s.Rules.IncludePreRelease, s.Rules.MatchDirectOnly, s.Schedule
		it.Sources = map[string]bool{"osv": s.Sources.OSV == nil || *s.Sources.OSV, "ghsa": s.Sources.GHSA == nil || *s.Sources.GHSA, "nvd": s.Sources.NVD != nil && *s.Sources.NVD}
	default:
		s, err := domain.ParseExternalAnalyzerSpec(o.Spec, o.Origin == "tenant")
		if err != nil {
			// the spec in force no longer passes (or never did): show what it is, and the reason
			it.Error = firstNonEmpty(it.Error, err.Error())
			break
		}
		it.Enabled, it.Protocol, it.Target, it.TimeoutSeconds, it.Secure = s.IsEnabled(), s.Protocol, s.Target(o.Namespace), int(s.Timeout()/time.Second), s.UseTLS()
	}
	it.Ready = it.Error == ""
	return it
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// handleListAnalyzers lists the analyzers of every kind: the services Rampart calls and the matcher inside the server, the cluster's and this
// tenant's own, each with the last thing that happened to it. Rampart does not call them when an SBOM arrives yet: the tab says so.
func (a *API) handleListAnalyzers(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	items := []analyzerItem{}
	if st, ok := a.store.(domain.AnalyzerStore); ok {
		list, err := st.ListAnalyzers(r.Context(), tenantID)
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "Could not list the analyzers")
			return
		}
		ev, haveEvents := a.store.(domain.AnalyzerEvents)
		for _, o := range list {
			it := analyzerItemOf(o)
			if haveEvents {
				if last, err := ev.ListAnalyzerEvents(r.Context(), tenantID, it.Kind, it.Scope, it.Namespace, it.Name, 1); err == nil && len(last) > 0 {
					e := eventItemOf(last[0])
					it.LastEvent = &e
				}
			}
			items = append(items, it)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		x, y := items[i], items[j]
		if x.Kind != y.Kind {
			return x.Kind < y.Kind // external first ("external" sorts before "sbom")
		}
		if x.Scope != y.Scope {
			return x.Scope < y.Scope // cluster first
		}
		return x.Name < y.Name
	})
	writeJSON(w, http.StatusOK, map[string]any{"analyzers": items, "total": len(items)})
}

// handleAnalyzerEvents lists what happened to one analyzer for this tenant, newest first.
func (a *API) handleAnalyzerEvents(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	q := r.URL.Query()
	kind, scope := q.Get("kind"), q.Get("scope")
	if (kind != "external" && kind != "sbom") || (scope != "cluster" && scope != "tenant") || q.Get("name") == "" {
		problem(w, http.StatusBadRequest, "invalid-request", "kind (external or sbom), scope (cluster or tenant) and name are required")
		return
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &limit); err != nil || limit < 1 || limit > 200 {
			problem(w, http.StatusBadRequest, "invalid-request", "limit is a number from 1 to 200")
			return
		}
	}
	out := []analyzerEventItem{}
	if ev, ok := a.store.(domain.AnalyzerEvents); ok {
		list, err := ev.ListAnalyzerEvents(r.Context(), tenantID, kind, scope, q.Get("namespace"), q.Get("name"), limit)
		if err != nil {
			problem(w, http.StatusInternalServerError, "internal", "Could not list the events")
			return
		}
		for _, e := range list {
			out = append(out, eventItemOf(e))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out, "total": len(out)})
}

type analyzerTestRequest struct {
	Kind      string `json:"kind"`
	Scope     string `json:"scope"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type analyzerTestResult struct {
	OK        bool               `json:"ok"`
	Outcome   string             `json:"outcome"`
	Message   string             `json:"message"`
	LatencyMs int64              `json:"latency_ms"`
	Detail    map[string]string  `json:"detail,omitempty"`
	Event     *analyzerEventItem `json:"event,omitempty"`
}

// handleTestAnalyzer tests one analyzer and keeps the answer as an event, whatever it was: an external analyzer is called for its health and its
// metadata (no component is sent, nothing is changed); the matcher inside the server is asked whether it has advisory data to match against. An
// administrator only: the server dials the address in the analyzer's spec.
func (a *API) handleTestAnalyzer(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleAdmin)
	if !ok {
		return
	}
	var req analyzerTestRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "invalid-request", "The body is not a JSON object with kind, scope, namespace and name")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if (req.Kind != "external" && req.Kind != "sbom") || (req.Scope != "cluster" && req.Scope != "tenant") || req.Name == "" {
		problem(w, http.StatusBadRequest, "invalid-request", "kind (external or sbom), scope (cluster or tenant) and name are required")
		return
	}
	st, ok := a.store.(domain.AnalyzerStore)
	if !ok {
		problem(w, http.StatusNotImplemented, "not-implemented", "This server does not keep analyzers")
		return
	}
	list, err := st.ListAnalyzers(r.Context(), tenantID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Could not read the analyzers")
		return
	}
	var found *domain.StoredAnalyzerObject
	for i := range list {
		o := list[i]
		if analyzerKindName(o.Kind) == req.Kind && o.Origin == req.Scope && o.Name == req.Name && (req.Scope == "cluster" || o.Namespace == req.Namespace) {
			found = &o
			break
		}
	}
	if found == nil {
		problem(w, http.StatusNotFound, "not-found", "No such analyzer")
		return
	}

	started := time.Now()
	res := analyzerTestResult{Detail: map[string]string{}}
	switch req.Kind {
	case "external":
		a.testExternalAnalyzer(r.Context(), *found, &res)
	default:
		a.testMatcher(r.Context(), *found, &res)
	}
	elapsed := time.Since(started)
	res.LatencyMs = elapsed.Milliseconds()
	res.Outcome = "failed"
	if res.OK {
		res.Outcome = "succeeded"
	}
	if ev, ok := a.store.(domain.AnalyzerEvents); ok {
		e := domain.AnalyzerEvent{ID: domain.NewID(), Kind: req.Kind, Scope: req.Scope, Namespace: req.Namespace, Name: req.Name, Event: "test",
			Outcome: res.Outcome, Message: res.Message, Detail: res.Detail, Duration: elapsed, Actor: actorOf(user), CreatedAt: time.Now().UTC()}
		if err := ev.RecordAnalyzerEvent(r.Context(), tenantID, e); err == nil {
			item := eventItemOf(e)
			res.Event = &item
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *API) testExternalAnalyzer(ctx context.Context, o domain.StoredAnalyzerObject, res *analyzerTestResult) {
	spec, err := domain.ParseExternalAnalyzerSpec(o.Spec, o.Origin == "tenant")
	if err != nil {
		res.Message = "The analyzer's spec is refused, so there is nothing to call: " + err.Error()
		return
	}
	target := spec.Target(o.Namespace)
	res.Detail["target"] = target
	res.Detail["enabled"] = fmt.Sprint(spec.IsEnabled())
	res.Detail["secure"] = fmt.Sprint(spec.UseTLS())
	timeout := spec.Timeout()
	if timeout > analyzerTestTimeout {
		timeout = analyzerTestTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	probe := a.analyzerProbe
	if probe == nil {
		probe = client.Probe
	}
	pr, err := probe(cctx, target, spec.UseTLS())
	if pr.Latency > 0 {
		res.Detail["answered_in_ms"] = fmt.Sprint(pr.Latency.Milliseconds())
	}
	switch {
	case err != nil:
		res.Message = "Could not reach " + target + ": " + describeProbeError(err, timeout)
	case !pr.Serving:
		res.Detail["analyzer_says"] = pr.Message
		res.Message = "It answered but says it is not serving: " + firstNonEmpty(pr.Message, "no reason given")
	default:
		res.OK = true
		res.Detail["name"], res.Detail["version"], res.Detail["analyzer_says"] = pr.Name, pr.Version, pr.Message
		res.Detail["package_types"] = strings.Join(pr.Ecosystems, ",")
		res.Message = fmt.Sprintf("Serving: %s %s", firstNonEmpty(pr.Name, "an analyzer"), pr.Version)
		if len(pr.Ecosystems) > 0 {
			res.Message += fmt.Sprintf(", %d package types", len(pr.Ecosystems))
		}
		if !spec.IsEnabled() {
			res.Message += " (the resource is disabled, so it is not used)"
		}
	}
}

func (a *API) testMatcher(ctx context.Context, o domain.StoredAnalyzerObject, res *analyzerTestResult) {
	if _, err := domain.ParseSBOMAnalyzerSpec(o.Spec); err != nil {
		res.Message = "The matcher's spec is refused: " + err.Error()
		return
	}
	sum, ok := a.store.(domain.AdvisorySummarizer)
	if !ok {
		res.Message = "This server holds no advisory data, so the matcher has nothing to match against"
		return
	}
	s, err := sum.AdvisorySummary(ctx)
	if err != nil {
		res.Message = "Could not read the advisory data: " + err.Error()
		return
	}
	res.Detail["affected_ranges"] = fmt.Sprint(s.Ranges)
	res.Detail["ecosystems"] = fmt.Sprint(len(s.Ecosystems))
	if s.Ranges == 0 {
		res.Message = "No advisory data is loaded: the OSV feed has not synced, so the matcher has nothing to match against"
		return
	}
	res.OK = true
	res.Message = fmt.Sprintf("%d affected ranges in %d ecosystems are loaded for the matcher", s.Ranges, len(s.Ecosystems))
}

// describeProbeError says what went wrong in words an operator can act on.
func describeProbeError(err error, timeout time.Duration) string {
	switch status.Code(err) {
	case codes.DeadlineExceeded:
		return fmt.Sprintf("no answer within %s", timeout)
	case codes.Unavailable:
		return "nothing answers there (the Service or the pod is down, the port is wrong, or TLS does not match): " + status.Convert(err).Message()
	case codes.Unimplemented:
		return "it does not implement the analyzer contract (AnalyzerService)"
	case codes.Unauthenticated, codes.PermissionDenied:
		return "it refused the call: " + status.Convert(err).Message()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("no answer within %s", timeout)
	}
	return err.Error()
}

type analyzeResponse struct {
	// Queued is how many analyses were queued. An analysis already pending or running is not queued again, and an analyzer that is
	// switched off or refused queues none, so it can be less than the SBOMs there are.
	Queued int `json:"queued"`
}

// handleAnalyzeWithAnalyzer asks one analyzer to analyse the newest SBOM of every application, as a person asks for it after adding or changing
// an analyzer. Administrators only: it can queue an analysis of every SBOM of the tenant.
func (a *API) handleAnalyzeWithAnalyzer(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleAdmin)
	if !ok {
		return
	}
	if a.analysis == nil {
		problem(w, http.StatusConflict, "analysis-disabled", "Analysis is switched off on this server (analysis.enabled)")
		return
	}
	var req analyzerTestRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "invalid-request", "The body is not a JSON object with kind, scope, namespace and name")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if (req.Kind != "external" && req.Kind != "sbom") || (req.Scope != "cluster" && req.Scope != "tenant") || req.Name == "" {
		problem(w, http.StatusBadRequest, "invalid-request", "kind (external or sbom), scope (cluster or tenant) and name are required")
		return
	}
	ref := domain.AnalyzerRef{Kind: req.Kind, Scope: req.Scope, Name: req.Name}
	if req.Scope == "tenant" {
		ref.Namespace = req.Namespace
	}
	n, err := a.analysis.DispatchAnalyzer(r.Context(), tenantID, ref, domain.TriggerManual)
	switch {
	case errors.Is(err, domain.ErrNoSuchAnalyzer):
		problem(w, http.StatusNotFound, "not-found", "No such analyzer")
	case err != nil && n == 0:
		problem(w, http.StatusInternalServerError, "internal", "Could not queue the analyses")
	default:
		writeJSON(w, http.StatusAccepted, analyzeResponse{Queued: n}) // some may have failed to queue: the count is what was
	}
}

// handleAnalyzeAsset asks every analyzer that is on to analyse the newest SBOM of one asset (of each of its tracks): "analyse again" on one application.
// It needs the triager role, as an upload does.
func (a *API) handleAnalyzeAsset(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	if a.analysis == nil {
		problem(w, http.StatusConflict, "analysis-disabled", "Analysis is switched off on this server (analysis.enabled)")
		return
	}
	assetID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid-request", "The asset id is not a UUID")
		return
	}
	n, err := a.analysis.DispatchAsset(r.Context(), tenantID, assetID, domain.TriggerManual)
	if err != nil && n == 0 {
		problem(w, http.StatusInternalServerError, "internal", "Could not queue the analyses")
		return
	}
	writeJSON(w, http.StatusAccepted, analyzeResponse{Queued: n})
}
