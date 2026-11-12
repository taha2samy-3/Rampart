package query

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// GateRequest is the body of POST /api/v1/gate (docs/05 section 9, D26).
type GateRequest struct {
	Source  string `json:"source"`
	Context struct {
		Commit      string `json:"commit,omitempty"`
		ImageDigest string `json:"imageDigest,omitempty"`
	} `json:"context"`
	Expect         []string `json:"expect"`                   // what the pipeline will upload: semgrep, trivy, sbom...
	Wait           bool     `json:"wait"`                     // wait for the declared runs to finish
	TimeoutSeconds int      `json:"timeoutSeconds,omitempty"` // default 300, at most 1800
	FailOn         string   `json:"failOn,omitempty"`         // severity at or above which a new finding blocks; default critical
}

// GateFinding is one finding that blocks the gate.
type GateFinding struct {
	ID       string `json:"id,omitempty"`
	Key      string `json:"key"`
	Severity string `json:"severity"`
	Title    string `json:"title,omitempty"`
	Path     string `json:"path,omitempty"`
	Run      string `json:"run"`
}

// GateResponse is the gate verdict.
type GateResponse struct {
	Pass     bool          `json:"pass"`
	Reasons  []string      `json:"reasons"`
	Summary  GateSummary   `json:"summary"`
	Blocking []GateFinding `json:"blocking,omitempty"`
	Runs     []string      `json:"runs"`
}

// GateSummary counts what the declared runs found against their baseline.
type GateSummary struct {
	New      int `json:"new"`
	Fixed    int `json:"fixed"`
	Existing int `json:"existing"`
}

func (a *API) handleGate(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	var req GateRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req) != nil {
		problem(w, http.StatusBadRequest, "validation", "Invalid JSON request")
		return
	}
	if req.Context.Commit == "" && req.Context.ImageDigest == "" {
		problem(w, http.StatusBadRequest, "validation", "context.commit or context.imageDigest is required: it is how the gate finds the runs of this build")
		return
	}
	if len(req.Expect) == 0 {
		problem(w, http.StatusBadRequest, "validation", "expect is required: declare what the pipeline uploads (for example semgrep, trivy, sbom)")
		return
	}
	failOn := domain.Severity(strings.ToLower(req.FailOn))
	if failOn == "" {
		failOn = domain.SeverityCritical
	}
	if failOn.Rank() == 0 {
		problem(w, http.StatusBadRequest, "validation", "failOn must be critical, high, medium or low")
		return
	}
	source, err := a.store.EnsureScanSource(r.Context(), tenantID, req.Source)
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Scan source not found")
		return
	}
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	timeout = min(timeout, 30*time.Minute)

	deadline := time.Now().Add(timeout)
	var resp GateResponse
	for {
		resp = a.evaluateGate(r.Context(), tenantID, source, req, failOn)
		if !req.Wait || resp.final() || time.Now().After(deadline) {
			if req.Wait && !resp.final() {
				resp.Pass = false // D26: a timeout fails the gate
				resp.Reasons = append(resp.Reasons, "timeout")
			}
			break
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// final reports whether the verdict no longer depends on runs still in progress.
func (g GateResponse) final() bool {
	for _, r := range g.Reasons {
		if strings.HasPrefix(r, "waiting for ") {
			return false
		}
	}
	return true
}

// evaluateGate looks at the runs of the build once. A run that is not finished yet makes the verdict
// "waiting"; a failed run fails the gate with its reason (fail closed).
func (a *API) evaluateGate(ctx context.Context, tenantID, source uuid.UUID, req GateRequest, failOn domain.Severity) GateResponse {
	resp := GateResponse{Pass: true, Reasons: []string{}, Runs: []string{}}
	runs, err := a.store.ListRunsForGate(ctx, tenantID, source, req.Context.Commit, req.Context.ImageDigest)
	if err != nil {
		resp.Pass, resp.Reasons = false, append(resp.Reasons, "could not read the runs: "+err.Error())
		return resp
	}
	// The newest run of each expected input.
	sort.Slice(runs, func(i, j int) bool { return runs[i].CreatedAt.After(runs[j].CreatedAt) })
	for _, want := range req.Expect {
		var run *domain.IngestRun
		for _, r := range runs {
			if a.runMatches(ctx, tenantID, r, want) {
				run = r
				break
			}
		}
		switch {
		case run == nil:
			resp.Pass = false
			resp.Reasons = append(resp.Reasons, fmt.Sprintf("waiting for %s: no run uploaded yet", want))
		case !run.Status.IsTerminal():
			resp.Pass = false
			resp.Reasons = append(resp.Reasons, fmt.Sprintf("waiting for %s: the run is %s", want, run.Status))
		case run.Status == domain.RunFailed, run.Status == domain.RunStale:
			resp.Pass = false
			resp.Runs = append(resp.Runs, run.ID.String())
			resp.Reasons = append(resp.Reasons, fmt.Sprintf("%s: the run %s (%s)", want, run.Status, run.Error))
		default:
			resp.Runs = append(resp.Runs, run.ID.String())
			a.gateRun(ctx, tenantID, run, failOn, &resp)
		}
	}
	if len(resp.Blocking) > 0 {
		resp.Pass = false
		resp.Reasons = append(resp.Reasons, fmt.Sprintf("%d new or reactivated finding(s) at %s or above", len(resp.Blocking), failOn))
	}
	if resp.Pass {
		resp.Reasons = append(resp.Reasons, "no new or reactivated finding at "+string(failOn)+" or above")
	}
	return resp
}

// runMatches says whether a run is the one the pipeline declared: by scanner family in its report, by the
// family or format it was uploaded as, or "sbom" for an SBOM format.
func (a *API) runMatches(ctx context.Context, tenantID uuid.UUID, r *domain.IngestRun, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	if strings.EqualFold(r.ScannerFamily, want) || strings.EqualFold(r.Format, want) {
		return true
	}
	if want == "sbom" {
		switch strings.ToLower(r.Format) {
		case "cyclonedx", "spdx", "syft":
			return true
		}
	}
	if fams, err := a.store.ListRunScopes(ctx, tenantID, r.ID); err == nil {
		for _, f := range fams {
			if strings.EqualFold(f, want) {
				return true
			}
		}
	}
	return false
}

// gateRun adds one run's new and reactivated findings to the verdict. Both kinds of run store them as
// ingest_run_result rows: an ephemeral run against its baseline, a tracked run as what the merge created or reactivated.
func (a *API) gateRun(ctx context.Context, tenantID uuid.UUID, run *domain.IngestRun, failOn domain.Severity, resp *GateResponse) {
	if results, err := a.store.ListRunResults(ctx, tenantID, run.ID); err == nil && len(results) > 0 {
		for _, res := range results {
			switch {
			case res.IsFixed:
				resp.Summary.Fixed++
			case res.IsNew:
				resp.Summary.New++
				if res.Severity.Rank() >= failOn.Rank() {
					resp.Blocking = append(resp.Blocking, GateFinding{Key: res.FindingKey, Severity: string(res.Severity), Path: res.Location.PrimaryPath(), Run: run.ID.String()})
				}
			default:
				resp.Summary.Existing++
			}
		}
		if run.Stats.Parsed > 0 && !isEphemeralRun(results) {
			resp.Summary.Existing = max(resp.Summary.Existing, run.Stats.Parsed-countNew(results))
		}
		return
	}
	// A run with no stored results has nothing new (a tracked run with only existing findings).
	resp.Summary.Existing += run.Stats.Parsed

}

func countNew(rs []*domain.IngestRunResult) int {
	n := 0
	for _, r := range rs {
		if r.IsNew {
			n++
		}
	}
	return n
}

// isEphemeralRun: ephemeral results also carry existing and fixed rows; a tracked run's carry new ones only.
func isEphemeralRun(rs []*domain.IngestRunResult) bool {
	for _, r := range rs {
		if r.IsFixed || !r.IsNew {
			return true
		}
	}
	return false
}
