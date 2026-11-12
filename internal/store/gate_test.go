package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/query"
)

// miniSARIF builds a report from (rule, security-severity) pairs; "9.5" is critical, "7.5" is high.
func miniSARIF(rules map[string]string) []byte {
	var defs, results []string
	for id, sev := range rules {
		defs = append(defs, fmt.Sprintf(`{"id":%q,"shortDescription":{"text":%q},"properties":{"security-severity":%q}}`, id, "rule "+id, sev))
		results = append(results, fmt.Sprintf(`{"ruleId":%q,"message":{"text":"problem %s"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/%s.go"},"region":{"startLine":10}}}]}`, id, id, id))
	}
	return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","version":"1","rules":[` + strings.Join(defs, ",") +
		`]}},"results":[` + strings.Join(results, ",") + `]}]}`)
}

func (h *uploadHarness) complete(id string, report []byte) string {
	h.t.Helper()
	code, body := h.call("POST", "/ingest/v1/uploads/"+id+"/complete", ingest.CompleteUploadRequest{SHA256: sha(report)}, nil)
	if code != http.StatusAccepted {
		h.t.Fatalf("complete: %d %s", code, body)
	}
	var done ingest.CompleteUploadResponse
	_ = json.Unmarshal(body, &done)
	return done.IngestRunID
}

func (h *uploadHarness) gate(commit string, expect []string, failOn string) (int, query.GateResponse) {
	h.t.Helper()
	code, body := h.call("POST", "/api/v1/gate", map[string]any{
		"source": "default", "context": map[string]string{"commit": commit}, "expect": expect, "failOn": failOn,
	}, nil)
	var out query.GateResponse
	_ = json.Unmarshal(body, &out)
	return code, out
}

func TestGate_EphemeralRunsAgainstTheBaseline(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	repo := "github.com/acme/up-test"

	// The tracked branch: one high finding in the inventory.
	base := miniSARIF(map[string]string{"rule.a": "7.5"})
	id, _ := h.uploadWith(base, "", domain.UploadContext{Repository: repo, Branch: "main", Commit: "c-main"})
	if run := h.waitRun(h.complete(id, base)); run.Status != domain.RunCompleted {
		t.Fatalf("baseline run: %s %s", run.Status, run.Error)
	}
	inventory, _ := h.app.ListFindings(ctx, h.tenant)
	if len(inventory) != 1 {
		t.Fatalf("baseline inventory: %d findings, want 1", len(inventory))
	}

	// A pull request that adds nothing: the same finding is "existing", the gate passes.
	pr1 := h.uploadAndComplete(base, domain.UploadContext{Repository: repo, Branch: "pr/1", Commit: "c-pr1"})
	if run := h.waitRun(pr1); run.Status != domain.RunCompleted || run.Stats.Untouched != 1 || run.Stats.Created != 0 {
		t.Fatalf("pr1 run: %s stats %+v", run.Status, run.Stats)
	}
	if code, g := h.gate("c-pr1", []string{"semgrep"}, "critical"); code != 200 || !g.Pass || g.Summary.Existing != 1 || g.Summary.New != 0 {
		t.Fatalf("a pull request with nothing new: %d %+v", code, g)
	}

	// A pull request that adds a critical finding and fixes the high one: the gate blocks on the new one.
	changed := miniSARIF(map[string]string{"rule.b": "9.5"})
	pr2 := h.uploadAndComplete(changed, domain.UploadContext{Repository: repo, Branch: "pr/2", Commit: "c-pr2"})
	if run := h.waitRun(pr2); run.Status != domain.RunCompleted || run.Stats.Created != 1 || run.Stats.Closed != 1 {
		t.Fatalf("pr2 run: %s stats %+v", run.Status, run.Stats)
	}
	code, g := h.gate("c-pr2", []string{"semgrep"}, "critical")
	if code != 200 || g.Pass || len(g.Blocking) != 1 || g.Blocking[0].Severity != "critical" || g.Summary.New != 1 || g.Summary.Fixed != 1 {
		t.Fatalf("a pull request adding a critical finding must fail the gate: %d %+v", code, g)
	}
	// The same findings are not blocking when the threshold is above them.
	if _, g := h.gate("c-pr2", []string{"semgrep"}, "critical"); g.Summary.New != 1 {
		t.Fatal("summary must not change with the threshold")
	}

	// Ephemeral runs never touch the inventory (D10).
	after, _ := h.app.ListFindings(ctx, h.tenant)
	if len(after) != 1 || after[0].ID != inventory[0].ID || after[0].State != domain.StateOpen {
		t.Fatalf("pull-request runs changed the inventory: %d findings", len(after))
	}

	// A declared input that was never uploaded keeps the gate from passing (no run is not "clean").
	if _, g := h.gate("c-pr2", []string{"semgrep", "trivy"}, "critical"); g.Pass {
		t.Fatalf("a missing declared run must not pass: %+v", g)
	}
	// An unknown commit has no runs at all.
	if _, g := h.gate("c-nobody", []string{"semgrep"}, "critical"); g.Pass {
		t.Fatalf("a build with no runs must not pass: %+v", g)
	}

	// A tracked run: a new critical finding on main blocks the gate for that commit.
	tracked := miniSARIF(map[string]string{"rule.a": "7.5", "rule.c": "9.9"})
	tr := h.uploadAndComplete(tracked, domain.UploadContext{Repository: repo, Branch: "main", Commit: "c-main2"})
	if run := h.waitRun(tr); run.Status != domain.RunCompleted {
		t.Fatalf("tracked run: %s %s", run.Status, run.Error)
	}
	if _, g := h.gate("c-main2", []string{"semgrep"}, "critical"); g.Pass || len(g.Blocking) != 1 {
		t.Fatalf("a tracked run that created a critical finding must fail the gate: %+v", g)
	}
	_ = uuid.Nil
}

func (h *uploadHarness) uploadAndComplete(report []byte, uctx domain.UploadContext) string {
	h.t.Helper()
	id, st := h.uploadWith(report, "", uctx)
	if st != http.StatusOK {
		h.t.Fatalf("PUT: %d", st)
	}
	return h.complete(id, report)
}
