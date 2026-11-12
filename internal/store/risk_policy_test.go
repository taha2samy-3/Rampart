package store_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/config/apply"
	"rampart/internal/domain"
)

// Risk policies (docs/06 section 2, D62): the tenant's RiskPolicy wins over the ClusterRiskPolicy, which wins over
// the built-in policy; a change re-scores stored findings; a refused spec keeps the one in force; deleting falls
// back; the API explains the score with the policy's own factor and its group.
func TestRiskPolicies(t *testing.T) {
	ctx := context.Background()
	h := newUploadHarness(t)
	h.formatHint = "semgrep"
	h.waitRun(h.uploadAndComplete(semgrepReport(semgrepResult("rule.sqli", "a.go", 3)), domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main"}))
	score := func(want int, why string) {
		t.Helper()
		flagged, err := h.sys.TenantsNeedingSLARecompute(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(flagged, h.tenant) {
			if _, err := h.scorer.RecomputeSLA(ctx, h.tenant); err != nil {
				t.Fatal(err)
			}
			_ = h.store.ClearSLARecompute(ctx, h.tenant)
		}
		if got := findingByRule(t, h, "rule.sqli").RiskScore; got != want {
			t.Fatalf("%s: stored score %d, want %d", why, got, want)
		}
	}
	score(400, "built-in: a high finding") // Semgrep ERROR is high (400); no context factor applies

	cluster := apply.PolicyObject{Name: "default", Spec: []byte(`{"base": {"high": 450}}`)}
	if err := h.sys.SaveClusterPolicy(ctx, "risk", cluster); err != nil {
		t.Fatal(err)
	}
	score(450, "the cluster default")

	tenantPolicy := apply.PolicyObject{Namespace: "default", Name: "default", Spec: []byte(`{"factors": [
		{"name": "injection", "when": "finding.cwes.exists(c, c == 89)", "points": 100, "group": "threat", "reason": "SQL injection"}]}`)}
	if err := h.sys.SaveRiskPolicy(ctx, h.tenant, tenantPolicy); err != nil {
		t.Fatal(err)
	}
	score(500, "the tenant's policy wins over the cluster default (built-in base 400 + injection 100)")

	// The API explains the stored number with the policy's factor and its group.
	viewer := h.tokenFor(auth.RoleViewer, "viewer@acme.example")
	f := findingByRule(t, h, "rule.sqli")
	_, body := h.callAs(viewer, "GET", "/api/v1/findings/"+f.ID.String(), nil, nil)
	var got struct {
		Risk struct {
			TotalScore int `json:"total_score"`
			Factors    []struct{ Name, Group string }
		} `json:"risk"`
	}
	_ = json.Unmarshal(body, &got)
	if got.Risk.TotalScore != 500 || len(got.Risk.Factors) != 1 || got.Risk.Factors[0].Name != "injection" || got.Risk.Factors[0].Group != "threat" {
		t.Fatalf("explained: %s", body)
	}

	// A refused edit keeps the policy in force (D41's rule, D62).
	bad := apply.PolicyObject{Namespace: "default", Name: "default", Spec: []byte(`{"factors": [{"name": "x", "when": "app.critcality == 1", "points": 5}]}`), Error: "refused"}
	if err := h.sys.SaveRiskPolicy(ctx, h.tenant, bad); err != nil {
		t.Fatal(err)
	}
	score(500, "a refused edit changes nothing")

	if err := h.sys.DeleteRiskPolicy(ctx, h.tenant, "default", "default"); err != nil {
		t.Fatal(err)
	}
	score(450, "without the tenant's policy, the cluster default")
	if err := h.sys.DeleteClusterPolicy(ctx, "risk", "default"); err != nil {
		t.Fatal(err)
	}
	score(400, "without either, the built-in policy")
}
