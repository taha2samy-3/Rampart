package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/workflow"
)

func days(n int) string {
	return time.Now().UTC().Add(time.Duration(n) * 24 * time.Hour).Format(time.RFC3339)
}

func decodeOutcome(t *testing.T, body []byte) workflow.Outcome {
	t.Helper()
	var o workflow.Outcome
	if err := json.Unmarshal(body, &o); err != nil {
		t.Fatalf("outcome: %v (%s)", err, body)
	}
	return o
}

func (h *uploadHarness) finding(id uuid.UUID) *domain.Finding {
	h.t.Helper()
	f, _, err := h.store.GetFinding(context.Background(), h.tenant, id)
	if err != nil {
		h.t.Fatal(err)
	}
	return f
}

func TestRiskAcceptance_EndToEnd(t *testing.T) {
	h := newUploadHarness(t)
	ingestRules(t, h, map[string]string{"rule.a": "9.5", "rule.b": "7.5", "rule.c": "5.5", "rule.d": "4.5"}, "main")
	ids := findingIDs(t, h)
	a, b, c, d := ids["rule.a"], ids["rule.b"], ids["rule.c"], ids["rule.d"]
	viewer := h.tokenFor(auth.RoleViewer, "viewer@acme.example")
	sara := h.tokenFor(auth.RoleTriager, "sara@acme.example")
	omar := h.tokenFor(auth.RoleTriager, "omar@acme.example")
	boss := h.tokenFor(auth.RoleAdmin, "boss@acme.example")
	boss2 := h.tokenFor(auth.RoleAdmin, "boss2@acme.example")
	req := func(ids ...uuid.UUID) map[string]any {
		var s []string
		for _, id := range ids {
			s = append(s, id.String())
		}
		return map[string]any{"findingIds": s, "justification": "the service is internal and behind the VPN", "expiresAt": days(30)}
	}

	// A plain PATCH cannot accept a risk: it would never end.
	if code, _ := h.callAs(sara, "PATCH", "/api/v1/findings/"+a.String(), map[string]any{"state": "risk_accepted"}, nil); code != http.StatusBadRequest {
		t.Fatalf("PATCH risk_accepted: want 400, got %d", code)
	}

	// Who may do what.
	if code, _ := h.callAs(viewer, "POST", "/api/v1/risk-acceptances", req(a), nil); code != http.StatusForbidden {
		t.Fatalf("viewer request: %d", code)
	}
	if code, _ := h.callAs(viewer, "GET", "/api/v1/risk-acceptances", nil, nil); code != http.StatusOK {
		t.Fatalf("viewer list: %d", code)
	}

	// Each refusal says why.
	bad := func(name string, mut func(m map[string]any), want string) {
		m := req(a)
		mut(m)
		code, body := h.callAs(sara, "POST", "/api/v1/risk-acceptances", m, nil)
		if code != http.StatusBadRequest || !strings.Contains(string(body), want) {
			t.Fatalf("%s: want 400 mentioning %q, got %d %s", name, want, code, body)
		}
	}
	bad("no justification", func(m map[string]any) { m["justification"] = "  " }, "needs a justification")
	bad("no end", func(m map[string]any) { m["expiresAt"] = days(0) }, "has to end")
	bad("past the tenant maximum", func(m map[string]any) { m["expiresAt"] = days(400) }, "at most 180 days")
	bad("no findings", func(m map[string]any) { m["findingIds"] = []string{} }, "at least one finding")
	bad("an unknown finding", func(m map[string]any) { m["findingIds"] = []string{uuid.NewString()} }, "was not found")
	bad("a bad on-expiry", func(m map[string]any) { m["onExpiry"] = "forever" }, "onExpiry")

	// Without tenant approval, a request is approved at once and applied.
	// First make b "affected", so that expiry has something to go back to.
	if code, _ := h.callAs(sara, "PATCH", "/api/v1/findings/"+b.String(), map[string]any{"state": "affected"}, nil); code != http.StatusOK {
		t.Fatalf("affected: %d", code)
	}
	code, body := h.callAs(sara, "POST", "/api/v1/risk-acceptances", req(a, b), nil)
	if code != http.StatusCreated {
		t.Fatalf("auto-approved request: %d %s", code, body)
	}
	out := decodeOutcome(t, body)
	if out.Acceptance.Status != domain.AcceptanceApproved || out.Acceptance.Approver != workflow.AutoApprover || out.Applied != 2 || len(out.Skipped) != 0 {
		t.Fatalf("outcome %+v", out)
	}
	fa, fb := h.finding(a), h.finding(b)
	if fa.State != domain.StateRiskAccepted || fa.RiskAcceptanceID == nil || *fa.RiskAcceptanceID != out.Acceptance.ID || fa.PreviousState != domain.StateOpen ||
		fb.State != domain.StateRiskAccepted || fb.PreviousState != domain.StateAffected {
		t.Fatalf("findings after: a=%+v b=%+v", fa, fb)
	}
	first := out.Acceptance.ID

	// The same finding cannot be under two acceptances, and a finding that is no longer active cannot be accepted.
	if code, body := h.callAs(sara, "POST", "/api/v1/risk-acceptances", req(a), nil); code != http.StatusBadRequest || !strings.Contains(string(body), "already") {
		t.Fatalf("a covered finding: %d %s", code, body)
	}

	// The timeline names who and why.
	_, evBody := h.callAs(viewer, "GET", "/api/v1/findings/"+a.String()+"/events", nil, nil)
	if !strings.Contains(string(evBody), "risk_acceptance_approved") || !strings.Contains(string(evBody), "the service is internal and behind the VPN") {
		t.Fatalf("timeline: %s", evBody)
	}

	// Settings: a tenant admin turns approval on; others cannot, and the limits hold.
	if code, _ := h.callAs(sara, "PATCH", "/api/v1/settings", map[string]any{"riskAcceptanceApproval": true}, nil); code != http.StatusForbidden {
		t.Fatalf("triager settings: %d", code)
	}
	if code, _ := h.callAs(boss, "PATCH", "/api/v1/settings", map[string]any{"riskAcceptanceMaxDays": 9999}, nil); code != http.StatusBadRequest {
		t.Fatalf("settings out of range: %d", code)
	}
	if code, _ := h.callAs(boss, "PATCH", "/api/v1/settings", map[string]any{"riskAcceptanceApproval": true, "riskAcceptanceMaxDays": 90}, nil); code != http.StatusOK {
		t.Fatalf("settings: %d", code)
	}
	_, sb := h.callAs(viewer, "GET", "/api/v1/settings", nil, nil)
	if !strings.Contains(string(sb), `"riskAcceptanceApproval":true`) || !strings.Contains(string(sb), `"riskAcceptanceMaxDays":90`) {
		t.Fatalf("settings not stored: %s", sb)
	}
	bad("now over the new maximum", func(m map[string]any) { m["expiresAt"] = days(120) }, "at most 90 days")

	// With approval on, a request waits and changes nothing.
	code, body = h.callAs(sara, "POST", "/api/v1/risk-acceptances", req(c, d), nil)
	if code != http.StatusCreated {
		t.Fatalf("pending request: %d %s", code, body)
	}
	pending := decodeOutcome(t, body)
	if pending.Acceptance.Status != domain.AcceptancePending || pending.Applied != 0 || h.finding(c).State != domain.StateOpen {
		t.Fatalf("a pending request must not change findings: %+v", pending)
	}
	// Nobody but an admin approves, and never the person who asked.
	if code, _ := h.callAs(omar, "POST", "/api/v1/risk-acceptances/"+pending.Acceptance.ID.String()+"/approve", nil, nil); code != http.StatusForbidden {
		t.Fatalf("triager approve: %d", code)
	}
	adminReq := h.tokenFor(auth.RoleAdmin, "asker@acme.example")
	code, body = h.callAs(adminReq, "POST", "/api/v1/risk-acceptances", req(d), nil)
	if code != http.StatusBadRequest { // d is already covered by the pending request
		t.Fatalf("d is covered: %d %s", code, body)
	}
	// Reject needs a reason.
	pid := pending.Acceptance.ID.String()
	if code, _ := h.callAs(boss, "POST", "/api/v1/risk-acceptances/"+pid+"/reject", map[string]any{}, nil); code != http.StatusBadRequest {
		t.Fatalf("reject without a reason: %d", code)
	}
	if code, body := h.callAs(boss, "POST", "/api/v1/risk-acceptances/"+pid+"/reject", map[string]any{"note": "the VPN claim is not true for this host"}, nil); code != http.StatusOK || !strings.Contains(string(body), `"status":"rejected"`) {
		t.Fatalf("reject: %d %s", code, body)
	}
	if h.finding(c).State != domain.StateOpen {
		t.Fatal("a rejected request must leave the finding as it was")
	}
	if code, _ := h.callAs(boss, "POST", "/api/v1/risk-acceptances/"+pid+"/approve", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("approving a rejected request: %d", code)
	}

	// The requester cannot approve their own request, even as an admin.
	code, body = h.callAs(adminReq, "POST", "/api/v1/risk-acceptances", req(c), nil)
	if code != http.StatusCreated {
		t.Fatalf("admin request: %d %s", code, body)
	}
	own := decodeOutcome(t, body).Acceptance.ID.String()
	if code, body := h.callAs(adminReq, "POST", "/api/v1/risk-acceptances/"+own+"/approve", nil, nil); code != http.StatusBadRequest || !strings.Contains(string(body), "own") {
		t.Fatalf("self approval: %d %s", code, body)
	}

	// Two approvers at once: exactly one wins.
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, tok := range []string{boss, boss2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], _ = h.callAs(tok, "POST", "/api/v1/risk-acceptances/"+own+"/approve", nil, nil)
		}()
	}
	wg.Wait()
	oks := 0
	for _, c := range codes {
		if c == http.StatusOK {
			oks++
		}
	}
	if oks != 1 {
		t.Fatalf("two simultaneous approvals: %v, want exactly one 200", codes)
	}
	fc := h.finding(c)
	if fc.State != domain.StateRiskAccepted || fc.Resolution == nil {
		t.Fatalf("approved: %+v", fc)
	}

	// Revoking: a triager who did not ask cannot; the one who asked can; the finding goes back where it came from.
	if code, _ := h.callAs(omar, "POST", "/api/v1/risk-acceptances/"+own+"/revoke", map[string]any{"note": "x"}, nil); code != http.StatusForbidden {
		t.Fatalf("someone else revoking: %d", code)
	}
	if code, body := h.callAs(boss, "POST", "/api/v1/risk-acceptances/"+own+"/revoke", map[string]any{"note": "no longer true"}, nil); code != http.StatusOK || !strings.Contains(string(body), `"status":"revoked"`) {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if fc := h.finding(c); fc.State != domain.StateOpen || fc.RiskAcceptanceID != nil || fc.Resolution != nil {
		t.Fatalf("a revoked acceptance must return the finding: %+v", fc)
	}
	if code, _ := h.callAs(boss, "POST", "/api/v1/risk-acceptances/"+own+"/revoke", map[string]any{}, nil); code != http.StatusBadRequest {
		t.Fatalf("revoking twice: %d", code)
	}

	// Expiry returns each finding to where it came from: a to open, b to affected.
	svc := workflow.New(h.store)
	if n, err := svc.ExpireDue(context.Background(), h.tenant, time.Now().Add(24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("nothing is due yet: %d %v", n, err)
	}
	tenants, err := h.sys.TenantsWithDueAcceptances(context.Background(), time.Now().Add(31*24*time.Hour))
	if err != nil || len(tenants) == 0 {
		t.Fatalf("the sweeper must find the tenant: %v %v", tenants, err)
	}
	if n, err := svc.ExpireDue(context.Background(), h.tenant, time.Now().Add(31*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("expiry: %d %v", n, err)
	}
	fa, fb = h.finding(a), h.finding(b)
	if fa.State != domain.StateOpen || fb.State != domain.StateAffected || fa.RiskAcceptanceID != nil {
		t.Fatalf("after expiry: a=%s b=%s", fa.State, fb.State)
	}
	if n, _ := svc.ExpireDue(context.Background(), h.tenant, time.Now().Add(31*24*time.Hour)); n != 0 {
		t.Fatal("an expired acceptance must not expire again")
	}
	_, got := h.callAs(viewer, "GET", "/api/v1/risk-acceptances/"+first.String(), nil, nil)
	if !strings.Contains(string(got), `"status":"expired"`) {
		t.Fatalf("status after expiry: %s", got)
	}
	_, evBody = h.callAs(viewer, "GET", "/api/v1/findings/"+a.String()+"/events", nil, nil)
	if !strings.Contains(string(evBody), "risk_acceptance_expired") {
		t.Fatalf("the timeline must say it expired: %s", evBody)
	}

	// The list filters by status.
	_, lst := h.callAs(viewer, "GET", "/api/v1/risk-acceptances?status=expired", nil, nil)
	var l struct {
		Items []domain.RiskAcceptance `json:"items"`
	}
	_ = json.Unmarshal(lst, &l)
	if len(l.Items) != 1 || l.Items[0].ID != first || len(l.Items[0].FindingIDs) != 2 {
		t.Fatalf("list expired: %s", lst)
	}
	if code, _ := h.callAs(viewer, "GET", "/api/v1/risk-acceptances?status=banana", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("bad status filter: %d", code)
	}

	// Another tenant sees none of it and cannot act on it.
	other := newUploadHarness(t)
	oBoss := other.tokenFor(auth.RoleAdmin, "eve@other.example")
	if code, _ := other.callAs(oBoss, "GET", "/api/v1/risk-acceptances/"+first.String(), nil, nil); code != http.StatusNotFound {
		t.Fatalf("SECURITY VIOLATION: another tenant read an acceptance: %d", code)
	}
	if code, _ := other.callAs(oBoss, "POST", "/api/v1/risk-acceptances/"+first.String()+"/revoke", map[string]any{}, nil); code != http.StatusNotFound {
		t.Fatalf("SECURITY VIOLATION: another tenant revoked an acceptance: %d", code)
	}
	if code, body := other.callAs(oBoss, "POST", "/api/v1/risk-acceptances", map[string]any{"findingIds": []string{a.String()}, "justification": "x", "expiresAt": days(10)}, nil); code != http.StatusBadRequest {
		t.Fatalf("SECURITY VIOLATION: another tenant accepted a finding it cannot see: %d %s", code, body)
	}
	_, os := other.callAs(oBoss, "GET", "/api/v1/settings", nil, nil)
	if strings.Contains(string(os), `"riskAcceptanceApproval":true`) {
		t.Fatalf("SECURITY VIOLATION: tenant settings leaked: %s", os)
	}
}

// notify_only keeps the finding accepted; an acceptance on a finding no scanner reports any more resolves it.
func TestRiskAcceptance_ExpiryModes(t *testing.T) {
	h := newUploadHarness(t)
	ingestRules(t, h, map[string]string{"rule.keep": "9.5", "rule.gone": "7.5"}, "main")
	ids := findingIDs(t, h)
	sara := h.tokenFor(auth.RoleTriager, "sara@acme.example")
	post := func(id uuid.UUID, onExpiry string) workflow.Outcome {
		code, body := h.callAs(sara, "POST", "/api/v1/risk-acceptances", map[string]any{
			"findingIds": []string{id.String()}, "justification": "tracked in the backlog", "expiresAt": days(20), "onExpiry": onExpiry,
		}, nil)
		if code != http.StatusCreated {
			t.Fatalf("request: %d %s", code, body)
		}
		return decodeOutcome(t, body)
	}
	keep := post(ids["rule.keep"], "notify_only")
	gone := post(ids["rule.gone"], "reactivate")

	// rule.gone is no longer reported: a rescan without it marks it absent (D18).
	ingestRules(t, h, map[string]string{"rule.keep": "9.5"}, "main")
	if f := h.finding(ids["rule.gone"]); f.State != domain.StateRiskAccepted || f.Detection != domain.DetectionAbsent {
		t.Fatalf("an accepted finding that disappears keeps its disposition and becomes absent: state %s detection %s", f.State, f.Detection)
	}

	if n, err := workflow.New(h.store).ExpireDue(context.Background(), h.tenant, time.Now().Add(21*24*time.Hour)); err != nil || n != 2 {
		t.Fatalf("expiry: %d %v", n, err)
	}
	kf, gf := h.finding(ids["rule.keep"]), h.finding(ids["rule.gone"])
	if kf.State != domain.StateRiskAccepted {
		t.Fatalf("notify_only must leave the finding accepted, got %s", kf.State)
	}
	if gf.State != domain.StateFixed || gf.Resolution == nil || *gf.Resolution != domain.ResolutionFixed {
		t.Fatalf("expiry on an absent finding resolves it (D18), got %s", gf.State)
	}
	_, got := h.callAs(sara, "GET", "/api/v1/risk-acceptances/"+keep.Acceptance.ID.String(), nil, nil)
	if !strings.Contains(string(got), `"status":"expired"`) {
		t.Fatalf("notify_only still ends the acceptance: %s", got)
	}
	_ = gone
}
