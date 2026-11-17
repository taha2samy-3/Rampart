package query_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/query"

	"github.com/google/uuid"
)

// "If I open a vulnerability I want to see that it is against a deadline, and fix it before the control goes out of
// compliance": the finding says which controls it counts against, and when it falls due.
func TestAPI_FindingSaysWhichControlsItCountsAgainst(t *testing.T) {
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	mem := ingest.NewMemoryStore()
	appID, assetID := domain.NewID(), domain.NewID()
	_ = mem.CreateApplication(context.Background(), &domain.Application{ID: appID, TenantID: tenantID, Slug: "shop", Name: "Shop"})
	soon, past := time.Now().Add(4*24*time.Hour), time.Now().Add(-3*24*time.Hour)
	mk := func(state domain.FindingState, cwes []int, cat domain.FindingCategory, due *time.Time) uuid.UUID {
		f := &domain.Finding{ID: domain.NewID(), TenantID: tenantID, ApplicationID: appID, AssetID: assetID, FindingKey: uuid.NewString(), Title: "x", RuleID: "r", RuleScannerFamily: "semgrep",
			Category: cat, CWEs: cwes, Severity: domain.SeverityHigh, RiskBand: domain.SeverityHigh, State: state, SLADue: due, FirstSeen: time.Now(), LastSeen: time.Now()}
		_ = mem.UpsertFindings(context.Background(), tenantID, []*domain.Finding{f})
		return f.ID
	}
	xssSoon := mk(domain.StateOpen, []int{79}, domain.CategorySAST, &soon)
	xssLate := mk(domain.StateOpen, []int{79}, domain.CategorySAST, &past)
	xssFixed := mk(domain.StateFixed, []int{79}, domain.CategorySAST, &past)
	nothing := mk(domain.StateOpen, nil, domain.CategoryDAST, &soon)

	authn := auth.NewAuthenticatorWithStore(mem)
	token := authn.DefaultAdminToken(tenantID)
	mux := http.NewServeMux()
	query.NewAPIWithAuth(mem, nil, authn).RegisterRoutes(mux)
	controls := func(id uuid.UUID) []query.FindingControl {
		req := httptest.NewRequest("GET", "/api/v1/findings/"+id.String(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out struct {
			Controls []query.FindingControl `json:"controls"`
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Controls == nil {
			t.Fatalf("%d %s (controls must be [] and never null)", rec.Code, rec.Body.String())
		}
		return out.Controls
	}
	find := func(cs []query.FindingControl, fw, ctl string) *query.FindingControl {
		for i := range cs {
			if cs[i].FrameworkID == fw && cs[i].ControlID == ctl {
				return &cs[i]
			}
		}
		return nil
	}

	c := find(controls(xssSoon), "cwe-top25", "CWE-79")
	if c == nil || c.Overdue || c.Due == nil || !c.Due.Equal(soon.UTC()) || c.Framework == "" || c.Control == "" {
		t.Fatalf("an XSS finding counts against CWE Top 25 CWE-79, with its deadline and not yet overdue: %+v", c)
	}
	if c := find(controls(xssLate), "cwe-top25", "CWE-79"); c == nil || !c.Overdue {
		t.Errorf("past its deadline: overdue: %+v", c)
	}
	if got := controls(xssFixed); len(got) != 0 {
		t.Errorf("a finding that is fixed counts against nothing: %+v", got)
	}
	if got := controls(nothing); find(got, "cwe-top25", "CWE-79") != nil {
		t.Errorf("a DAST finding with no weakness does not count against CWE-79: %+v", got)
	}
	// Sorted, so the list does not jump between requests.
	cs := controls(xssSoon)
	for i := 1; i < len(cs); i++ {
		if cs[i-1].Framework > cs[i].Framework || (cs[i-1].Framework == cs[i].Framework && cs[i-1].ControlID > cs[i].ControlID) {
			t.Fatalf("unsorted: %v before %v", cs[i-1], cs[i])
		}
	}
}
