package domain_test

import (
	"strings"
	"testing"
	"time"

	"rampart/internal/domain"
)

func TestParseSLAPolicySpec(t *testing.T) {
	// An empty spec is the built-in policy.
	p, err := domain.ParseSLAPolicySpec(nil)
	if err != nil || p.Days(domain.SeverityCritical, "critical") != 3 {
		t.Fatalf("empty spec: %v %+v", err, p)
	}
	// What is given replaces the built-in value; the rest stays.
	p, err = domain.ParseSLAPolicySpec([]byte(`{"matrix":{"critical":{"critical":1,"high":2}},"caps":{"kevDueDate":false,"maxDays":30},"restartOnReactivation":false}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Days(domain.SeverityCritical, "critical") != 1 || p.Days(domain.SeverityCritical, "high") != 2 || p.Days(domain.SeverityCritical, "medium") != 14 {
		t.Fatalf("matrix merge: %+v", p.Matrix["critical"])
	}
	if p.KEVDueDate || p.MaxDays != 30 || p.RestartOnReactivation || !p.PauseDuringRiskAcceptance {
		t.Fatalf("caps and flags: %+v", p)
	}
	// maxDays caps a long allowance (the low row is 365 days).
	if got := p.Days(domain.SeverityLow, "low"); got != 30 {
		t.Fatalf("maxDays cap: %d", got)
	}
	// The CISA date wins only when the policy says so.
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	kev := start.Add(24 * time.Hour)
	if d := domain.DefaultSLAPolicy().Due(domain.SeverityLow, "low", start, &kev); !d.Equal(kev) {
		t.Fatalf("kev cap on: %v", d)
	}
	if d := p.Due(domain.SeverityLow, "low", start, &kev); d.Equal(kev) {
		t.Fatal("kev cap off, but the CISA date was used")
	}

	for name, bad := range map[string]struct{ spec, want string }{
		"unknown band":        {`{"matrix":{"urgent":{"low":1}}}`, "not a risk band"},
		"unknown criticality": {`{"matrix":{"low":{"huge":1}}}`, "not an application criticality"},
		"zero days":           {`{"matrix":{"low":{"low":0}}}`, "not between 1 and 3650"},
		"too many days":       {`{"matrix":{"low":{"low":99999}}}`, "not between 1 and 3650"},
		"bad cap":             {`{"caps":{"maxDays":0}}`, "caps.maxDays"},
		"verified start":      {`{"startFrom":"verified"}`, "not supported yet"},
		"business days":       {`{"businessDays":true}`, "business days"},
		"not json":            {`{`, "not valid"},
	} {
		if _, err := domain.ParseSLAPolicySpec([]byte(bad.spec)); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Fatalf("%s: want an error containing %q, got %v", name, bad.want, err)
		}
	}
}
