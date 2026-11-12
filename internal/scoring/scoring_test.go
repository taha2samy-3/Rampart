package scoring

import (
	"testing"

	"rampart/internal/domain"
)

func factor(t *testing.T, f *domain.Finding, app *domain.Application, name string) int {
	t.Helper()
	b, _ := Breakdown(f, app, nil, nil)
	for _, x := range b.Factors {
		if x.Name == name {
			return x.Points
		}
	}
	return 0
}

// The application's context reaches the score (D55): sensitive data adds, a WAF subtracts only from a finding a
// dynamic scan made.
func TestBreakdown_ApplicationContext(t *testing.T) {
	app := &domain.Application{BusinessCriticality: "critical", DataClassification: []string{"pii"}, CompensatingControls: []string{"waf"}}
	dast := &domain.Finding{Severity: domain.SeverityHigh, Category: domain.CategoryDAST}
	sast := &domain.Finding{Severity: domain.SeverityHigh, Category: domain.CategorySAST}
	if p := factor(t, dast, app, "COMPENSATING_CONTROL"); p != -80 {
		t.Fatalf("a WAF on a DAST finding: %d", p)
	}
	if p := factor(t, sast, app, "COMPENSATING_CONTROL"); p != 0 {
		t.Fatalf("a WAF must not lower a SAST finding: %d", p)
	}
	withData, _ := Breakdown(sast, app, nil, nil)
	without, _ := Breakdown(sast, &domain.Application{BusinessCriticality: "critical"}, nil, nil)
	if withData.TotalScore-without.TotalScore != 80 {
		t.Fatalf("sensitive data should add 80: %d vs %d", withData.TotalScore, without.TotalScore)
	}
}
