package risk_test

import (
	"testing"
	"time"

	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/risk"
)

func TestEvaluateRiskBase(t *testing.T) {
	finding := domain.RawFinding{
		Severity: domain.SeverityCritical,
	}

	res := risk.EvaluateRisk(finding, nil, risk.Context{}, nil)
	if res.TotalScore != 600 {
		t.Errorf("expected base score 600 for critical, got %d", res.TotalScore)
	}
	if res.Band != domain.SeverityHigh {
		t.Errorf("expected high band for score 600, got %s", res.Band)
	}
}

func TestEvaluateRiskWithKEVAndEPSS(t *testing.T) {
	feeds := enrich.NewFeedStore()
	feeds.SetKEV(enrich.KEVEntry{
		CVEID: "CVE-2021-44228",
	})
	feeds.SetEPSS(enrich.EPSSScore{
		CVEID: "CVE-2021-44228",
		EPSS:  0.95,
	})

	finding := domain.RawFinding{
		Severity: domain.SeverityHigh, // 400
	}

	ctx := risk.Context{
		IsInternetFacing:    true,         // +100
		BusinessCriticality: "critical",   // +100
		Environment:         "production", // +60
	}

	// 400 + KEV(300) + EPSS_HIGH(150) + Internet(100) + AppCritical(100) + Prod(60) = 1110 -> clamped to 1000
	res := risk.EvaluateRisk(finding, []string{"CVE-2021-44228"}, ctx, feeds)
	if res.TotalScore != 1000 {
		t.Errorf("expected clamped score 1000, got %d", res.TotalScore)
	}
	if res.Band != domain.SeverityCritical {
		t.Errorf("expected critical band, got %s", res.Band)
	}
	if !res.HasKEV {
		t.Errorf("expected HasKEV true")
	}
	if res.EPSSScore != 0.95 {
		t.Errorf("expected EPSS 0.95, got %f", res.EPSSScore)
	}
}

func TestEvaluateRiskUnreachableModifier(t *testing.T) {
	finding := domain.RawFinding{
		Severity: domain.SeverityMedium, // 200
	}

	ctx := risk.Context{
		IsUnreachable: true, // -200
	}

	res := risk.EvaluateRisk(finding, nil, ctx, nil)
	if res.TotalScore != 0 {
		t.Errorf("expected score 0 (200 - 200), got %d", res.TotalScore)
	}
	if res.Band != domain.SeverityLow {
		t.Errorf("expected low band for score 0, got %s", res.Band)
	}
}

func TestCalculateSLADueDate(t *testing.T) {
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Critical risk band + critical app -> 3 days
	due1 := risk.CalculateSLADueDate(domain.SeverityCritical, "critical", start, nil)
	expected1 := start.Add(3 * 24 * time.Hour)
	if !due1.Equal(expected1) {
		t.Errorf("expected due %v, got %v", expected1, due1)
	}

	// Critical risk band + low app -> 30 days
	due2 := risk.CalculateSLADueDate(domain.SeverityCritical, "low", start, nil)
	expected2 := start.Add(30 * 24 * time.Hour)
	if !due2.Equal(expected2) {
		t.Errorf("expected due %v, got %v", expected2, due2)
	}

	// KEV due date wins when earlier
	earlierKEVDue := start.Add(1 * 24 * time.Hour)
	due3 := risk.CalculateSLADueDate(domain.SeverityCritical, "critical", start, &earlierKEVDue)
	if !due3.Equal(earlierKEVDue) {
		t.Errorf("expected KEV due date %v to override SLA due date, got %v", earlierKEVDue, due3)
	}
}
