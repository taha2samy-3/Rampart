package risk_test

import (
	"errors"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/risk"
)

func names(b risk.ScoreBreakdown) map[string]int {
	out := map[string]int{}
	for _, f := range b.Factors {
		out[f.Name] = f.Points
	}
	return out
}

// The built-in policy as data gives the numbers the code gave before D62 (docs/06 section 2).
func TestBuiltinPolicyKeepsTheNumbers(t *testing.T) {
	p := risk.Builtin()
	// High (400) + KEV 300 + EPSS >= 0.5 150 + internet 100 + critical app 100 + production 60 = 1110, clamped.
	b := p.Evaluate(risk.Input{
		Finding: risk.FindingInput{Severity: "high", Category: "sca", Track: "production"},
		Vuln:    risk.VulnInput{ID: "CVE-2021-44228", KEV: true, EPSS: 0.95},
		App:     risk.AppInput{Criticality: "critical", InternetFacing: true},
	})
	if b.TotalScore != 1000 || b.Band != domain.SeverityCritical || !b.HasKEV || b.EPSSScore != 0.95 {
		t.Fatalf("%+v", b)
	}
	want := map[string]int{"KEV": 300, "EPSS_HIGH": 150, "INTERNET_FACING": 100, "APP_CRITICAL": 100, "PRODUCTION_ENV": 60}
	got := names(b)
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: %d, want %d (%v)", k, got[k], v, got)
		}
	}
	// Each base and band boundary as before: medium 200, unknown severity weighs as low (80), info 10.
	for sev, base := range map[string]int{"critical": 600, "medium": 200, "low": 80, "info": 10, "unknown": 80} {
		if b := p.Evaluate(risk.Input{Finding: risk.FindingInput{Severity: sev}}); b.TotalScore != base {
			t.Fatalf("%s: %d, want %d", sev, b.TotalScore, base)
		}
	}
	// EPSS 10-50 % adds 60; sensitive data 80; a WAF lowers a DAST finding by 80 and nothing else (D55).
	if b := p.Evaluate(risk.Input{Finding: risk.FindingInput{Severity: "medium"}, Vuln: risk.VulnInput{EPSS: 0.2}}); b.TotalScore != 260 {
		t.Fatalf("EPSS moderate: %d", b.TotalScore)
	}
	app := risk.AppInput{DataClassification: []string{"pii"}, CompensatingControls: []string{"waf"}}
	if b := p.Evaluate(risk.Input{Finding: risk.FindingInput{Severity: "high", Category: "dast"}, App: app}); b.TotalScore != 400 {
		t.Fatalf("dast with pii and a WAF: %d (400 + 80 - 80)", b.TotalScore)
	}
	if b := p.Evaluate(risk.Input{Finding: risk.FindingInput{Severity: "high", Category: "sast"}, App: app}); b.TotalScore != 480 {
		t.Fatalf("sast with pii and a WAF: %d (the WAF does not count)", b.TotalScore)
	}
	// Bands: 800 critical, 600 high, 300 medium.
	if b := p.Evaluate(risk.Input{Finding: risk.FindingInput{Severity: "critical"}}); b.Band != domain.SeverityHigh {
		t.Fatalf("600 is high: %s", b.Band)
	}
	// Every factor carries its group for the score bar (docs/13 section 6).
	for _, f := range p.Evaluate(risk.Input{Finding: risk.FindingInput{Severity: "high", Category: "dast"}, App: risk.AppInput{CompensatingControls: []string{"waf"}}}).Factors {
		if f.Group == "" {
			t.Fatalf("%s has no group", f.Name)
		}
	}
}

// A policy's own factors, base and bands; and what is refused, with the reason (D62).
func TestCompileRiskPolicy(t *testing.T) {
	p, err := risk.ParseRiskPolicySpec([]byte(`{
		"base": {"critical": 700},
		"factors": [
			{"name": "payments-scope", "when": "app.data_classification.exists(d, d == \"pci\") && finding.category == \"sca\"", "points": 200, "group": "context"},
			{"name": "injection", "when": "finding.cwes.exists(c, c == 89)", "points": 50},
			{"name": "test-code", "when": "finding.rule_id.startsWith(\"test.\")", "points": -150}
		],
		"bands": {"critical": 900}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	b := p.Evaluate(risk.Input{
		Finding: risk.FindingInput{Severity: "critical", Category: "sca", CWEs: []int{89}},
		App:     risk.AppInput{DataClassification: []string{"pci"}},
	})
	if b.TotalScore != 950 || b.Band != domain.SeverityCritical || len(b.Factors) != 2 {
		t.Fatalf("%+v", b)
	}
	if b := p.Evaluate(risk.Input{Finding: risk.FindingInput{Severity: "critical", RuleID: "test.x"}}); b.TotalScore != 550 || b.Factors[0].Group != "reduction" {
		t.Fatalf("a negative factor: %+v", b)
	}
	// A policy with factors replaces the built-in factors; one without keeps them.
	if p2, _ := risk.ParseRiskPolicySpec([]byte(`{"base": {"high": 300}}`)); len(p2.Evaluate(risk.Input{Finding: risk.FindingInput{Severity: "high"}, Vuln: risk.VulnInput{KEV: true}}).Factors) != 1 {
		t.Fatal("a spec without factors keeps the built-in ones")
	}

	refused := map[string]string{
		"a misspelt field":      `{"factors": [{"name": "x", "when": "app.critcality == \"high\"", "points": 10}]}`,
		"not a condition":       `{"factors": [{"name": "x", "when": "finding.cwes", "points": 10}]}`,
		"a syntax error":        `{"factors": [{"name": "x", "when": "vuln.kev &&", "points": 10}]}`,
		"an unknown variable":   `{"factors": [{"name": "x", "when": "now > 0", "points": 10}]}`,
		"zero points":           `{"factors": [{"name": "x", "when": "vuln.kev", "points": 0}]}`,
		"a duplicate name":      `{"factors": [{"name": "x", "when": "vuln.kev", "points": 1}, {"name": "x", "when": "vuln.kev", "points": 2}]}`,
		"bands out of order":    `{"bands": {"high": 900}}`,
		"an unknown severity":   `{"base": {"urgent": 900}}`,
		"an unknown spec field": `{"weights": {}}`,
		"an unknown group":      `{"factors": [{"name": "x", "when": "vuln.kev", "points": 1, "group": "bonus"}]}`,
		"too expensive":         `{"factors": [{"name": "x", "when": "[1,2,3,4,5,6,7,8,9,10].all(a, [1,2,3,4,5,6,7,8,9,10].all(b, [1,2,3,4,5,6,7,8,9,10].all(c, a + b + c > 0)))", "points": 1}]}`,
	}
	for why, spec := range refused {
		if _, err := risk.ParseRiskPolicySpec([]byte(spec)); !errors.Is(err, risk.ErrPolicy) {
			t.Fatalf("%s: accepted (%v)", why, err)
		}
	}
	if _, err := risk.ParseRiskPolicySpec([]byte(`{"factors": [{"name": "x", "when": "app.critcality == \"high\"", "points": 10}]}`)); !strings.Contains(err.Error(), "app.criticality") {
		t.Fatalf("the error should list the fields: %v", err)
	}
}
