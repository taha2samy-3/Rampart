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

// D88: exploitation reported outside CISA KEV, and a weaponized exploit, raise the built-in score; KEV is not counted twice.
func TestBuiltinExploitationFactors(t *testing.T) {
	p := risk.Builtin()
	base := p.Evaluate(risk.Input{Finding: risk.FindingInput{Severity: "high"}}).TotalScore
	ex := p.Evaluate(risk.Input{Finding: risk.FindingInput{Severity: "high"}, Vuln: risk.VulnInput{Exploited: true, ExploitMaturity: "weaponized"}}).TotalScore
	if ex != base+300+120 {
		t.Fatalf("exploited and weaponized: %d, want %d", ex, base+420)
	}
	kev := p.Evaluate(risk.Input{Finding: risk.FindingInput{Severity: "high"}, Vuln: risk.VulnInput{KEV: true, Exploited: true}}).TotalScore
	if kev != base+300 {
		t.Fatalf("KEV and another source reporting the same exploitation count once: %d", kev)
	}
}

// The environment of an application is a fact the score reads (D140). The built-in production factor applies to a finding found on
// a production branch (as before) and to any finding of an application whose environment is production; an application that says
// nothing gets no points, so no score of an existing application moves.
func TestBuiltin_ProductionEnvironmentFromTheApplication(t *testing.T) {
	p := risk.Builtin()
	base := risk.Input{Finding: risk.FindingInput{Severity: "high", Category: "sca", Track: "main"}, App: risk.AppInput{Criticality: "medium"}}
	if got := p.Evaluate(base).TotalScore; got != 400 {
		t.Fatalf("nothing said: %d", got)
	}
	prod := base
	prod.App.Environment = "production"
	if got := p.Evaluate(prod).TotalScore; got != 460 {
		t.Fatalf("environment production: %d", got)
	}
	dev := base
	dev.App.Environment = "development"
	if got := p.Evaluate(dev).TotalScore; got != 400 {
		t.Fatalf("development takes no points: %d", got)
	}
	onTrack := base
	onTrack.Finding.Track = "production"
	if got := p.Evaluate(onTrack).TotalScore; got != 460 {
		t.Fatalf("the branch rule still works: %d", got)
	}
	both := onTrack
	both.App.Environment = "production"
	if got := p.Evaluate(both).TotalScore; got != 460 {
		t.Fatalf("the two do not add up: %d", got)
	}
}

// A tenant's own policy can read app.type and app.environment, and a misspelled one is refused when the policy is applied.
func TestPolicy_ReadsTypeAndEnvironment(t *testing.T) {
	good := []byte(`{"factors":[{"name":"STAGING","when":"app.environment == \"staging\" && app.type == \"repo\"","points":-40,"group":"reduction"}]}`)
	p, err := risk.ParseRiskPolicySpec(good)
	if err != nil {
		t.Fatal(err)
	}
	in := risk.Input{Finding: risk.FindingInput{Severity: "high"}, App: risk.AppInput{Type: "repo", Environment: "staging"}}
	if got := p.Evaluate(in).TotalScore; got != 360 {
		t.Fatalf("got %d, want 360", got)
	}
	if _, err := risk.ParseRiskPolicySpec([]byte(`{"factors":[{"name":"X","when":"app.enviroment == \"staging\"","points":1}]}`)); err == nil {
		t.Fatal("a misspelled variable must be refused")
	}
}

// Enterprise custom scoring with dynamic attributes on app and safe attr() lookup.
func TestPolicy_DynamicAttributes(t *testing.T) {
	custom := []byte(`{
		"base": {"critical": 600, "high": 400},
		"factors": [
			{"name": "AIR_GAPPED_VPN", "when": "attr(app, 'has_vpn', false) == true", "points": -150, "group": "reduction", "reason": "App behind internal VPN"},
			{"name": "DMZ_TIER", "when": "attr(app.attributes, 'network_tier', 'internal') == 'dmz'", "points": 100, "group": "context", "reason": "App placed in DMZ network tier"}
		]
	}`)
	p, err := risk.ParseRiskPolicySpec(custom)
	if err != nil {
		t.Fatalf("custom policy compilation failed: %v", err)
	}

	// 1. App with has_vpn = true and network_tier = "dmz"
	inMatch := risk.Input{
		Finding: risk.FindingInput{Severity: "high"},
		App: risk.AppInput{
			Attributes: map[string]any{
				"has_vpn":      true,
				"network_tier": "dmz",
			},
		},
	}
	// Base (400) - 150 (AIR_GAPPED_VPN) + 100 (DMZ_TIER) = 350
	b := p.Evaluate(inMatch)
	if b.TotalScore != 350 {
		t.Fatalf("expected 350, got %d (factors: %+v)", b.TotalScore, b.Factors)
	}
	if len(b.Factors) != 2 {
		t.Fatalf("expected 2 factors, got %d", len(b.Factors))
	}

	// 2. App with empty attributes: safe evaluation, no panic, no factors match
	inEmpty := risk.Input{
		Finding: risk.FindingInput{Severity: "high"},
		App:     risk.AppInput{},
	}
	bEmpty := p.Evaluate(inEmpty)
	if bEmpty.TotalScore != 400 {
		t.Fatalf("expected 400, got %d", bEmpty.TotalScore)
	}
	if len(bEmpty.Factors) != 0 {
		t.Fatalf("expected 0 factors, got %d", len(bEmpty.Factors))
	}
	if len(bEmpty.Errors) != 0 {
		t.Fatalf("expected 0 errors, got %+v", bEmpty.Errors)
	}
}
