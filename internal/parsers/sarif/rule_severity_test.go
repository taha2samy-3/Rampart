package sarif_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/parsers/sarif"
)

// security-severity lives on the rule in CodeQL, Semgrep and Trivy output, not on each result.
func TestSecuritySeverityOnTheRule(t *testing.T) {
	const doc = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[
	  {"id":"r.crit","properties":{"security-severity":"9.5"}},
	  {"id":"r.high","properties":{"security-severity":7.2}},
	  {"id":"r.low","properties":{"security-severity":"2.0"}},
	  {"id":"r.own","properties":{"security-severity":"1.0"}}]}},
	"results":[
	  {"ruleId":"r.crit","level":"warning","message":{"text":"a"}},
	  {"ruleId":"r.high","level":"note","message":{"text":"b"}},
	  {"ruleId":"r.low","level":"error","message":{"text":"c"}},
	  {"ruleId":"r.own","level":"error","message":{"text":"d"},"properties":{"security-severity":"9.1"}}]}]}`
	got := map[string]domain.Severity{}
	for f, err := range sarif.NewParser().Parse(context.Background(), strings.NewReader(doc), domain.ParseContext{}) {
		if err != nil {
			t.Fatal(err)
		}
		got[f.RuleID] = f.Severity
	}
	want := map[string]domain.Severity{"r.crit": domain.SeverityCritical, "r.high": domain.SeverityHigh, "r.low": domain.SeverityLow, "r.own": domain.SeverityCritical}
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("%s: severity %q, want %q", id, got[id], sev)
		}
	}
}
