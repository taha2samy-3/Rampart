package zap

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
)

const sampleZapJSON = `{
  "@programName": "ZAP",
  "@version": "2.14.0",
  "site": [
    {
      "@name": "https://test.example.com",
      "@host": "test.example.com",
      "@port": "443",
      "alerts": [
        {
          "pluginId": "40012",
          "alert": "Cross Site Scripting (Reflected)",
          "name": "Cross Site Scripting (Reflected)",
          "riskcode": "3",
          "riskdesc": "High (Medium)",
          "desc": "Cross-site Scripting (XSS) is possible.",
          "solution": "Sanitize all user-provided input.",
          "cweid": "79",
          "instances": [
            {
              "uri": "https://test.example.com/search",
              "method": "GET",
              "param": "q",
              "evidence": "<script>alert(1)</script>"
            }
          ]
        }
      ]
    }
  ]
}`

func TestZapParser(t *testing.T) {
	p := NewParser()

	// 1. Detect
	score := p.Detect([]byte(sampleZapJSON), "zap-report.json", "application/json")
	if score < 80 {
		t.Errorf("detection score = %d, expected >= 80", score)
	}

	// 2. Parse
	var findings []domain.RawFinding
	for f, err := range p.Parse(context.Background(), strings.NewReader(sampleZapJSON), domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "40012" {
		t.Errorf("rule_id = %s", f.RuleID)
	}
	if f.Category != domain.CategoryDAST {
		t.Errorf("category = %s", f.Category)
	}
	if f.Severity != domain.SeverityHigh {
		t.Errorf("severity = %s", f.Severity)
	}
	if f.Location.Web == nil || f.Location.Web.NormalizedURL != "https://test.example.com/search" {
		t.Errorf("web location = %+v", f.Location.Web)
	}
	if f.Location.Web.Parameter != "q" || f.Location.Web.Method != "GET" {
		t.Errorf("web params = %+v", f.Location.Web)
	}
	if len(f.CWEs) != 1 || f.CWEs[0] != 79 {
		t.Errorf("cwes = %+v", f.CWEs)
	}
}
