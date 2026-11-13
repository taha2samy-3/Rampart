package bandit

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
)

const sampleBanditJSON = `{
  "errors": [],
  "generated_at": "2026-11-13T10:00:00Z",
  "metrics": {},
  "results": [
    {
      "code": "12 def exec_code(user_input):\n13     eval(user_input)\n",
      "filename": "app/vuln.py",
      "issue_confidence": "HIGH",
      "issue_cwe": {
        "id": 95,
        "url": "https://cwe.mitre.org/data/definitions/95.html"
      },
      "issue_severity": "HIGH",
      "issue_text": "Use of possibly insecure function - consider using safer alternatives.",
      "line_number": 13,
      "line_range": [13],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b307_eval.html",
      "test_id": "B307",
      "test_name": "blacklist"
    }
  ]
}`

func TestBanditParser(t *testing.T) {
	p := NewParser()

	// 1. Detect
	score := p.Detect([]byte(sampleBanditJSON), "bandit.json", "application/json")
	if score < 80 {
		t.Errorf("detection score = %d, expected >= 80", score)
	}

	// 2. Parse
	var findings []domain.RawFinding
	for f, err := range p.Parse(context.Background(), strings.NewReader(sampleBanditJSON), domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "B307" {
		t.Errorf("rule_id = %s", f.RuleID)
	}
	if f.Category != domain.CategorySAST {
		t.Errorf("category = %s", f.Category)
	}
	if f.Severity != domain.SeverityHigh {
		t.Errorf("severity = %s", f.Severity)
	}
	if f.Location.Code == nil || f.Location.Code.FilePath != "app/vuln.py" || f.Location.Code.StartLine != 13 {
		t.Errorf("location code = %+v", f.Location.Code)
	}
	if len(f.CWEs) != 1 || f.CWEs[0] != 95 {
		t.Errorf("cwes = %+v", f.CWEs)
	}
}
