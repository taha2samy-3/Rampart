package lua_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/integrations/lua"
)

func TestLuaParserDetection(t *testing.T) {
	manifest := []byte(`
apiVersion: rampart.aspm.dev/v1alpha1
kind: Parser
metadata:
  name: custom-scanner
spec:
  version: "1.0.0"
  family: custom
  category: sast
  runtime: lua
  detect:
    filenames:
      - "*custom*.json"
    probes:
      - jsonHasKeys: ["custom_scan_id"]
  script: |
    function parse(input, emit)
    end
`)

	p, err := lua.NewLuaParserFromSpec("custom-scanner", manifest)
	if err != nil {
		t.Fatalf("failed to create Lua parser: %v", err)
	}

	// One scale for every parser kind (domain.DetectSpec): a file name adds 50, a probe 60, capped at 100.
	// 1. Both filename and probe match -> 100
	score := p.Detect([]byte(`{"custom_scan_id": "123"}`), "custom-report.json", "application/json")
	if score != 100 {
		t.Errorf("expected score 100, got %d", score)
	}

	// 2. Only filename matches -> 50
	score = p.Detect([]byte(`{"other": "data"}`), "custom-report.json", "application/json")
	if score != 50 {
		t.Errorf("expected score 50, got %d", score)
	}

	// 3. Only probe matches -> 60
	score = p.Detect([]byte(`{"custom_scan_id": "123"}`), "report.json", "application/json")
	if score != 60 {
		t.Errorf("expected score 60, got %d", score)
	}

	// 4. Neither matches -> 0
	score = p.Detect([]byte(`{"other": "data"}`), "report.json", "application/json")
	if score != 0 {
		t.Errorf("expected score 0, got %d", score)
	}
}

func TestLuaParserExecution(t *testing.T) {
	manifest := []byte(`
apiVersion: rampart.aspm.dev/v1alpha1
kind: Parser
metadata:
  name: demo-parser
spec:
  version: "1.0.0"
  family: demo
  category: sast
  runtime: lua
  script: |
    function parse(input, emit)
      local report = json.decode(input)
      for _, issue in ipairs(report.issues) do
        emit({
          rule_id = issue.code,
          title = issue.message,
          severity = "HIGH",
          confidence = "CONFIRMED",
          file = issue.file,
          line = issue.line,
          cve = issue.cve,
          cwes = {89, 79}
        })
      end
    end
`)

	p, err := lua.NewLuaParserFromSpec("demo-parser", manifest)
	if err != nil {
		t.Fatalf("failed to create Lua parser: %v", err)
	}

	inputJSON := `{
		"issues": [
			{"code": "SEC-001", "message": "SQL Injection vulnerability", "file": "db.go", "line": 42, "cve": "CVE-2026-1234"},
			{"code": "SEC-002", "message": "XSS vulnerability", "file": "web.go", "line": 100}
		]
	}`

	ctx := context.Background()
	var findings []domain.RawFinding
	for f, err := range p.Parse(ctx, strings.NewReader(inputJSON), domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("parsing error: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.RuleID != "SEC-001" || f1.Title != "SQL Injection vulnerability" {
		t.Errorf("unexpected finding 1: %+v", f1)
	}
	if f1.Severity != domain.SeverityHigh {
		t.Errorf("unexpected severity: %s", f1.Severity)
	}
	if f1.Location.Code == nil || f1.Location.Code.FilePath != "db.go" || f1.Location.Code.StartLine != 42 {
		t.Errorf("unexpected location: %+v", f1.Location)
	}
	if len(f1.VulnIDs) == 0 || f1.VulnIDs[0] != "CVE-2026-1234" {
		t.Errorf("unexpected VulnIDs: %v", f1.VulnIDs)
	}
	if len(f1.CWEs) != 2 || f1.CWEs[0] != 89 || f1.CWEs[1] != 79 {
		t.Errorf("unexpected CWEs: %v", f1.CWEs)
	}
}
