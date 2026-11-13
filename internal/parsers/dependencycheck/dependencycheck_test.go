package dependencycheck

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
)

const sampleDependencyCheckJSON = `{
  "reportSchema": "1.1",
  "scanInfo": {
    "engineVersion": "8.4.0"
  },
  "dependencies": [
    {
      "fileName": "log4j-core-2.14.1.jar",
      "filePath": "/app/lib/log4j-core-2.14.1.jar",
      "packages": [
        {
          "id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        }
      ],
      "vulnerabilities": [
        {
          "name": "CVE-2021-44228",
          "severity": "CRITICAL",
          "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
          "cvssv3": {
            "baseScore": 10.0,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
          },
          "cwes": [
            "CWE-502",
            "CWE-400"
          ]
        }
      ]
    }
  ]
}`

func TestDependencyCheckParser(t *testing.T) {
	p := NewParser()

	// 1. Detect
	score := p.Detect([]byte(sampleDependencyCheckJSON), "dependency-check-report.json", "application/json")
	if score < 80 {
		t.Errorf("detection score = %d, expected >= 80", score)
	}

	// 2. Parse
	var findings []domain.RawFinding
	for f, err := range p.Parse(context.Background(), strings.NewReader(sampleDependencyCheckJSON), domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CVE-2021-44228" {
		t.Errorf("rule_id = %s", f.RuleID)
	}
	if f.Category != domain.CategorySCA {
		t.Errorf("category = %s", f.Category)
	}
	if f.Severity != domain.SeverityCritical {
		t.Errorf("severity = %s", f.Severity)
	}
	if f.Location.Package == nil || f.Location.Package.Purl != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("package location = %+v", f.Location.Package)
	}
	if len(f.CWEs) != 2 || f.CWEs[0] != 502 || f.CWEs[1] != 400 {
		t.Errorf("cwes = %+v", f.CWEs)
	}
}
