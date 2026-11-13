package snyk

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
)

const sampleSnykJSON = `{
  "ok": false,
  "packageManager": "npm",
  "vulnerabilities": [
    {
      "id": "SNYK-JS-LODASH-567746",
      "title": "Prototype Pollution",
      "description": "Prototype Pollution in lodash",
      "severity": "high",
      "packageName": "lodash",
      "version": "4.17.15",
      "fixedIn": ["4.17.21"],
      "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
      "cvssScore": 7.5,
      "identifiers": {
        "CVE": ["CVE-2020-8203"],
        "CWE": ["CWE-1321"]
      },
      "from": ["my-app@1.0.0", "lodash@4.17.15"]
    }
  ]
}`

func TestSnykParser(t *testing.T) {
	p := NewParser()

	// 1. Detect
	score := p.Detect([]byte(sampleSnykJSON), "snyk.json", "application/json")
	if score < 80 {
		t.Errorf("detection score = %d, expected >= 80", score)
	}

	// 2. Parse
	var findings []domain.RawFinding
	for f, err := range p.Parse(context.Background(), strings.NewReader(sampleSnykJSON), domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "SNYK-JS-LODASH-567746" {
		t.Errorf("rule_id = %s", f.RuleID)
	}
	if f.Category != domain.CategorySCA {
		t.Errorf("category = %s", f.Category)
	}
	if f.Severity != domain.SeverityHigh {
		t.Errorf("severity = %s", f.Severity)
	}
	if f.Location.Package == nil || f.Location.Package.ComponentName != "lodash" || f.Location.Package.InstalledVersion != "4.17.15" {
		t.Errorf("package location = %+v", f.Location.Package)
	}
	if f.Location.Package.FixedVersion != "4.17.21" {
		t.Errorf("fixed version = %s", f.Location.Package.FixedVersion)
	}
	if len(f.CWEs) != 1 || f.CWEs[0] != 1321 {
		t.Errorf("cwes = %+v", f.CWEs)
	}
	if len(f.VulnIDs) != 1 || f.VulnIDs[0] != "CVE-2020-8203" {
		t.Errorf("vuln_ids = %+v", f.VulnIDs)
	}
}
