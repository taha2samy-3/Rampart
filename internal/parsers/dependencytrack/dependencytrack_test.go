package dependencytrack_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/parsers/dependencytrack"
)

func parse(t *testing.T, doc string, pc domain.ParseContext) ([]domain.RawFinding, error) {
	t.Helper()
	var out []domain.RawFinding
	for rf, err := range dependencytrack.NewParser().Parse(context.Background(), strings.NewReader(doc), pc) {
		if err != nil {
			return out, err
		}
		out = append(out, rf)
	}
	return out, nil
}

func fixtureFPF(t *testing.T) string {
	b, err := os.ReadFile("testdata/findings.fpf.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func fixtureArray(t *testing.T) string {
	b, err := os.ReadFile("testdata/findings_array.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDetect(t *testing.T) {
	p := dependencytrack.NewParser()

	// High confidence on FPF file
	if s := p.Detect([]byte(fixtureFPF(t)), "findings-320e8a71.fpf", "application/json"); s < 80 {
		t.Fatalf("FPF report must be recognized with high score, got %d", s)
	}

	// Good score on direct array with component & vulnerability
	if s := p.Detect([]byte(fixtureArray(t)), "findings.json", "application/json"); s < 50 {
		t.Fatalf("direct findings array must be recognized, got %d", s)
	}

	// Negative checks: other formats must score 0 or low
	for name, other := range map[string]string{
		"sarif":     `{"version":"2.1.0","runs":[{"results":[]}]}`,
		"cyclonedx": `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`,
		"spdx":      `{"spdxVersion":"SPDX-2.3","name":"sample"}`,
		"empty":     `{}`,
	} {
		if s := p.Detect([]byte(other), "report.json", ""); s > 30 {
			t.Errorf("%s scored unexpectedly high: %d", name, s)
		}
	}
}

func TestParse_FPFExport(t *testing.T) {
	findings, err := parse(t, fixtureFPF(t), domain.ParseContext{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// 1. Log4j finding
	f0 := findings[0]
	if f0.ScannerFamily != "dependency-track" {
		t.Errorf("scanner family = %q, want dependency-track", f0.ScannerFamily)
	}
	if f0.Category != domain.CategorySCA {
		t.Errorf("category = %q, want sca", f0.Category)
	}
	if f0.RuleID != "CVE-2021-44228" {
		t.Errorf("rule id = %q, want CVE-2021-44228", f0.RuleID)
	}
	if len(f0.VulnIDs) != 2 || f0.VulnIDs[0] != "CVE-2021-44228" || f0.VulnIDs[1] != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("vuln ids = %v, want [CVE-2021-44228, GHSA-jfh8-c2jp-5v3q]", f0.VulnIDs)
	}
	if f0.Severity != domain.SeverityCritical {
		t.Errorf("severity = %v, want Critical", f0.Severity)
	}
	if f0.ToolRecordID != "320e8a71-6a2c-4903-8d07-2a6c117b34b6:4c278fb1-e214-43ff-90a6-1215b2e3a1f8:f5835b3d-b452-4a00-bca4-d13ebbf00f40" {
		t.Errorf("tool record id = %q", f0.ToolRecordID)
	}
	if f0.Location.Package == nil {
		t.Fatal("expected package location")
	}
	if f0.Location.Package.PurlBase != "pkg:maven/org.apache.logging.log4j/log4j-core" {
		t.Errorf("purl base = %q", f0.Location.Package.PurlBase)
	}
	if f0.Location.Package.InstalledVersion != "2.14.1" {
		t.Errorf("installed version = %q", f0.Location.Package.InstalledVersion)
	}
	if len(f0.CWEs) != 1 || f0.CWEs[0] != 502 {
		t.Errorf("cwes = %v, want [502]", f0.CWEs)
	}
	if f0.VEX == nil {
		t.Fatal("expected VEX statement")
	}
	if f0.VEX.State != domain.StateNotAffected {
		t.Errorf("vex state = %v, want not_affected", f0.VEX.State)
	}
	if f0.VEX.Justification != "vulnerable_code_not_present" {
		t.Errorf("vex justification = %q, want vulnerable_code_not_present", f0.VEX.Justification)
	}

	// 2. Lodash finding
	f1 := findings[1]
	if f1.RuleID != "CVE-2021-23337" {
		t.Errorf("rule id = %q, want CVE-2021-23337", f1.RuleID)
	}
	if f1.Severity != domain.SeverityHigh {
		t.Errorf("severity = %v, want High", f1.Severity)
	}
	if f1.VEX == nil || f1.VEX.State != domain.StateAffected {
		t.Errorf("vex state = %v, want affected", f1.VEX)
	}

	// 3. Unassigned finding
	f2 := findings[2]
	if f2.Severity != domain.SeverityInfo {
		t.Errorf("unassigned severity should map to Info, got %v", f2.Severity)
	}
	if f2.VEX == nil || f2.VEX.State != domain.StateRiskAccepted {
		t.Errorf("isSuppressed without state should map to risk_accepted, got %v", f2.VEX)
	}
}

func TestParse_DirectArray(t *testing.T) {
	findings, err := parse(t, fixtureArray(t), domain.ParseContext{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "CVE-2021-44228" {
		t.Errorf("rule id = %q, want CVE-2021-44228", findings[0].RuleID)
	}
}

func TestParse_RecordErrors(t *testing.T) {
	doc := `{
		"findings": [
			{"component": "not an object"},
			{
				"component": {"name": "valid-pkg", "purl": "pkg:npm/valid-pkg@1.0.0"},
				"vulnerability": {"vulnId": "CVE-2026-0001", "severity": "LOW"}
			}
		]
	}`

	var recordErrors []domain.RecordError
	pc := domain.ParseContext{
		RecordError: func(re domain.RecordError) {
			recordErrors = append(recordErrors, re)
		},
	}

	findings, err := parse(t, doc, pc)
	if err != nil {
		t.Fatalf("unexpected parse failure with error handler: %v", err)
	}

	if len(recordErrors) != 1 {
		t.Fatalf("expected 1 record error, got %d", len(recordErrors))
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 successful finding, got %d", len(findings))
	}
	if findings[0].RuleID != "CVE-2026-0001" {
		t.Errorf("expected finding CVE-2026-0001, got %s", findings[0].RuleID)
	}
}
