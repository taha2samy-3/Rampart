package openvex_test

import (
	"context"
	"os"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/parsers/openvex"
)

func TestOpenVEXDetect(t *testing.T) {
	p := openvex.NewParser()

	score := p.Detect([]byte(`{"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}`), "sample.vex.json", "application/openvex+json")
	if score < 80 {
		t.Errorf("expected high score for OpenVEX, got %d", score)
	}

	scoreNon := p.Detect([]byte(`{"name": "package.json"}`), "package.json", "application/json")
	if scoreNon > 20 {
		t.Errorf("expected low score for non-OpenVEX, got %d", scoreNon)
	}
}

func TestOpenVEXParse(t *testing.T) {
	f, err := os.Open("testdata/sample.vex.json")
	if err != nil {
		t.Fatalf("failed to open OpenVEX fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	p := openvex.NewParser()
	ctx := context.Background()
	parseCtx := domain.ParseContext{
		TenantID:      domain.NewID(),
		ScanSourceID:  domain.NewID(),
		ScannerFamily: "openvex",
		Track:         "main",
	}

	var results []domain.RawFinding
	for finding, err := range p.Parse(ctx, f, parseCtx) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		results = append(results, finding)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	rf := results[0]
	if rf.RuleID != "CVE-2021-44228" {
		t.Errorf("expected rule ID 'CVE-2021-44228', got %q", rf.RuleID)
	}
	if rf.VEX == nil {
		t.Fatalf("expected VEX statement to be present")
	}
	if rf.VEX.State != domain.StateNotAffected {
		t.Errorf("expected state 'not_affected', got %q", rf.VEX.State)
	}
	if rf.VEX.Justification != "vulnerable_code_not_present" {
		t.Errorf("expected justification 'vulnerable_code_not_present', got %q", rf.VEX.Justification)
	}
}
