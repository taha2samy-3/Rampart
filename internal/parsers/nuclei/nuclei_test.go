package nuclei

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
)

const sampleNucleiJSONL = `{"template-id":"cve-2023-24489","info":{"name":"Citrix ADC and Gateway - Unauthenticated Remote Code Execution","author":["princechaddha"],"severity":"critical","description":"Citrix Gateway and Citrix ADC contain an unauthenticated remote code execution vulnerability.","classification":{"cwe-id":["cwe-287"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cvss-score":9.8}},"type":"http","host":"https://vpn.example.com","matched-at":"https://vpn.example.com/oauth/idp/.well-known/openid-configuration","ip":"192.0.2.1"}
{"template-id":"git-config-disclosure","info":{"name":".git/config Disclosure","severity":"medium","description":".git/config was detected exposed."},"type":"http","host":"https://app.example.com","matched-at":"https://app.example.com/.git/config"}`

func TestNucleiParser(t *testing.T) {
	p := NewParser()

	// 1. Detect
	score := p.Detect([]byte(sampleNucleiJSONL), "nuclei-results.jsonl", "application/x-ndjson")
	if score < 80 {
		t.Errorf("detection score = %d, expected >= 80", score)
	}

	// 2. Parse
	var findings []domain.RawFinding
	for f, err := range p.Parse(context.Background(), strings.NewReader(sampleNucleiJSONL), domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.RuleID != "cve-2023-24489" {
		t.Errorf("rule_id = %s", f1.RuleID)
	}
	if f1.Category != domain.CategoryDAST {
		t.Errorf("category = %s", f1.Category)
	}
	if f1.Severity != domain.SeverityCritical {
		t.Errorf("severity = %s", f1.Severity)
	}
	if f1.Location.Web == nil || f1.Location.Web.NormalizedURL != "https://vpn.example.com/oauth/idp/.well-known/openid-configuration" {
		t.Errorf("web location = %+v", f1.Location.Web)
	}
	if len(f1.CWEs) != 1 || f1.CWEs[0] != 287 {
		t.Errorf("cwes = %+v", f1.CWEs)
	}
}
