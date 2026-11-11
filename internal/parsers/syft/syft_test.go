package syft_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/parsers/syft"
)

func TestSyftDetect(t *testing.T) {
	p := syft.NewParser()

	raw := `{"artifacts": [], "artifactRelationships": [], "descriptor": {"name": "syft"}}`
	score := p.Detect([]byte(raw), "report.syft.json", "application/json")
	if score < 80 {
		t.Errorf("expected high score for syft JSON, got %d", score)
	}

	nonSyft := `{"name": "test", "version": "1.0.0"}`
	nonScore := p.Detect([]byte(nonSyft), "package.json", "application/json")
	if nonScore > 20 {
		t.Errorf("expected low score for package.json, got %d", nonScore)
	}
}

func TestSyftParseAndGraph(t *testing.T) {
	syftDoc := `{
		"descriptor": {
			"name": "syft",
			"version": "1.0.1"
		},
		"source": {
			"id": "src-1",
			"name": "ecommerce-api",
			"version": "1.0.0",
			"type": "directory",
			"target": "."
		},
		"artifacts": [
			{
				"id": "art-express",
				"name": "express",
				"version": "4.18.2",
				"type": "npm",
				"purl": "pkg:npm/express@4.18.2",
				"licenses": [
					{
						"value": "MIT",
						"spdxExpression": "MIT"
					}
				]
			},
			{
				"id": "art-debug",
				"name": "debug",
				"version": "2.6.9",
				"type": "npm",
				"purl": "pkg:npm/debug@2.6.9",
				"licenses": [
					{
						"value": "MIT",
						"spdxExpression": "MIT"
					}
				]
			}
		],
		"artifactRelationships": [
			{
				"parent": "ecommerce-api@1.0.0",
				"child": "art-express",
				"type": "depends-on"
			},
			{
				"parent": "art-express",
				"child": "art-debug",
				"type": "depends-on"
			}
		]
	}`

	p := syft.NewParser()

	// 1. Verify Parse iter
	ctx := context.Background()
	parseCtx := domain.ParseContext{
		TenantID:      domain.NewID(),
		ScanSourceID:  domain.NewID(),
		ScannerFamily: "syft",
	}

	var findings []domain.RawFinding
	for f, err := range p.Parse(ctx, strings.NewReader(syftDoc), parseCtx) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 raw findings, got %d", len(findings))
	}
	if findings[0].RuleID != "pkg:npm/express" {
		t.Errorf("expected ruleID 'pkg:npm/express', got %q", findings[0].RuleID)
	}

	// 2. Verify ParseSBOM and DependencyGraph
	sbom, comps, g, err := p.ParseSBOM(strings.NewReader(syftDoc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sbom.RootComponent != "ecommerce-api@1.0.0" {
		t.Errorf("expected root 'ecommerce-api@1.0.0', got %q", sbom.RootComponent)
	}
	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}

	compMap := make(map[string]domain.SBOMComponent)
	for _, c := range comps {
		compMap[c.Name] = c
	}

	if !compMap["express"].Direct {
		t.Errorf("expected express to be direct dependency")
	}
	if compMap["debug"].Direct {
		t.Errorf("expected debug to be transitive dependency")
	}

	// Trace path from root to debug
	path := g.FindShortestPath("pkg:npm/debug@2.6.9")
	if len(path) != 3 {
		t.Fatalf("expected path length 3, got %v", path)
	}
	if path[0] != "ecommerce-api@1.0.0" || path[1] != "pkg:npm/express@4.18.2" || path[2] != "pkg:npm/debug@2.6.9" {
		t.Errorf("unexpected path chain: %v", path)
	}
}
