package cyclonedx_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/parsers/cyclonedx"
)

func TestCycloneDXDetect(t *testing.T) {
	p := cyclonedx.NewParser()

	// JSON
	score := p.Detect([]byte(`{"bomFormat": "CycloneDX", "specVersion": "1.5"}`), "bom.cdx.json", "application/vnd.cyclonedx+json")
	if score < 80 {
		t.Errorf("expected high score for CycloneDX JSON document, got %d", score)
	}

	// XML
	scoreXML := p.Detect([]byte(`<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"></bom>`), "bom.cdx.xml", "application/vnd.cyclonedx+xml")
	if scoreXML < 80 {
		t.Errorf("expected high score for CycloneDX XML document, got %d", scoreXML)
	}

	// Non-CycloneDX
	scoreNon := p.Detect([]byte(`{"name": "package.json"}`), "package.json", "application/json")
	if scoreNon > 20 {
		t.Errorf("expected low score for non-CycloneDX, got %d", scoreNon)
	}
}

func TestCycloneDXParseJSON(t *testing.T) {
	f, err := os.Open("testdata/sample.cdx.json")
	if err != nil {
		t.Fatalf("failed to open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	p := cyclonedx.NewParser()
	ctx := context.Background()
	parseCtx := domain.ParseContext{
		TenantID:      domain.NewID(),
		ScanSourceID:  domain.NewID(),
		ScannerFamily: "cyclonedx",
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
	if rf.RuleID != "CVE-2020-28168" {
		t.Errorf("expected rule ID 'CVE-2020-28168', got %q", rf.RuleID)
	}
	if rf.Severity != domain.SeverityHigh {
		t.Errorf("expected severity 'high', got %q", rf.Severity)
	}
	if len(rf.CWEs) != 1 || rf.CWEs[0] != 918 {
		t.Errorf("expected CWE-918, got %v", rf.CWEs)
	}
	if rf.Location.Package == nil || rf.Location.Package.PurlBase != "pkg:npm/axios" {
		t.Errorf("expected purlBase 'pkg:npm/axios', got %v", rf.Location.Package)
	}

	// Also verify component extraction
	_, _ = f.Seek(0, 0)
	components, err := p.ParseComponents(f)
	if err != nil {
		t.Fatalf("failed to parse components: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	if components[0].Name != "axios" || components[0].PurlBase != "pkg:npm/axios" {
		t.Errorf("unexpected component: %+v", components[0])
	}
}

func TestCycloneDXParseXML(t *testing.T) {
	f, err := os.Open("testdata/sample.cdx.xml")
	if err != nil {
		t.Fatalf("failed to open XML fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	p := cyclonedx.NewParser()
	ctx := context.Background()
	parseCtx := domain.ParseContext{
		TenantID:      domain.NewID(),
		ScanSourceID:  domain.NewID(),
		ScannerFamily: "cyclonedx",
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
		t.Fatalf("expected 1 finding from XML, got %d", len(results))
	}

	rf := results[0]
	if rf.RuleID != "CVE-2021-44228" {
		t.Errorf("expected rule ID 'CVE-2021-44228', got %q", rf.RuleID)
	}
	if rf.Severity != domain.SeverityCritical {
		t.Errorf("expected critical severity, got %q", rf.Severity)
	}
	if len(rf.CWEs) != 1 || rf.CWEs[0] != 502 {
		t.Errorf("expected CWE-502, got %v", rf.CWEs)
	}
	if rf.Location.Package == nil || !strings.Contains(rf.Location.Package.Purl, "log4j-core") {
		t.Errorf("expected log4j-core package location, got %v", rf.Location.Package)
	}

	// Verify XML component extraction
	_, _ = f.Seek(0, 0)
	components, err := p.ParseComponents(f)
	if err != nil {
		t.Fatalf("failed to parse XML components: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	comp := components[0]
	if comp.Name != "log4j-core" || comp.Version != "2.14.1" {
		t.Errorf("unexpected XML component: %+v", comp)
	}
	if len(comp.Licenses) == 0 || comp.Licenses[0] != "Apache-2.0" {
		t.Errorf("expected Apache-2.0 license, got %v", comp.Licenses)
	}
	if len(comp.Hashes) == 0 || comp.Hashes["sha-256"] == "" {
		t.Errorf("expected sha-256 hash, got %v", comp.Hashes)
	}
}

func TestCycloneDXDependencyGraphJSON(t *testing.T) {
	cdxDoc := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"component": {
				"bom-ref": "pkg:npm/my-app@1.0.0",
				"name": "my-app",
				"version": "1.0.0",
				"purl": "pkg:npm/my-app@1.0.0"
			}
		},
		"components": [
			{
				"bom-ref": "pkg:npm/express@4.18.2",
				"name": "express",
				"version": "4.18.2",
				"purl": "pkg:npm/express@4.18.2"
			},
			{
				"bom-ref": "pkg:npm/debug@2.6.9",
				"name": "debug",
				"version": "2.6.9",
				"purl": "pkg:npm/debug@2.6.9"
			},
			{
				"bom-ref": "pkg:npm/ms@2.0.0",
				"name": "ms",
				"version": "2.0.0",
				"purl": "pkg:npm/ms@2.0.0"
			}
		],
		"dependencies": [
			{
				"ref": "pkg:npm/my-app@1.0.0",
				"dependsOn": [
					"pkg:npm/express@4.18.2"
				]
			},
			{
				"ref": "pkg:npm/express@4.18.2",
				"dependsOn": [
					"pkg:npm/debug@2.6.9"
				]
			},
			{
				"ref": "pkg:npm/debug@2.6.9",
				"dependsOn": [
					"pkg:npm/ms@2.0.0"
				]
			}
		]
	}`

	p := cyclonedx.NewParser()
	sbom, comps, g, err := p.ParseSBOM(strings.NewReader(cdxDoc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sbom.RootComponent != "pkg:npm/my-app@1.0.0" {
		t.Errorf("expected root component 'pkg:npm/my-app@1.0.0', got %q", sbom.RootComponent)
	}

	if len(sbom.Dependencies) != 3 {
		t.Errorf("expected 3 dependency edges, got %d", len(sbom.Dependencies))
	}

	// express should be direct
	// debug and ms should be transitive
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
	if compMap["ms"].Direct {
		t.Errorf("expected ms to be transitive dependency")
	}

	// Verify shortest path tracing from root to ms
	path := g.FindShortestPath("pkg:npm/ms@2.0.0")
	if len(path) != 4 {
		t.Fatalf("expected path length 4 (my-app -> express -> debug -> ms), got %v", path)
	}
	if path[0] != "pkg:npm/my-app@1.0.0" || path[3] != "pkg:npm/ms@2.0.0" {
		t.Errorf("unexpected path chain: %v", path)
	}

	// Verify Mermaid output
	mermaid := g.RenderMermaid()
	if !strings.Contains(mermaid, "flowchart TD") || !strings.Contains(mermaid, "express@4.18.2") {
		t.Errorf("invalid mermaid output: %s", mermaid)
	}

	// Verify Tree output
	tree := g.RenderTextTree()
	if !strings.Contains(tree, "express@4.18.2") || !strings.Contains(tree, "ms@2.0.0") {
		t.Errorf("invalid tree output: %s", tree)
	}
}

func TestCycloneDXDependencyGraphXML(t *testing.T) {
	cdxXML := `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <metadata>
    <component bom-ref="pkg:maven/com.example/core-app@1.0.0">
      <name>core-app</name>
      <version>1.0.0</version>
    </component>
  </metadata>
  <components>
    <component bom-ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1">
      <name>log4j-core</name>
      <version>2.14.1</version>
    </component>
    <component bom-ref="pkg:maven/com.lmax/disruptor@3.4.4">
      <name>disruptor</name>
      <version>3.4.4</version>
    </component>
  </components>
  <dependencies>
    <dependency ref="pkg:maven/com.example/core-app@1.0.0">
      <dependency ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" />
    </dependency>
    <dependency ref="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1">
      <dependency ref="pkg:maven/com.lmax/disruptor@3.4.4" />
    </dependency>
  </dependencies>
</bom>`

	p := cyclonedx.NewParser()
	sbom, comps, g, err := p.ParseSBOM(strings.NewReader(cdxXML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sbom.RootComponent != "pkg:maven/com.example/core-app@1.0.0" {
		t.Errorf("expected root 'core-app', got %q", sbom.RootComponent)
	}
	if len(sbom.Dependencies) != 2 {
		t.Errorf("expected 2 dependency edges, got %d", len(sbom.Dependencies))
	}

	compMap := make(map[string]domain.SBOMComponent)
	for _, c := range comps {
		compMap[c.Name] = c
	}

	if !compMap["log4j-core"].Direct {
		t.Errorf("expected log4j-core to be direct dependency")
	}
	if compMap["disruptor"].Direct {
		t.Errorf("expected disruptor to be transitive dependency")
	}

	path := g.FindShortestPath("pkg:maven/com.lmax/disruptor@3.4.4")
	if len(path) != 3 {
		t.Fatalf("expected path length 3, got %v", path)
	}
}
