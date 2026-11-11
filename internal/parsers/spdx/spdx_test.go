package spdx_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/parsers/spdx"
)

func TestSPDXDetect(t *testing.T) {
	p := spdx.NewParser()

	// JSON
	scoreJSON := p.Detect([]byte(`{"spdxVersion": "SPDX-2.3"}`), "bom.spdx.json", "application/spdx+json")
	if scoreJSON < 80 {
		t.Errorf("expected high score for SPDX JSON, got %d", scoreJSON)
	}

	// Tag-Value
	scoreTV := p.Detect([]byte("SPDXVersion: SPDX-2.3\nPackageName: foo"), "bom.spdx", "text/plain")
	if scoreTV < 80 {
		t.Errorf("expected high score for SPDX Tag-Value, got %d", scoreTV)
	}

	// Non-SPDX
	scoreNon := p.Detect([]byte(`{"name": "package.json"}`), "package.json", "application/json")
	if scoreNon > 20 {
		t.Errorf("expected low score for non-SPDX, got %d", scoreNon)
	}
}

func TestSPDXParseJSON(t *testing.T) {
	f, err := os.Open("testdata/sample.spdx.json")
	if err != nil {
		t.Fatalf("failed to open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	p := spdx.NewParser()
	ctx := context.Background()
	parseCtx := domain.ParseContext{
		TenantID:      domain.NewID(),
		ScanSourceID:  domain.NewID(),
		ScannerFamily: "spdx",
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
	if rf.RuleID != "pkg:golang/github.com/golang-jwt/jwt/v5" {
		t.Errorf("expected rule ID 'pkg:golang/github.com/golang-jwt/jwt/v5', got %q", rf.RuleID)
	}
	if rf.Severity != domain.SeverityInfo {
		t.Errorf("expected severity 'info', got %q", rf.Severity)
	}
	if rf.Location.Package == nil || rf.Location.Package.ComponentName != "golang-jwt/jwt" {
		t.Errorf("expected component golang-jwt/jwt, got %v", rf.Location.Package)
	}

	// Verify component extraction
	_, _ = f.Seek(0, 0)
	components, err := p.ParseComponents(f)
	if err != nil {
		t.Fatalf("failed to parse components: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	if components[0].Name != "golang-jwt/jwt" || components[0].Version != "v5.2.0" {
		t.Errorf("unexpected component: %+v", components[0])
	}
	if len(components[0].Licenses) == 0 || components[0].Licenses[0] != "MIT" {
		t.Errorf("expected MIT license, got %v", components[0].Licenses)
	}
}

func TestSPDXParseTagValue(t *testing.T) {
	f, err := os.Open("testdata/sample.spdx")
	if err != nil {
		t.Fatalf("failed to open Tag-Value fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	p := spdx.NewParser()
	ctx := context.Background()
	parseCtx := domain.ParseContext{
		TenantID:      domain.NewID(),
		ScanSourceID:  domain.NewID(),
		ScannerFamily: "spdx",
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
		t.Fatalf("expected 1 finding from tag-value, got %d", len(results))
	}

	rf := results[0]
	if rf.RuleID != "pkg:generic/openssl" {
		t.Errorf("expected rule ID 'pkg:generic/openssl', got %q", rf.RuleID)
	}
	if rf.Location.Package == nil || rf.Location.Package.ComponentName != "openssl" {
		t.Errorf("expected component openssl, got %v", rf.Location.Package)
	}

	// Verify component extraction from Tag-Value
	_, _ = f.Seek(0, 0)
	components, err := p.ParseComponents(f)
	if err != nil {
		t.Fatalf("failed to parse components: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	comp := components[0]
	if comp.Name != "openssl" || comp.Version != "1.1.1k" {
		t.Errorf("unexpected component: %+v", comp)
	}
	if len(comp.Licenses) == 0 || comp.Licenses[0] != "OpenSSL" {
		t.Errorf("expected OpenSSL license, got %v", comp.Licenses)
	}
	if comp.Hashes["sha256"] == "" || !strings.HasPrefix(comp.Hashes["sha256"], "b2a3") {
		t.Errorf("expected sha256 hash, got %v", comp.Hashes)
	}
}

func TestSPDXDependencyGraphJSON(t *testing.T) {
	spdxDoc := `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "sample-doc",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-Root",
				"name": "my-service",
				"versionInfo": "1.0.0"
			},
			{
				"SPDXID": "SPDXRef-Package-Gin",
				"name": "gin",
				"versionInfo": "v1.9.1",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:golang/github.com/gin-gonic/gin@v1.9.1"
					}
				]
			},
			{
				"SPDXID": "SPDXRef-Package-Validator",
				"name": "validator",
				"versionInfo": "v10.14.0",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:golang/github.com/go-playground/validator/v10@v10.14.0"
					}
				]
			}
		],
		"relationships": [
			{
				"spdxElementId": "SPDXRef-DOCUMENT",
				"relationshipType": "DESCRIBES",
				"relatedSpdxElement": "SPDXRef-Package-Root"
			},
			{
				"spdxElementId": "SPDXRef-Package-Root",
				"relationshipType": "DEPENDS_ON",
				"relatedSpdxElement": "SPDXRef-Package-Gin"
			},
			{
				"spdxElementId": "SPDXRef-Package-Gin",
				"relationshipType": "DEPENDS_ON",
				"relatedSpdxElement": "SPDXRef-Package-Validator"
			}
		]
	}`

	p := spdx.NewParser()
	sbom, comps, g, err := p.ParseSBOM(strings.NewReader(spdxDoc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sbom.RootComponent != "SPDXRef-Package-Root" {
		t.Errorf("expected root 'SPDXRef-Package-Root', got %q", sbom.RootComponent)
	}
	if len(sbom.Dependencies) != 2 {
		t.Errorf("expected 2 dependency edges, got %d", len(sbom.Dependencies))
	}

	compMap := make(map[string]domain.SBOMComponent)
	for _, c := range comps {
		compMap[c.Name] = c
	}

	if !compMap["gin"].Direct {
		t.Errorf("expected gin to be marked as direct dependency")
	}
	if compMap["validator"].Direct {
		t.Errorf("expected validator to be marked as transitive dependency")
	}

	// Trace path from root to validator
	path := g.FindShortestPath("SPDXRef-Package-Validator")
	if len(path) != 3 {
		t.Fatalf("expected path length 3, got %v", path)
	}
	if path[0] != "SPDXRef-Package-Root" || path[1] != "SPDXRef-Package-Gin" || path[2] != "SPDXRef-Package-Validator" {
		t.Errorf("unexpected path chain: %v", path)
	}
}

func TestSPDXDependencyGraphTagValue(t *testing.T) {
	tagValueDoc := `SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: tv-sample

PackageName: app
SPDXID: SPDXRef-Package-App
PackageVersion: 1.0.0

PackageName: lodash
SPDXID: SPDXRef-Package-Lodash
PackageVersion: 4.17.21
ExternalRef: PACKAGE-MANAGER purl pkg:npm/lodash@4.17.21

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-App
Relationship: SPDXRef-Package-App DEPENDS_ON SPDXRef-Package-Lodash
`

	p := spdx.NewParser()
	sbom, comps, _, err := p.ParseSBOM(strings.NewReader(tagValueDoc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sbom.RootComponent != "SPDXRef-Package-App" {
		t.Errorf("expected root 'SPDXRef-Package-App', got %q", sbom.RootComponent)
	}
	if len(sbom.Dependencies) != 1 {
		t.Errorf("expected 1 dependency edge, got %d", len(sbom.Dependencies))
	}

	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}
	if !comps[1].Direct {
		t.Errorf("expected lodash to be direct dependency")
	}
}

func TestSPDX3JSONLD(t *testing.T) {
	spdx3Doc := `{
		"@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
		"@graph": [
			{
				"@type": "SoftwarePackage",
				"spdxId": "urn:spdx:pkg:web-service",
				"name": "web-service",
				"packageVersion": "2.0.0",
				"packageUrl": "pkg:generic/web-service@2.0.0"
			},
			{
				"@type": "SoftwarePackage",
				"spdxId": "urn:spdx:pkg:redis-client",
				"name": "redis-client",
				"packageVersion": "7.0.1",
				"packageUrl": "pkg:generic/redis-client@7.0.1"
			},
			{
				"@type": "Relationship",
				"spdxId": "urn:spdx:rel:1",
				"from": "urn:spdx:pkg:web-service",
				"to": "urn:spdx:pkg:redis-client",
				"relationshipType": "dependsOn"
			}
		]
	}`

	p := spdx.NewParser()
	detScore := p.Detect([]byte(spdx3Doc), "sbom.spdx.jsonld", "application/ld+json")
	if detScore < 60 {
		t.Errorf("expected high detection score for SPDX 3.0, got %d", detScore)
	}

	sbom, comps, _, err := p.ParseSBOM(strings.NewReader(spdx3Doc))
	if err != nil {
		t.Fatalf("unexpected error parsing SPDX 3.0: %v", err)
	}

	if sbom.SpecVersion != "SPDX-3.0" {
		t.Errorf("expected SPDX-3.0, got %q", sbom.SpecVersion)
	}
	if sbom.RootComponent != "urn:spdx:pkg:web-service" {
		t.Errorf("expected root 'urn:spdx:pkg:web-service', got %q", sbom.RootComponent)
	}
	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}
	if !comps[1].Direct {
		t.Errorf("expected redis-client to be direct dependency")
	}
}
