package sbom_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/sbom"
)

func TestParseSBOMStream_CycloneDX(t *testing.T) {
	cdxData := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		"metadata": {
			"component": {
				"name": "sample-app",
				"version": "1.0.0",
				"purl": "pkg:npm/sample-app@1.0.0"
			}
		},
		"components": [
			{
				"name": "lodash",
				"version": "4.17.21",
				"purl": "pkg:npm/lodash@4.17.21"
			}
		],
		"dependencies": [
			{
				"ref": "pkg:npm/sample-app@1.0.0",
				"dependsOn": ["pkg:npm/lodash@4.17.21"]
			}
		]
	}`

	ctx := context.Background()
	sbomDoc, comps, edges, err := sbom.ParseSBOMStream(ctx, "cyclonedx", strings.NewReader(cdxData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(comps) == 0 {
		t.Fatalf("expected components, got 0")
	}

	t.Logf("CycloneDX parsed successfully: format=%s, comps=%d, edges=%d", sbomDoc.Format, len(comps), len(edges))
}

func TestParseSBOMStream_SPDX(t *testing.T) {
	spdxData := `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "sample-spdx",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-app",
				"name": "my-app",
				"versionInfo": "1.0.0",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:golang/my-app@1.0.0"
					}
				]
			}
		],
		"relationships": [
			{
				"spdxElementId": "SPDXRef-DOCUMENT",
				"relationshipType": "DESCRIBES",
				"relatedSpdxElement": "SPDXRef-Package-app"
			}
		]
	}`

	ctx := context.Background()
	sbomDoc, comps, edges, err := sbom.ParseSBOMStream(ctx, "spdx", strings.NewReader(spdxData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}

	t.Logf("SPDX parsed successfully: format=%s, comps=%d, edges=%d", sbomDoc.Format, len(comps), len(edges))
}

func TestParseSBOMStream_OpenVEX(t *testing.T) {
	vexDoc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://openvex.dev/docs/public/vex-2023-001",
		"author": "Security Team",
		"timestamp": "2023-10-15T00:00:00Z",
		"version": 1,
		"statements": [
			{
				"vulnerability": {
					"name": "CVE-2023-44487",
					"aliases": ["GHSA-m425-mq94-257g"]
				},
				"products": [
					{
						"@id": "pkg:golang/google.golang.org/grpc@v1.58.2",
						"subcomponents": []
					}
				],
				"status": "not_affected",
				"justification": "vulnerable_code_not_in_execute_path",
				"impact_statement": "HTTP/2 rapid reset attack mitigated by fronting Envoy proxy."
			}
		]
	}`

	ctx := context.Background()

	// 1. Test ParseSBOMResultStream with ExtractVEX: true
	res, err := sbom.ParseSBOMResultStream(ctx, "openvex", strings.NewReader(vexDoc), sbom.Limits{ExtractVEX: true})
	if err != nil {
		t.Fatalf("ParseSBOMResultStream failed: %v", err)
	}
	if res.SBOM == nil || res.SBOM.Format != "openvex" {
		t.Fatalf("expected format 'openvex', got %+v", res.SBOM)
	}
	if len(res.VEXStatements) != 1 {
		t.Fatalf("expected 1 VEX statement, got %d", len(res.VEXStatements))
	}
	st := res.VEXStatements[0]
	if st.VulnerabilityID != "CVE-2023-44487" {
		t.Errorf("expected vuln CVE-2023-44487, got %s", st.VulnerabilityID)
	}
	if len(st.Aliases) != 1 || st.Aliases[0] != "GHSA-m425-mq94-257g" {
		t.Errorf("expected alias GHSA-m425-mq94-257g, got %v", st.Aliases)
	}
	if st.Status != "not_affected" {
		t.Errorf("expected status not_affected, got %s", st.Status)
	}
	if st.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("expected justification vulnerable_code_not_in_execute_path, got %s", st.Justification)
	}
	if st.Impact != "HTTP/2 rapid reset attack mitigated by fronting Envoy proxy." {
		t.Errorf("expected impact statement, got %s", st.Impact)
	}
	if st.Purl != "pkg:golang/google.golang.org/grpc@v1.58.2" {
		t.Errorf("expected purl pkg:golang/google.golang.org/grpc@v1.58.2, got %s", st.Purl)
	}

	// 2. Test ParseSBOMStream
	doc, comps, edges, err := sbom.ParseSBOMStream(ctx, "openvex", strings.NewReader(vexDoc))
	if err != nil {
		t.Fatalf("ParseSBOMStream failed: %v", err)
	}
	if doc == nil || doc.Format != "openvex" {
		t.Fatalf("expected openvex doc, got %+v", doc)
	}
	if len(comps) != 0 {
		t.Errorf("expected 0 components for openvex doc, got %d", len(comps))
	}
	if len(edges) != 0 {
		t.Errorf("expected 0 edges for openvex doc, got %d", len(edges))
	}
}

func TestParseSBOMStream_CycloneDX_VEXStatements(t *testing.T) {
	cdxVEXData := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		"metadata": {
			"component": {
				"name": "sample-app",
				"version": "1.0.0",
				"purl": "pkg:npm/sample-app@1.0.0"
			}
		},
		"components": [
			{
				"name": "lodash",
				"version": "4.17.21",
				"purl": "pkg:npm/lodash@4.17.21"
			}
		],
		"vulnerabilities": [
			{
				"id": "CVE-2021-23337",
				"analysis": {
					"state": "not_affected",
					"justification": "code_not_reachable",
					"detail": "Vulnerable template engine is disabled"
				},
				"affects": [
					{
						"ref": "pkg:npm/lodash@4.17.21"
					}
				]
			}
		]
	}`

	ctx := context.Background()
	res, err := sbom.ParseSBOMResultStream(ctx, "cyclonedx", strings.NewReader(cdxVEXData), sbom.Limits{
		ExtractVEX:             true,
		ExtractVulnerabilities: true,
	})
	if err != nil {
		t.Fatalf("ParseSBOMResultStream failed: %v", err)
	}
	if len(res.Components) == 0 {
		t.Fatalf("expected components, got 0")
	}
	t.Logf("CycloneDX with VEX parsed: %d components, %d VEX statements", len(res.Components), len(res.VEXStatements))
}
