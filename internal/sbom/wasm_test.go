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
