package apply_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
)

const sbomParserYAML = `apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterSBOMParser
metadata:
  name: sbom-spdx
spec:
  format: spdx
  runtime: wasm
  source:
    oci: ghcr.io/example/sbom-parsers/sbom-spdx:v1
  detect:
    filenames: ["*.spdx"]
`

// `rampart apply` stores a ClusterSBOMParser the way the operator does: with the cluster's parsers, as the whole resource.
func TestApplyClusterSBOMParserIsStoredLikeTheOperatorStoresIt(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	out, err := apply.NewApplier(store).ApplyDocument(ctx, []byte(sbomParserYAML))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "clustersbomparser") {
		t.Errorf("unexpected result line %q", out)
	}
	list, _ := store.ListParsers(ctx, domain.NewID())
	if len(list) != 1 || list[0].Name != "sbom-spdx" || list[0].Error != "" ||
		!strings.Contains(string(list[0].Spec), `"kind":"ClusterSBOMParser"`) {
		t.Fatalf("stored wrongly: %+v", list)
	}
}

func TestApplyClusterSBOMParserRefusesABadNameAndTheReportParserCannotTakeTheSBOMPrefix(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	ap := apply.NewApplier(store)

	if _, err := ap.ApplyDocument(ctx, []byte(strings.Replace(sbomParserYAML, "name: sbom-spdx", "name: spdx", 1))); err == nil || !strings.Contains(err.Error(), "sbom-") {
		t.Errorf("a ClusterSBOMParser without the sbom- prefix must be refused, got %v", err)
	}

	report := `apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterParser
metadata:
  name: sbom-impostor
spec:
  version: 1.0.0
  family: x
  category: sast
  runtime: wasm
  source:
    oci: ghcr.io/example/x:v1
`
	if _, err := ap.ApplyDocument(ctx, []byte(report)); err == nil || !strings.Contains(err.Error(), "ClusterSBOMParser") {
		t.Errorf("a ClusterParser named sbom-* must be refused and say why, got %v", err)
	}
	// A refused document is stored with its reason, never as a working parser.
	for _, p := range func() []domain.StoredParserObject { l, _ := store.ListParsers(ctx, domain.NewID()); return l }() {
		if p.Error == "" {
			t.Errorf("%s was stored as valid", p.Name)
		}
	}
}
