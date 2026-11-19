package sbom_test

import (
	"reflect"
	"testing"

	"rampart/internal/integrations"
	"rampart/internal/parsertest"
	"rampart/internal/sbom"
)

// The parsers list says what an SBOM reader is without loading its module (InstalledDescriptor). It must say what the reader
// itself says once it is built, or the list and the runs would name the same reader two ways.
func TestInstalledDescriptorMatchesTheSBOMReader(t *testing.T) {
	n := 0
	for _, m := range parsertest.Manifests(t) {
		if m.Kind != "ClusterSBOMParser" {
			continue
		}
		want, err := sbom.NewWasmSBOMParserFromSpec(m.Name, m.Stored, nil)
		if err != nil {
			t.Fatalf("%s: %v", m.Name, err)
		}
		got, err := integrations.InstalledDescriptor(m.Name, m.Stored)
		if err != nil {
			t.Fatalf("%s: %v", m.Name, err)
		}
		if !reflect.DeepEqual(want.Descriptor(), got) {
			t.Errorf("%s: the list says %+v, the reader says %+v", m.Name, got, want.Descriptor())
		}
		n++
	}
	if n != 3 {
		t.Fatalf("checked %d SBOM readers, want 3", n)
	}
}
