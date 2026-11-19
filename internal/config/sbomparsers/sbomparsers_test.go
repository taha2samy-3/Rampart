package sbomparsers_test

import (
	"testing"

	"rampart/internal/config/sbomparsers"
)

func TestListDefaultSBOMParsers(t *testing.T) {
	list, err := sbomparsers.ListDefaultSBOMParsers()
	if err != nil {
		t.Fatalf("failed to list default sbom parsers: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 default sbom parsers (cyclonedx, spdx, syft), got %d", len(list))
	}

	for _, p := range list {
		manifest, err := sbomparsers.ParseManifest(p.Spec)
		if err != nil {
			t.Errorf("parser %q failed to parse YAML: %v", p.Name, err)
			continue
		}
		if manifest.Kind != "ClusterSBOMParser" {
			t.Errorf("parser %q expected Kind 'ClusterSBOMParser', got %q", p.Name, manifest.Kind)
		}
		runtime, ok := manifest.Spec["runtime"].(string)
		if !ok || runtime != "wasm" {
			t.Errorf("parser %q expected runtime 'wasm', got %v", p.Name, manifest.Spec["runtime"])
		}
	}
}
