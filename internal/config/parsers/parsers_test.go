package parsers_test

import (
	"testing"

	"rampart/internal/config/parsers"
)

func TestListDefaultParsers(t *testing.T) {
	list, err := parsers.ListDefaultParsers()
	if err != nil {
		t.Fatalf("failed to list default parsers: %v", err)
	}
	if len(list) != 17 {
		t.Fatalf("expected 17 default parsers, got %d", len(list))
	}

	expected := []string{
		"bandit", "checkov", "dependencycheck",
		"genericjson", "gitlab", "gitleaks", "grype", "kubebench",
		"nuclei", "openvex", "prowler", "sarif", "semgrep",
		"snyk", "trivy", "trufflehog", "zap",
	}

	found := make(map[string]bool)
	for _, p := range list {
		found[p.Name] = true
		manifest, err := parsers.ParseManifest(p.Spec)
		if err != nil {
			t.Errorf("parser %q failed to parse YAML: %v", p.Name, err)
			continue
		}
		if manifest.Kind != "ClusterParser" {
			t.Errorf("parser %q expected Kind 'ClusterParser', got %q", p.Name, manifest.Kind)
		}
		if manifest.Metadata.Name != p.Name {
			t.Errorf("parser %q metadata.name mismatch: %q", p.Name, manifest.Metadata.Name)
		}
		runtime, ok := manifest.Spec["runtime"].(string)
		if !ok || (runtime != "native" && runtime != "lua" && runtime != "wasm") {
			t.Errorf("parser %q expected runtime 'native', 'lua', or 'wasm', got %v", p.Name, manifest.Spec["runtime"])
		}
	}

	for _, name := range expected {
		if !found[name] {
			t.Errorf("missing expected default parser: %q", name)
		}
	}
}

func TestGetDefaultParser(t *testing.T) {
	data, err := parsers.GetDefaultParser("sarif")
	if err != nil {
		t.Fatalf("failed to get sarif parser: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("sarif parser YAML was empty")
	}

	_, err = parsers.GetDefaultParser("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent parser, got nil")
	}
}
