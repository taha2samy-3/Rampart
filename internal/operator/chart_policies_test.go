package operator_test

import (
	"os"
	"regexp"
	"testing"

	"gopkg.in/yaml.v3"
)

// Rampart installs the default scoring policies and compliance frameworks (the rampart-policies chart) as a dependency of its own
// chart: an option, on by default. This keeps the three places that make that true in step: the dependency, the condition it is
// switched by, and the default of that switch. A dependency that is declared but whose switch is off (or missing) would install
// nothing, and nobody would see it until a tenant had no policies.
func TestChartInstallsThePoliciesByDefault(t *testing.T) {
	read := func(p string) map[string]any {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := yaml.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		return m
	}
	chart := read("../../deploy/helm/rampart/Chart.yaml")
	deps, _ := chart["dependencies"].([]any)
	var dep map[string]any
	for _, d := range deps {
		if m, ok := d.(map[string]any); ok && m["name"] == "rampart-policies" {
			dep = m
		}
	}
	if dep == nil {
		t.Fatal("Chart.yaml does not depend on rampart-policies")
	}
	if dep["alias"] != "policies" || dep["condition"] != "policies.enabled" {
		t.Errorf("the dependency must be aliased policies and switched by policies.enabled: %v", dep)
	}
	if repo, _ := dep["repository"].(string); !regexp.MustCompile(`^oci://ghcr\.io/[a-z0-9-]+/charts$`).MatchString(repo) {
		t.Errorf("the repository must be an OCI registry on GHCR: %q", repo)
	}
	if v, _ := dep["version"].(string); !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(v) {
		t.Errorf("the version must be exact, so a release of the policies cannot change an install by itself: %q", v)
	}
	values := read("../../deploy/helm/rampart/values.yaml")
	pol, _ := values["policies"].(map[string]any)
	if pol == nil || pol["enabled"] != true {
		t.Errorf("policies.enabled must be true by default: %v", pol)
	}
}
