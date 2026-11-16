package operator

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Parser controller was registered with no RBAC rule for parsers (and the standalone manifest also lacked
// integrationpackages): on a cluster that enforces RBAC the manager's informer for the kind is forbidden, the
// manager fails to start, and the whole server exits. Every kind the operator has a controller for must be
// granted, with its status and finalizers, in both RBAC manifests.
func TestOperatorRBACCoversEveryController(t *testing.T) {
	src, err := os.ReadFile("manager.go")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*gvk\w+\s*=\s*schema\.GroupVersionKind\{[^}]*Kind:\s*"(\w+)"`).FindAllStringSubmatch(string(src), -1) {
		kinds[m[1]] = true
	}
	if len(kinds) < 13 {
		t.Fatalf("expected the 13 controller kinds in manager.go, found %d: %v", len(kinds), kinds)
	}

	plural := map[string]string{} // kind -> plural, from the CRDs
	files, _ := filepath.Glob("../../deploy/crds/*.yaml")
	for _, f := range files {
		b, _ := os.ReadFile(f)
		k := regexp.MustCompile(`(?m)^\s+kind:\s*(\w+)`).FindStringSubmatch(string(b))
		p := regexp.MustCompile(`(?m)^\s+plural:\s*(\w+)`).FindStringSubmatch(string(b))
		if k != nil && p != nil {
			plural[k[1]] = p[1]
		}
	}

	for _, manifest := range []string{"../../deploy/helm/rampart/templates/rbac.yaml", "../../deploy/operator/rbac.yaml"} {
		b, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		for kind := range kinds {
			pl := plural[kind]
			if pl == "" {
				t.Errorf("no CRD plural found for %s", kind)
				continue
			}
			for _, res := range []string{pl, pl + "/status", pl + "/finalizers"} {
				// a list item (- name), or a name inside a flow list ([a, b] or ", b,")
				if !regexp.MustCompile(`(?m)(^\s*-\s*` + regexp.QuoteMeta(res) + `\s*$|[\[\s,]` + regexp.QuoteMeta(res) + `[,\]])`).MatchString(text) {
					t.Errorf("%s does not grant %q to the operator (kind %s)", filepath.Base(manifest), res, kind)
				}
			}
		}
		if strings.Contains(text, "rampart.aspm.dev") == false {
			t.Errorf("%s has no rule for the rampart.aspm.dev group", manifest)
		}
	}
}
