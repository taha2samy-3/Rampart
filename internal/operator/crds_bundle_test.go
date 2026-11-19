package operator_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// deploy/rampart-crds.yaml is every CRD in one file, for a cluster that already runs Rampart (Helm installs the chart's crds/ folder on
// the first install only, so a newer release's CRDs have to be applied another way). It must name exactly the CRDs of deploy/crds: one
// missing from it is one that never reaches such a cluster, and one extra is one the chart does not ship. hack/crds-bundle.py writes it,
// and CI runs it with --check; this is the same rule inside `go test`, where a person changing a CRD will see it first.
func TestCRDBundleHasEveryCRD(t *testing.T) {
	names := func(raw []byte) []string {
		var out []string
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		for {
			var d struct {
				Kind     string `yaml:"kind"`
				Metadata struct {
					Name string `yaml:"name"`
				} `yaml:"metadata"`
			}
			if err := dec.Decode(&d); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			if d.Kind == "" {
				continue
			}
			if d.Kind != "CustomResourceDefinition" {
				t.Errorf("a document of kind %s in a CRD file", d.Kind)
			}
			out = append(out, d.Metadata.Name)
		}
		slices.Sort(out)
		return out
	}
	var want []string
	files, err := filepath.Glob("../../deploy/crds/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("deploy/crds: %v %d", err, len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, names(raw)...)
	}
	slices.Sort(want)
	bundle, err := os.ReadFile("../../deploy/rampart-crds.yaml")
	if err != nil {
		t.Fatalf("no bundle: run hack/crds-bundle.py: %v", err)
	}
	if got := names(bundle); !slices.Equal(got, want) {
		t.Fatalf("the bundle and deploy/crds name different CRDs: run hack/crds-bundle.py\n bundle: %v\n crds:   %v", got, want)
	}
}
