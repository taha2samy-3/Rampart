// Package parsertest gives tests the default parsers as data. Rampart compiles in no parser: a test that needs trivy or the SPDX
// reader installs them from the manifests in internal/testdata/parsers, the way a deployment installs its own, either from the
// directory (RAMPART_PARSERS_DIR) or through the store the control plane writes (the Stored form).
package parsertest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"rampart/internal/domain"
)

// Manifest is one default parser.
type Manifest struct {
	Name string // metadata.name
	Kind string // ClusterParser or ClusterSBOMParser
	// Raw is the file. Stored is what the control plane keeps for it: a ClusterParser's spec alone as JSON, a
	// ClusterSBOMParser as the whole resource.
	Raw, Stored []byte
}

// Dir is the directory of the default manifests (internal/testdata/parsers), found from the working directory of the test.
func Dir() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for d := wd; ; d = filepath.Dir(d) {
		if c := filepath.Join(d, "internal", "testdata", "parsers"); dirExists(c) {
			return c
		}
		if filepath.Dir(d) == d {
			return ""
		}
	}
}

func dirExists(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// Manifests reads every default manifest, sorted by name.
func Manifests(t testing.TB) []Manifest {
	t.Helper()
	dir := Dir()
	if dir == "" {
		t.Fatal("parsertest: internal/testdata/parsers not found from the working directory")
	}
	var out []Manifest
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Spec map[string]any `yaml:"spec"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return err
		}
		spec, err := json.Marshal(doc.Spec)
		if err != nil {
			return err
		}
		stored := spec
		if doc.Kind == "ClusterSBOMParser" {
			stored = domain.StoredSBOMParser(doc.Metadata.Name, spec)
		}
		out = append(out, Manifest{Name: doc.Metadata.Name, Kind: doc.Kind, Raw: raw, Stored: stored})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SetEnv points a test binary at the default manifests (for TestMain, which cannot use t.Setenv).
func SetEnv() {
	if d := Dir(); d != "" {
		_ = os.Setenv("RAMPART_PARSERS_DIR", d)
	}
}
