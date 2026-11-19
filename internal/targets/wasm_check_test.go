package targets

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"rampart/internal/wasmstore"
)

func TestExpectedWasmModulesAreTheOnesTheTableLists(t *testing.T) {
	st := &wasmstore.Store{Digests: map[string]string{"trivy": "x", "sarif": "y", "sbom-spdx": "z"}}
	got := expectedWasmModules(st)
	if strings.Join(got, ",") != "sarif,sbom-spdx,trivy" {
		t.Fatalf("the digest table is the list, sorted: %v", got)
	}
}

func TestStartupRefusesAnIncompleteStrictSet(t *testing.T) {
	dir := t.TempDir()
	code := []byte("not really wasm")
	if err := os.WriteFile(filepath.Join(dir, "sarif.wasm"), code, 0o644); err != nil {
		t.Fatal(err)
	}
	// The table lists trivy and the directory has no such module: the server must not start.
	wasmstore.SetDefault(&wasmstore.Store{Dir: dir, Digests: map[string]string{"sarif": wasmstore.Digest(code), "trivy": wasmstore.Digest([]byte("other"))}})
	t.Cleanup(func() { wasmstore.SetDefault(&wasmstore.Store{}) })
	r := &Runner{logger: testLogger()}
	err := r.verifyWasmModules()
	if err == nil || !strings.Contains(err.Error(), "cannot be used") || !strings.Contains(err.Error(), "trivy") {
		t.Fatalf("a listed module is missing, so the server must not start, and the error names it: %v", err)
	}
}

func TestStartupAcceptsACompleteStrictSetAndRefusesAChangedModule(t *testing.T) {
	dir := t.TempDir()
	code := []byte("module bytes")
	if err := os.WriteFile(filepath.Join(dir, "sarif.wasm"), code, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wasmstore.SetDefault(&wasmstore.Store{}) })
	r := &Runner{logger: testLogger()}

	wasmstore.SetDefault(&wasmstore.Store{Dir: dir, Digests: map[string]string{"sarif": wasmstore.Digest(code)}})
	if err := r.verifyWasmModules(); err != nil {
		t.Fatalf("every listed module is present and matches: %v", err)
	}
	wasmstore.SetDefault(&wasmstore.Store{Dir: dir, Digests: map[string]string{"sarif": wasmstore.Digest([]byte("another build"))}})
	if err := r.verifyWasmModules(); err == nil {
		t.Fatal("a module that does not match its digest must stop the server")
	}
}

func TestStartupAcceptsADevelopmentCheckout(t *testing.T) {
	wasmstore.SetDefault(&wasmstore.Store{})
	r := &Runner{logger: testLogger()}
	if err := r.verifyWasmModules(); err != nil {
		t.Fatalf("without a digest table nothing is enforced: %v", err)
	}
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// defaultWasmModules is the set of modules the default parsers need: the wasm report parsers and the SBOM readers of the
// manifests in testdata (the ones the chart installs as ClusterParser and ClusterSBOMParser).
func defaultWasmModules(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, d := range []string{"../testdata/parsers/report", "../testdata/parsers/sbom"} {
		files, _ := filepath.Glob(filepath.Join(d, "*.yaml"))
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var m struct {
				Metadata struct {
					Name string `yaml:"name"`
				} `yaml:"metadata"`
				Spec struct {
					Runtime string `yaml:"runtime"`
				} `yaml:"spec"`
			}
			if err := yaml.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			if m.Spec.Runtime == "wasm" {
				out = append(out, m.Metadata.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// The chart must list exactly the modules its default parsers need: one fewer and a default parser has no module to run, one
// more and a module nobody asked for is mounted.
func TestChartListsTheModulesOfItsDefaultParsers(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/helm/rampart/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Parsers struct {
			Modules map[string]any `yaml:"modules"`
		} `yaml:"parsers"`
	}
	if err := yaml.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	have := defaultWasmModules(t)
	if len(v.Parsers.Modules) != len(have) {
		t.Errorf("the chart lists %d modules, its default parsers need %d: %v", len(v.Parsers.Modules), len(have), have)
	}
	for _, n := range have {
		if _, ok := v.Parsers.Modules[n]; !ok {
			t.Errorf("values.yaml parsers.modules has no entry for %q, a module a default parser needs", n)
		}
	}
}

// values.yaml lists a switch for every default parser and every default SBOM reader, so a reader of the file sees what is
// installed. The list must be the manifests' names exactly: one missing hides a parser, one extra is a switch for nothing.
func TestChartValuesListASwitchForEveryDefaultParser(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/helm/rampart/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Parsers struct {
			Default map[string]any `yaml:"defaultParsers"`
		} `yaml:"parsers"`
		SBOM struct {
			Default map[string]any `yaml:"defaultSBOMParsers"`
		} `yaml:"sbomParsers"`
	}
	if err := yaml.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	names := func(dir, trim string) []string {
		files, _ := filepath.Glob(filepath.Join("../testdata/parsers", dir, "*.yaml"))
		var out []string
		for _, f := range files {
			out = append(out, strings.TrimPrefix(strings.TrimSuffix(filepath.Base(f), ".yaml"), trim))
		}
		sort.Strings(out)
		return out
	}
	keys := func(m map[string]any) []string {
		var out []string
		for k := range m {
			if k != "enabled" {
				out = append(out, k)
			}
		}
		sort.Strings(out)
		return out
	}
	if got, want := keys(v.Parsers.Default), names("report", ""); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("parsers.defaultParsers lists %v, the default report parsers are %v", got, want)
	}
	// the SBOM manifests are cyclonedx.yaml, spdx.yaml, syft.yaml; the resources are named sbom-<that>
	if got, want := keys(v.SBOM.Default), names("sbom", ""); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("sbomParsers.defaultSBOMParsers lists %v, the default SBOM readers are %v", got, want)
	}
}
