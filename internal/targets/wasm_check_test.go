package targets

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"rampart/internal/wasmstore"
)

func TestShippedWasmModulesAreNamed(t *testing.T) {
	names := shippedWasmModules()
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, want := range []string{"sarif", "trivy", "gitleaks", "semgrep", "sbom-cyclonedx", "sbom-spdx"} {
		if !have[want] {
			t.Errorf("%s is a shipped module and must be checked at start-up: %v", want, names)
		}
	}
	for _, lua := range []string{"bandit", "zap", "nuclei", "genericjson"} {
		if have[lua] {
			t.Errorf("%s is a Lua parser: it has no module to check", lua)
		}
	}
}

func TestStartupRefusesAnIncompleteStrictSet(t *testing.T) {
	dir := t.TempDir()
	code := []byte("not really wasm")
	if err := os.WriteFile(filepath.Join(dir, "sarif.wasm"), code, 0o644); err != nil {
		t.Fatal(err)
	}
	wasmstore.SetDefault(&wasmstore.Store{Dir: dir, Digests: map[string]string{"sarif": wasmstore.Digest(code)}})
	t.Cleanup(func() { wasmstore.SetDefault(&wasmstore.Store{}) })
	r := &Runner{logger: testLogger()}
	err := r.verifyWasmModules()
	if err == nil || !strings.Contains(err.Error(), "cannot be used") {
		t.Fatalf("every other shipped module is missing, so the server must not start: %v", err)
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

// The chart must list exactly the modules the server checks at start-up: one fewer and the server would refuse to start
// (a shipped module is unlisted), one more and a module nobody asked for is mounted.
func TestChartListsTheShippedModules(t *testing.T) {
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
	have := shippedWasmModules()
	if len(v.Parsers.Modules) != len(have) {
		t.Errorf("the chart lists %d modules, the server ships %d: %v", len(v.Parsers.Modules), len(have), have)
	}
	for _, n := range have {
		if _, ok := v.Parsers.Modules[n]; !ok {
			t.Errorf("values.yaml parsers.modules has no entry for the shipped module %q", n)
		}
	}
}
