package main_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func compileWasm(t *testing.T) []byte {
	t.Helper()
	wasmPath := filepath.Join(t.TempDir(), "parser.wasm")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", wasmPath, "main.go", "parser.go")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile wasm module: %v\nOutput: %s", err, string(out))
	}
	code, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func runWasm(t *testing.T, code, input []byte) (stdout, stderr []byte, err error) {
	t.Helper()
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer func() { _ = r.Close(ctx) }()
	wasi_snapshot_preview1.MustInstantiate(ctx, r)
	var out, errb bytes.Buffer
	cfg := wazero.NewModuleConfig().WithStdin(bytes.NewReader(input)).WithStdout(&out).WithStderr(&errb).WithArgs("parser.wasm")
	compiled, err := r.CompileModule(ctx, code)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = compiled.Close(ctx) }()
	mod, err := r.InstantiateModule(ctx, compiled, cfg)
	if mod != nil {
		_ = mod.Close(ctx)
	}
	return out.Bytes(), errb.Bytes(), err
}

func events(t *testing.T, stdout []byte) (meta map[string]any, comps, edges []map[string]any) {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("line is not JSON: %q", sc.Text())
		}
		switch ev["type"] {
		case "metadata":
			meta = ev
		case "component":
			comps = append(comps, ev)
		case "edge":
			edges = append(edges, ev)
		default:
			t.Fatalf("a Syft reader emits metadata, components and edges only, got %q", ev["type"])
		}
	}
	return meta, comps, edges
}

func TestSyft_Wasm_ReadsThePackagesAndTheGraph(t *testing.T) {
	code := compileWasm(t)
	data, err := os.ReadFile("testdata/report.syft.json")
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := runWasm(t, code, data)
	if err != nil {
		t.Fatalf("module failed: %v\nstderr: %s", err, stderr)
	}
	meta, comps, edges := events(t, stdout)

	if meta["format"] != "Syft" || meta["spec_version"] != "16.0.0" || meta["tool_name"] != "syft" {
		t.Errorf("metadata = %v", meta)
	}
	// The source is the package `ecommerce-api@1.0.0` of the list: the root is that component.
	if meta["root_ref"] != "pkg:npm/ecommerce-api@1.0.0" {
		t.Errorf("root_ref = %v, want the purl of the source package", meta["root_ref"])
	}

	// Four packages; the artifact that names nothing is skipped, and the module says so.
	if len(comps) != 4 {
		t.Fatalf("components = %d, want 4: %v", len(comps), comps)
	}
	if !strings.Contains(string(stderr), "1 artifact(s)") {
		t.Errorf("the skipped artifact is not reported on stderr: %q", stderr)
	}
	byName := map[string]map[string]any{}
	for _, c := range comps {
		byName[c["name"].(string)] = c
	}
	if got := byName["express"]; got["ref"] != "pkg:npm/express@4.18.2" || got["purl_base"] != "pkg:npm/express" {
		t.Errorf("express = %v", got)
	}
	if got := byName["debug"]["licenses"]; len(got.([]any)) != 1 || got.([]any)[0] != "MIT" {
		t.Errorf("a licence given only as an spdxExpression is lost: %v", got)
	}
	// A package with no purl is referenced by its Syft id, which the relationships use.
	if got := byName["busybox"]; got["ref"] != "a-busybox" || got["purl"] != nil {
		t.Errorf("busybox = %v", got)
	}

	type edge struct {
		from, to string
		direct   bool
	}
	var got []edge
	for _, e := range edges {
		got = append(got, edge{e["from"].(string), e["to"].(string), e["direct"] == true})
	}
	want := []edge{
		{"pkg:npm/ecommerce-api@1.0.0", "pkg:npm/express@4.18.2", true}, // dependency-of, reversed
		{"pkg:npm/express@4.18.2", "pkg:npm/debug@4.3.4", false},        // dependency-of, reversed
		{"pkg:npm/ecommerce-api@1.0.0", "a-busybox", true},              // contains
	}
	if len(got) != len(want) {
		t.Fatalf("edges = %v, want %v (an ownership relationship is not a dependency; an edge with no end is dropped)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("edge %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// A source that is no package of the list (an image) stays a name and marks nothing direct.
func TestSyft_Wasm_ImageSourceIsNoComponent(t *testing.T) {
	code := compileWasm(t)
	doc := `{"artifacts":[{"id":"1","name":"zlib","version":"1.2","purl":"pkg:apk/alpine/zlib@1.2"}],
	  "artifactRelationships":[{"parent":"1","child":"1","type":"contains"}],
	  "source":{"name":"alpine","version":"sha256:abc","type":"image"}}`
	stdout, stderr, err := runWasm(t, code, []byte(doc))
	if err != nil {
		t.Fatalf("%v: %s", err, stderr)
	}
	meta, _, edges := events(t, stdout)
	if meta["root_ref"] != "alpine@sha256:abc" {
		t.Errorf("root_ref = %v", meta["root_ref"])
	}
	for _, e := range edges {
		if e["direct"] == true {
			t.Errorf("nothing is direct when the root is not a component: %v", e)
		}
	}
}

// What is not a Syft document fails the module, with the reason on stderr: it must not read as an empty inventory.
func TestSyft_Wasm_RefusesWhatIsNotSyft(t *testing.T) {
	code := compileWasm(t)
	for name, in := range map[string]string{
		"empty input":        "",
		"plain text":         "hello",
		"a JSON array":       `[1,2,3]`,
		"unrelated JSON":     `{"hello":"world"}`,
		"a CycloneDX BOM":    `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`,
		"truncated document": `{"artifacts":[{"id":"1","name":"a"}`,
	} {
		stdout, stderr, err := runWasm(t, code, []byte(in))
		if err == nil {
			t.Errorf("%s: accepted, wrote %q", name, stdout)
			continue
		}
		if !strings.Contains(string(stderr), "syft sbom parser error") {
			t.Errorf("%s: stderr says nothing useful: %q", name, stderr)
		}
	}
}

// A document with an empty artifacts array is a real, empty inventory.
func TestSyft_Wasm_AllowsAnEmptyInventory(t *testing.T) {
	code := compileWasm(t)
	stdout, stderr, err := runWasm(t, code, []byte(`{"artifacts":[],"artifactRelationships":[]}`))
	if err != nil {
		t.Fatalf("%v: %s", err, stderr)
	}
	meta, comps, _ := events(t, stdout)
	if meta == nil || len(comps) != 0 {
		t.Errorf("meta = %v, components = %d", meta, len(comps))
	}
}
