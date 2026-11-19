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
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func compileWasm(t *testing.T) string {
	t.Helper()
	wasmPath := filepath.Join(t.TempDir(), "parser.wasm")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", wasmPath, "main.go", "parser.go")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile wasm module: %v\nOutput: %s", err, string(out))
	}
	return wasmPath
}

func runWasm(ctx context.Context, t *testing.T, wasmCode []byte, input []byte, envVars []string) ([]byte, []byte, error) {
	t.Helper()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)

	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	stdin := bytes.NewReader(input)
	var stdout, stderr bytes.Buffer

	cfg := wazero.NewModuleConfig().
		WithStdin(stdin).
		WithStdout(&stdout).
		WithStderr(&stderr).
		WithArgs("parser.wasm")

	for _, e := range envVars {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			cfg = cfg.WithEnv(parts[0], parts[1])
		}
	}

	compiled, err := r.CompileModule(ctx, wasmCode)
	if err != nil {
		return nil, nil, err
	}
	defer compiled.Close(ctx)

	mod, err := r.InstantiateModule(ctx, compiled, cfg)
	if mod != nil {
		_ = mod.Close(ctx)
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func TestCycloneDX_Wasm_DropwizardLargeGraph(t *testing.T) {
	ctx := context.Background()
	wasmPath := compileWasm(t)
	wasmCode, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read wasm module: %v", err)
	}

	dropwizardData, err := os.ReadFile("testdata/dropwizard.cdx.json")
	if err != nil {
		t.Fatalf("failed to read dropwizard.cdx.json: %v", err)
	}

	start := time.Now()
	stdout, stderr, err := runWasm(ctx, t, wasmCode, dropwizardData, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("wasm execution failed: %v\nStderr: %s", err, string(stderr))
	}

	t.Logf("Parsed Dropwizard CycloneDX (380KB) in %v", elapsed)

	// Parse JSONL events from stdout
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	var (
		metadataCount      int
		componentCount     int
		edgeCount          int
		directEdgeCount    int
		componentsWithPurl int
	)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			t.Fatalf("invalid json line emitted: %s", string(line))
		}

		eventType, _ := raw["type"].(string)
		switch eventType {
		case "metadata":
			metadataCount++
			if raw["format"] != "CycloneDX" {
				t.Errorf("expected format CycloneDX, got %v", raw["format"])
			}
			t.Logf("Metadata: specVersion=%v, rootRef=%v", raw["spec_version"], raw["root_ref"])

		case "component":
			componentCount++
			if purl, ok := raw["purl"].(string); ok && purl != "" {
				componentsWithPurl++
				if raw["purl_base"] == "" {
					t.Errorf("component %v has purl %s but missing purl_base", raw["name"], purl)
				}
			}

		case "edge":
			edgeCount++
			if direct, ok := raw["direct"].(bool); ok && direct {
				directEdgeCount++
			}
		}
	}

	if metadataCount != 1 {
		t.Errorf("expected exactly 1 metadata event, got %d", metadataCount)
	}
	if componentCount < 100 {
		t.Errorf("expected >= 100 components, got %d", componentCount)
	}
	if edgeCount < 50 {
		t.Errorf("expected >= 50 edges, got %d", edgeCount)
	}
	if directEdgeCount == 0 {
		t.Errorf("expected some direct dependency edges, got 0")
	}

	t.Logf("Results: components=%d (purl=%d), total edges=%d (direct edges=%d)",
		componentCount, componentsWithPurl, edgeCount, directEdgeCount)
}

func TestCycloneDX_Wasm_JuiceShop(t *testing.T) {
	ctx := context.Background()
	wasmPath := compileWasm(t)
	wasmCode, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read wasm module: %v", err)
	}

	juiceShopData, err := os.ReadFile("testdata/juice-shop.cdx.json")
	if err != nil {
		t.Fatalf("failed to read juice-shop.cdx.json: %v", err)
	}

	start := time.Now()
	stdout, stderr, err := runWasm(ctx, t, wasmCode, juiceShopData, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("wasm execution failed: %v\nStderr: %s", err, string(stderr))
	}

	t.Logf("Parsed OWASP Juice Shop CycloneDX (726KB) in %v", elapsed)

	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	componentCount := 0
	for scanner.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &raw); err == nil {
			if raw["type"] == "component" {
				componentCount++
			}
		}
	}

	if componentCount < 200 {
		t.Errorf("expected >= 200 components in Juice Shop, got %d", componentCount)
	}
	t.Logf("Extracted %d components from Juice Shop", componentCount)
}

// vulnerabilities lists the "vulnerability" events of one run.
func vulnerabilities(t *testing.T, stdout []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 1<<20), 10<<20)
	for sc.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			t.Fatalf("a line that is not JSON: %s", sc.Text())
		}
		if raw["type"] == "vulnerability" {
			out = append(out, raw)
		}
	}
	return out
}

// The vulnerabilities a document states are emitted only when the option is on. Off is the default: an SBOM is assets.
func TestCycloneDX_Wasm_ExtractVulnerabilitiesIsAnOption(t *testing.T) {
	ctx := context.Background()
	wasmCode, err := os.ReadFile(compileWasm(t))
	if err != nil {
		t.Fatalf("failed to read wasm module: %v", err)
	}
	vdr := []byte(`{
		"bomFormat": "CycloneDX", "specVersion": "1.5",
		"components": [
			{"bom-ref": "pkg:npm/lodash@4.17.20", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20",
			 "cpe": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*"},
			{"bom-ref": "pkg:npm/other@1.0.0", "name": "other", "version": "1.0.0", "purl": "pkg:npm/other@1.0.0"}
		],
		"vulnerabilities": [
			{
				"id": "CVE-2021-23337", "source": {"name": "NVD"},
				"description": "Command Injection in lodash",
				"ratings": [
					{"severity": "medium", "score": 5.0, "method": "CVSSv2"},
					{"severity": "high", "score": 7.2, "method": "CVSSv31", "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}
				],
				"cwes": [78],
				"references": [{"id": "GHSA-35jh-r3h4-6jhm"}],
				"affects": [{"ref": "pkg:npm/lodash@4.17.20"}, {"ref": "pkg:npm/other@1.0.0"}]
			},
			{"id": "", "affects": [{"ref": "pkg:npm/lodash@4.17.20"}]},
			{"id": "CVE-2000-0001", "affects": []}
		]
	}`)

	for _, env := range [][]string{nil, {"EXTRACT_VULNERABILITIES=false"}, {"EXTRACT_VULNERABILITIES=0"}} {
		stdout, stderr, err := runWasm(ctx, t, wasmCode, vdr, env)
		if err != nil {
			t.Fatalf("env %v: %v\n%s", env, err, stderr)
		}
		if got := vulnerabilities(t, stdout); len(got) != 0 {
			t.Errorf("env %v: the option is off and %d vulnerabilities were emitted", env, len(got))
		}
	}

	stdout, stderr, err := runWasm(ctx, t, wasmCode, vdr, []string{"EXTRACT_VULNERABILITIES=true"})
	if err != nil {
		t.Fatalf("option on: %v\n%s", err, stderr)
	}
	got := vulnerabilities(t, stdout)
	if len(got) != 2 {
		t.Fatalf("one event per affected component was expected (2), got %d: %v", len(got), got)
	}
	v := got[0]
	if v["id"] != "CVE-2021-23337" || v["affected_ref"] != "pkg:npm/lodash@4.17.20" || v["source"] != "NVD" {
		t.Errorf("unexpected event: %v", v)
	}
	// of two ratings the one that says the most is used: the highest score, with its own vector
	if v["severity"] != "high" || v["score"] != 7.2 || !strings.HasPrefix(v["vector"].(string), "CVSS:3.1/") {
		t.Errorf("the best rating was not used: %v", v)
	}
	if cw, _ := v["cwes"].([]any); len(cw) != 1 || cw[0] != float64(78) {
		t.Errorf("cwes: %v", v["cwes"])
	}
	if al, _ := v["aliases"].([]any); len(al) != 1 || al[0] != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("aliases: %v", v["aliases"])
	}
	// the CPE of a component is never read as a vulnerability
	for _, e := range got {
		if strings.Contains(strings.ToLower(e["id"].(string)), "cpe") {
			t.Errorf("a CPE became a vulnerability: %v", e)
		}
	}
}

func TestCycloneDX_Wasm_ExtractVulnerabilitiesXML(t *testing.T) {
	ctx := context.Background()
	wasmCode, err := os.ReadFile(compileWasm(t))
	if err != nil {
		t.Fatalf("failed to read wasm module: %v", err)
	}
	doc := []byte(`<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1" serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79">
  <components>
    <component type="library" bom-ref="pkg:maven/a/b@1.0"><name>b</name><version>1.0</version><purl>pkg:maven/a/b@1.0</purl></component>
  </components>
  <vulnerabilities>
    <vulnerability bom-ref="v1">
      <id>CVE-2021-44228</id>
      <source name="NVD"/>
      <ratings>
        <rating><score><base>10.0</base></score><severity>critical</severity><method>CVSSv3</method><vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</vector></rating>
        <rating><score>4.0</score><severity>medium</severity><method>other</method></rating>
      </ratings>
      <cwes><cwe>502</cwe></cwes>
      <description>Log4Shell</description>
      <affects><target><ref>pkg:maven/a/b@1.0</ref></target></affects>
    </vulnerability>
  </vulnerabilities>
</bom>`)
	stdout, stderr, err := runWasm(ctx, t, wasmCode, doc, []string{"EXTRACT_VULNERABILITIES=1"})
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	got := vulnerabilities(t, stdout)
	if len(got) != 1 || got[0]["id"] != "CVE-2021-44228" || got[0]["severity"] != "critical" || got[0]["score"] != 10.0 {
		t.Fatalf("unexpected events: %v", got)
	}
	// with the option off the same document still reads, and says nothing about vulnerabilities
	stdout, stderr, err = runWasm(ctx, t, wasmCode, doc, nil)
	if err != nil {
		t.Fatalf("option off: %v\n%s", err, stderr)
	}
	if got := vulnerabilities(t, stdout); len(got) != 0 {
		t.Errorf("option off emitted %v", got)
	}
}

func TestCycloneDX_Wasm_XML(t *testing.T) {
	ctx := context.Background()
	wasmPath := compileWasm(t)
	wasmCode, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read compiled wasm: %v", err)
	}

	xmlPayload, err := os.ReadFile("testdata/sample.cdx.xml")
	if err != nil {
		t.Fatalf("failed to read XML fixture: %v", err)
	}

	// The fixture has one component and one vulnerability. Components are read either way; the vulnerability only when asked.
	for _, tc := range []struct {
		env  []string
		want int
	}{{nil, 0}, {[]string{"EXTRACT_VULNERABILITIES=true"}, 1}} {
		stdout, stderr, err := runWasm(ctx, t, wasmCode, xmlPayload, tc.env)
		if err != nil {
			t.Fatalf("env %v: run failed: %v\nStderr: %s", tc.env, err, string(stderr))
		}
		compCount := 0
		scanner := bufio.NewScanner(bytes.NewReader(stdout))
		for scanner.Scan() {
			var raw map[string]any
			_ = json.Unmarshal(scanner.Bytes(), &raw)
			if raw["type"] == "component" {
				compCount++
			}
		}
		if compCount != 1 {
			t.Errorf("env %v: expected 1 component, got %d", tc.env, compCount)
		}
		if got := vulnerabilities(t, stdout); len(got) != tc.want {
			t.Errorf("env %v: expected %d vulnerabilities, got %d", tc.env, tc.want, len(got))
		}
	}
}

// A component nested in another is a component of the document: a dependency can name it by its bom-ref, and without it the
// edge would point at nothing. Both formats.
func TestCycloneDX_Wasm_NestedComponentsAreComponents(t *testing.T) {
	ctx := context.Background()
	wasmCode, err := os.ReadFile(compileWasm(t))
	if err != nil {
		t.Fatal(err)
	}
	names := func(t *testing.T, doc string) (comps []string, edges []string) {
		t.Helper()
		stdout, stderr, err := runWasm(ctx, t, wasmCode, []byte(doc), nil)
		if err != nil {
			t.Fatalf("%v\n%s", err, stderr)
		}
		sc := bufio.NewScanner(bytes.NewReader(stdout))
		for sc.Scan() {
			var ev map[string]any
			_ = json.Unmarshal(sc.Bytes(), &ev)
			switch ev["type"] {
			case "component":
				comps = append(comps, ev["ref"].(string))
			case "edge":
				edges = append(edges, ev["from"].(string)+">"+ev["to"].(string))
			}
		}
		return
	}

	comps, edges := names(t, `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"bom-ref":"outer","name":"outer","version":"1","components":[
	    {"bom-ref":"inner","name":"inner","version":"1","components":[{"bom-ref":"deep","name":"deep","version":"1"}]}]}],
	 "dependencies":[{"ref":"outer","dependsOn":["inner"]},{"ref":"inner","dependsOn":["deep"]}]}`)
	if strings.Join(comps, ",") != "outer,inner,deep" || strings.Join(edges, ",") != "outer>inner,inner>deep" {
		t.Errorf("JSON: components %v, edges %v", comps, edges)
	}

	comps, edges = names(t, `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
	  <components><component type="library" bom-ref="outer"><name>outer</name><version>1</version>
	    <components><component type="library" bom-ref="inner"><name>inner</name><version>1</version></component></components>
	  </component></components>
	  <dependencies><dependency ref="outer"><dependency ref="inner"/></dependency></dependencies></bom>`)
	if strings.Join(comps, ",") != "outer,inner" || strings.Join(edges, ",") != "outer>inner" {
		t.Errorf("XML: components %v, edges %v", comps, edges)
	}
}
