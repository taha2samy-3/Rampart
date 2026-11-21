package integrations_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"rampart/internal/domain"
	"rampart/internal/integrations"
	_ "rampart/internal/integrations/lua"  // the runtimes a parser needs register themselves
	_ "rampart/internal/integrations/wasm" // on import, as they do in the server
)

const reportManifests = "../testdata/parsers/report"

// specOnly is a ClusterParser the way the control plane stores it: the spec alone, as JSON.
func specOnly(t *testing.T, manifest []byte) []byte {
	t.Helper()
	var doc struct {
		Spec map[string]any `yaml:"spec"`
	}
	if err := yaml.Unmarshal(manifest, &doc); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(doc.Spec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// An installed parser is the same parser whether it comes from the whole resource (a file) or from its spec alone (the
// control plane), and it has the id the compliance report and the gate read.
func TestInstalledParserIsTheSameFromAFileAndFromTheControlPlane(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(reportManifests, "*.yaml"))
	if len(files) < 16 {
		t.Fatalf("expected the 16 report manifests, found %d", len(files))
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".yaml")
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		fromFile, err := integrations.NewInstalledParser(name, raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fromSpec, err := integrations.NewInstalledParser(name, specOnly(t, raw))
		if err != nil {
			t.Fatalf("%s (spec alone): %v", name, err)
		}
		a, b := fromFile.Descriptor(), fromSpec.Descriptor()
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: the descriptor depends on where the parser came from:\n file %+v\n spec %+v", name, a, b)
		}
		if a.ID != "cluster:"+name || a.Kind != integrations.KindParser || a.Category == "" {
			t.Errorf("%s: unexpected descriptor %+v", name, a)
		}
	}
}

// A parser installed from the directory (a file, in a Compose or one-binary deployment) is the parser the control plane gives.
func TestInstalledFromADirectoryEqualsInstalledFromTheControlPlane(t *testing.T) {
	embedded := integrations.DefaultRegistry()
	reports := map[string][]byte{}
	for _, f := range []string{
		"../testdata/reports/trivy/image-0.50.json", "../testdata/reports/grype/image-0.74.json", "../testdata/reports/semgrep/scan-1.45.json",
		"../testdata/reports/trufflehog/scan-3.63.jsonl", "../testdata/reports/gitleaks/repo-8.18.json", "../testdata/reports/sarif/semgrep.sarif",
		"../testdata/reports/gitlab/gl-sast-report-15.json", "../testdata/reports/genericjson/rampart-generic-v1.json",
		"../testdata/reports/genericjson/defectdojo-generic.json",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		reports[f] = b
	}
	files, _ := filepath.Glob(filepath.Join(reportManifests, "*.yaml"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".yaml")
		raw, _ := os.ReadFile(f)
		want, err := embedded.GetParser("cluster:" + name)
		if err != nil {
			t.Fatalf("%s: not installed from the directory: %v", name, err)
		}
		got, err := integrations.NewInstalledParser(name, specOnly(t, raw))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want.Descriptor(), got.Descriptor()) {
			t.Errorf("%s: descriptor differs:\n directory %+v\n control plane %+v", name, want.Descriptor(), got.Descriptor())
		}
		for path, data := range reports {
			head := data
			if len(head) > 64<<10 {
				head = head[:64<<10]
			}
			if w, g := want.Detect(head, filepath.Base(path), ""), got.Detect(head, filepath.Base(path), ""); w != g {
				t.Errorf("%s on %s: detect %d, installed %d", name, filepath.Base(path), w, g)
			}
		}
	}
}

func findings(t *testing.T, p integrations.ParserContract, file string) int {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, err := range p.Parse(context.Background(), bytes.NewReader(data), domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		n++
	}
	return n
}

// The control plane keeps a ClusterParser's spec alone. The WASM and Lua runtimes read a whole resource and refused a spec alone
// ("source.oci or source.file is required", "script is required"): a parser installed through the operator never loaded, and
// the compiled-in copy hid it. Both shapes must now run the same report to the same findings.
func TestInstalledParserFromTheSpecAloneReadsARealReport(t *testing.T) {
	for _, c := range []struct{ name, report string }{
		{"trivy", "../testdata/reports/trivy/image-0.50.json"},                     // wasm
		{"sarif", "../testdata/reports/sarif/semgrep.sarif"},                       // wasm
		{"genericjson", "../testdata/reports/genericjson/rampart-generic-v1.json"}, // lua
	} {
		raw, err := os.ReadFile(filepath.Join(reportManifests, c.name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		whole, err := integrations.NewInstalledParser(c.name, raw)
		if err != nil {
			t.Fatal(err)
		}
		alone, err := integrations.NewInstalledParser(c.name, specOnly(t, raw))
		if err != nil {
			t.Fatal(err)
		}
		a, b := findings(t, whole, c.report), findings(t, alone, c.report)
		if a == 0 || a != b {
			t.Errorf("%s: the resource gave %d findings and its spec alone gave %d", c.name, a, b)
		}
	}
}

func firstError(t *testing.T, p integrations.ParserContract) error {
	t.Helper()
	for _, err := range p.Parse(context.Background(), bytes.NewReader([]byte("{}")), domain.ParseContext{}) {
		return err
	}
	return nil
}

// A parser that cannot run says so when it is used, with the parser and the reason, and never panics. A runtime that refused
// a spec used to leave a nil parser inside an interface and the server panicked.
func TestInstalledParserThatCannotRunSaysWhy(t *testing.T) {
	// the module is missing
	p, err := integrations.NewInstalledParser("no-such-module", []byte(`{"runtime":"wasm","category":"sast","version":"1.0.0","source":{"oci":"ghcr.io/example/no-such-module:v1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := firstError(t, p); got == nil || !strings.Contains(got.Error(), "no-such-module") {
		t.Errorf("a missing module: want an error that names the parser, got %v", got)
	}

	// the runtime refuses the spec (a wasm parser that names no source)
	p, err = integrations.NewInstalledParser("no-source", []byte(`{"runtime":"wasm","category":"sast","version":"1.0.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	got := firstError(t, p)
	if got == nil || !strings.Contains(got.Error(), "cluster:no-source") || !strings.Contains(got.Error(), "source.oci or source.file is required") {
		t.Errorf("a refused spec: want the parser and the runtime's reason, got %v", got)
	}
}
