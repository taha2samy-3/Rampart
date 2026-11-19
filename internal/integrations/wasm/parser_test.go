package wasm_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/integrations/wasm"
)

func TestWasmParserDetection(t *testing.T) {
	manifest := []byte(`
apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterParser
metadata:
  name: wasm-scanner
spec:
  version: "1.0.0"
  family: wasmscanner
  category: sast
  runtime: wasm
  source:
    oci: "registry.internal/parsers/wasmscanner:1.0.0"
  detect:
    filenames:
      - "*wasm*.json"
    probes:
      - jsonHasKeys: ["wasm_scan_id"]
`)

	p, err := wasm.NewWasmParserFromSpec("wasm-scanner", manifest, nil)
	if err != nil {
		t.Fatalf("failed to create WASM parser: %v", err)
	}

	// One scale for every parser kind (domain.DetectSpec): a file name adds 50, a probe 60, capped at 100.
	// 1. Both filename and probe match -> 100
	score := p.Detect([]byte(`{"wasm_scan_id": "123"}`), "wasm-report.json", "application/json")
	if score != 100 {
		t.Errorf("expected score 100, got %d", score)
	}

	// 2. Only filename matches -> 50
	score = p.Detect([]byte(`{"other": "data"}`), "wasm-report.json", "application/json")
	if score != 50 {
		t.Errorf("expected score 50, got %d", score)
	}

	// 3. Only probe matches -> 60
	score = p.Detect([]byte(`{"wasm_scan_id": "123"}`), "report.json", "application/json")
	if score != 60 {
		t.Errorf("expected score 60, got %d", score)
	}

	// 4. Neither matches -> 0
	score = p.Detect([]byte(`{"other": "data"}`), "report.json", "application/json")
	if score != 0 {
		t.Errorf("expected score 0, got %d", score)
	}
}

func TestWasmParserExecution(t *testing.T) {
	wasmBytes, err := os.ReadFile("/tmp/wasmpkg/test.wasm")
	if err != nil {
		t.Skip("skipping wasm execution test; /tmp/wasmpkg/test.wasm not present")
	}

	manifest := []byte(`
apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterParser
metadata:
  name: demo-wasm
spec:
  version: "1.0.0"
  family: wasmdemo
  category: sast
  runtime: wasm
  source:
    oci: "local/test:1.0"
`)

	p, err := wasm.NewWasmParserFromSpec("demo-wasm", manifest, wasmBytes)
	if err != nil {
		t.Fatalf("failed to create WASM parser: %v", err)
	}

	ctx := context.Background()
	var findings []domain.RawFinding
	for f, err := range p.Parse(ctx, strings.NewReader(`{}`), domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("unexpected wasm error: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "WASM-001" || f.Title != "WASM Finding" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.Severity != domain.SeverityHigh {
		t.Errorf("expected severity high, got %s", f.Severity)
	}
}
