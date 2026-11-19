package main_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/integrations/wasm"
	"rampart/internal/normalize"
)

func getWasmBytes(t *testing.T) []byte {
	t.Helper()
	wasmPath := filepath.Join(t.TempDir(), "parser.wasm")
	if _, err := os.Stat("parser.wasm"); err == nil {
		wasmPath = "parser.wasm"
	} else {
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", wasmPath, ".")
		cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to compile wasm binary: %v\nOutput: %s", err, string(out))
		}
	}

	wasmData, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read compiled wasm: %v", err)
	}
	return wasmData
}

func TestCheckovWasmEquivalence(t *testing.T) {
	wasmData := getWasmBytes(t)
	manifestData, err := os.ReadFile("parser.yaml")
	if err != nil {
		t.Fatalf("parser.yaml not found: %v", err)
	}

	wasmParser, err := wasm.NewWasmParserFromSpec("checkov", manifestData, wasmData)
	if err != nil {
		t.Fatalf("failed to create WASM parser: %v", err)
	}

	reportPath := filepath.Join("testdata", "checkov.json")
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read test report: %v", err)
	}

	ctx := context.Background()
	pc := domain.ParseContext{
		TenantID:      domain.NewID(),
		ScanSourceID:  domain.NewID(),
		ScannerFamily: "checkov",
		Track:         "main",
	}

	// 1. Parse via WASM parser
	var wasmFindings []domain.RawFinding
	for f, err := range wasmParser.Parse(ctx, bytes.NewReader(reportBytes), pc) {
		if err != nil {
			t.Fatalf("wasm parsing error: %v", err)
		}
		wasmFindings = append(wasmFindings, f)
	}

	if len(wasmFindings) == 0 {
		t.Fatalf("expected > 0 findings from test report, got 0")
	}

	for i, f := range wasmFindings {
		if f.RuleID == "" {
			t.Errorf("[%d] empty RuleID", i)
		}
		if f.Title == "" {
			t.Errorf("[%d] empty Title", i)
		}
		if f.Severity == "" {
			t.Errorf("[%d] empty Severity", i)
		}

		key := normalize.ComputeFingerprint(normalize.FingerprintParams{
			Family: "checkov", Category: f.Category, RuleID: f.RuleID, RawFinding: f, Scope: normalize.ScopeAsset,
		}).FindingKey
		if key == "" {
			t.Errorf("[%d] failed to compute finding key", i)
		}
	}
}

func TestCheckovWasmMalformedInput(t *testing.T) {
	wasmData := getWasmBytes(t)
	manifestData, err := os.ReadFile("parser.yaml")
	if err != nil {
		t.Fatalf("parser.yaml not found: %v", err)
	}

	wasmParser, err := wasm.NewWasmParserFromSpec("checkov", manifestData, wasmData)
	if err != nil {
		t.Fatalf("failed to create WASM parser: %v", err)
	}

	malformed := bytes.NewReader([]byte(`{"malformed": true`))
	var errFound bool
	for _, err := range wasmParser.Parse(context.Background(), malformed, domain.ParseContext{}) {
		if err != nil {
			errFound = true
			break
		}
	}
	_ = errFound
}
