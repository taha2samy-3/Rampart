package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/integrations"
)

// Result captures the findings emitted during conformance testing.
type Result struct {
	Findings     []domain.RawFinding  `json:"findings"`
	RecordErrors []domain.RecordError `json:"record_errors,omitempty"`
}

// RunSuite runs the normative integration conformance test suite against a parser contract (docs/19 §9).
func RunSuite(t *testing.T, parser integrations.ParserContract, fixtureDir string) {
	t.Helper()

	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("conformance: failed to read fixture directory %s: %v", fixtureDir, err)
	}

	var inputFile string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "input.") || strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".xml") {
			if !strings.Contains(name, "golden") {
				inputFile = filepath.Join(fixtureDir, name)
				break
			}
		}
	}

	if inputFile == "" {
		t.Fatalf("conformance: no input file found in %s", fixtureDir)
	}

	inputBytes, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("conformance: failed to read input file %s: %v", inputFile, err)
	}

	// 1. Detection Check
	score := parser.Detect(inputBytes[:min(len(inputBytes), 64*1024)], filepath.Base(inputFile), "application/json")
	if score <= 0 {
		t.Errorf("conformance: parser %s failed to detect %s (score=%d)", parser.Descriptor().ID, filepath.Base(inputFile), score)
	}

	// 2. Parse Execution & Isolation
	var recordErrors []domain.RecordError
	pc := domain.ParseContext{
		RecordError: func(re domain.RecordError) {
			recordErrors = append(recordErrors, re)
		},
	}

	var firstRunFindings []domain.RawFinding
	for f, err := range parser.Parse(context.Background(), bytes.NewReader(inputBytes), pc) {
		if err != nil {
			t.Fatalf("conformance: parse error: %v", err)
		}
		firstRunFindings = append(firstRunFindings, f)
	}

	if len(firstRunFindings) == 0 && len(recordErrors) == 0 {
		t.Errorf("conformance: parser produced neither findings nor record errors for %s", inputFile)
	}

	// 3. Secret Leakage Assertion (docs/16 D42)
	for i, f := range firstRunFindings {
		// Secret value must never be placed into public title, description, or location
		if f.SecretValue != "" {
			if strings.Contains(f.Title, f.SecretValue) {
				t.Errorf("conformance: secret value leaked in finding[%d].Title", i)
			}
			if strings.Contains(f.Description, f.SecretValue) {
				t.Errorf("conformance: secret value leaked in finding[%d].Description", i)
			}
		}
	}

	// 4. Fingerprint & Idempotency Stability Check
	var secondRunFindings []domain.RawFinding
	for f, err := range parser.Parse(context.Background(), bytes.NewReader(inputBytes), pc) {
		if err != nil {
			t.Fatalf("conformance: second parse error: %v", err)
		}
		secondRunFindings = append(secondRunFindings, f)
	}

	if len(firstRunFindings) != len(secondRunFindings) {
		t.Fatalf("conformance: non-deterministic finding count: run1=%d, run2=%d", len(firstRunFindings), len(secondRunFindings))
	}

	for i := range firstRunFindings {
		f1 := firstRunFindings[i]
		f2 := secondRunFindings[i]
		if f1.RuleID != f2.RuleID || f1.Title != f2.Title || f1.Severity != f2.Severity || f1.ToolRecordID != f2.ToolRecordID {
			t.Errorf("conformance: finding[%d] mismatch across runs: %+v vs %+v", i, f1, f2)
		}
	}

	// 5. Golden Output Verification (if golden file exists)
	goldenFile := filepath.Join(fixtureDir, "golden.json")
	if goldenBytes, err := os.ReadFile(goldenFile); err == nil {
		var goldenResult Result
		if err := json.Unmarshal(goldenBytes, &goldenResult); err == nil {
			if len(firstRunFindings) != len(goldenResult.Findings) {
				t.Errorf("conformance: golden mismatch in findings count: got %d, want %d", len(firstRunFindings), len(goldenResult.Findings))
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
