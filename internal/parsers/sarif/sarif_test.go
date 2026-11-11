package sarif_test

import (
	"context"
	"os"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/sarif"
)

func TestSarifDetect(t *testing.T) {
	p := sarif.NewParser()

	// 1. High confidence by filename
	score := p.Detect([]byte(`{"version": "2.1.0"}`), "results.sarif", "application/json")
	if score < 80 {
		t.Errorf("expected high confidence score for .sarif file, got %d", score)
	}

	// 2. Low confidence for non-sarif
	scoreNon := p.Detect([]byte(`{"foo": "bar"}`), "report.xml", "text/xml")
	if scoreNon > 20 {
		t.Errorf("expected low confidence score for non-sarif, got %d", scoreNon)
	}
}

func TestSarifStreamingParse(t *testing.T) {
	f, err := os.Open("testdata/semgrep.sarif")
	if err != nil {
		t.Fatalf("failed to open test fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	p := sarif.NewParser()
	ctx := context.Background()
	parseCtx := domain.ParseContext{
		TenantID:      domain.NewID(),
		ScanSourceID:  domain.NewID(),
		ScannerFamily: "semgrep",
		Track:         "main",
	}

	var results []domain.RawFinding
	for finding, err := range p.Parse(ctx, f, parseCtx) {
		if err != nil {
			t.Fatalf("parsing error: %v", err)
		}
		results = append(results, finding)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	rf := results[0]

	// Assertions
	if rf.RuleID != "rules.go.sql-injection" {
		t.Errorf("expected rule ID 'rules.go.sql-injection', got %q", rf.RuleID)
	}
	if rf.ScannerFamily != "semgrep" {
		t.Errorf("expected scanner family 'semgrep', got %q", rf.ScannerFamily)
	}
	if rf.Category != domain.CategorySAST {
		t.Errorf("expected category 'sast', got %q", rf.Category)
	}
	if rf.Severity != domain.SeverityHigh {
		t.Errorf("expected severity 'high' from security-severity 8.5, got %q", rf.Severity)
	}
	if len(rf.CWEs) != 1 || rf.CWEs[0] != 89 {
		t.Errorf("expected CWE-89, got %v", rf.CWEs)
	}

	if rf.Location.Code == nil {
		t.Fatal("expected non-nil code location")
	}
	codeLoc := rf.Location.Code
	if codeLoc.FilePath != "pkg/auth/store.go" {
		t.Errorf("expected file path 'pkg/auth/store.go', got %q", codeLoc.FilePath)
	}
	if codeLoc.StartLine != 52 || codeLoc.EndLine != 54 {
		t.Errorf("expected lines 52-54, got %d-%d", codeLoc.StartLine, codeLoc.EndLine)
	}
	if codeLoc.LogicalLocation != "auth.GetUserByEmail" {
		t.Errorf("expected logical location 'auth.GetUserByEmail', got %q", codeLoc.LogicalLocation)
	}
	if codeLoc.SnippetHash == "" {
		t.Error("expected non-empty snippet hash")
	}

	// Verify that normalized fingerprint can be computed directly from the stream
	fp := normalize.ComputeFingerprint(normalize.FingerprintParams{
		TenantID:      parseCtx.TenantID,
		AssetID:       domain.NewID(),
		ApplicationID: domain.NewID(),
		Track:         parseCtx.Track,
		Family:        rf.ScannerFamily,
		Category:      rf.Category,
		RuleID:        rf.RuleID,
		RawFinding:    rf,
	})

	if fp.FindingKey == "" {
		t.Fatal("expected non-empty finding key from parsed raw finding")
	}
	if fp.WeakFingerprint {
		t.Error("expected strong fingerprint using logical location/snippet hash")
	}
}
