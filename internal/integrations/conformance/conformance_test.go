package conformance

import (
	"context"
	"io"
	"iter"
	"os"
	"path/filepath"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/integrations"
	"rampart/internal/parsers/bandit"
)

func TestConformance_Bandit(t *testing.T) {
	tmpDir := t.TempDir()
	banditSample := `{
  "results": [
    {
      "code": "eval('foo')",
      "filename": "vuln.py",
      "issue_confidence": "HIGH",
      "issue_severity": "HIGH",
      "issue_text": "Use of eval",
      "line_number": 10,
      "test_id": "B307"
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "bandit.json"), []byte(banditSample), 0644); err != nil {
		t.Fatalf("failed to write test fixture: %v", err)
	}

	p := bandit.NewParser()
	adapter := &testParserAdapter{p}
	RunSuite(t, adapter, tmpDir)
}

type testParserAdapter struct {
	p *bandit.Parser
}

func (a *testParserAdapter) Descriptor() integrations.Descriptor {
	return integrations.Descriptor{
		ID:   "builtin:bandit",
		Name: "Bandit Parser",
		Kind: integrations.KindParser,
	}
}

func (a *testParserAdapter) Detect(head []byte, filename string, contentType string) int {
	return a.p.Detect(head, filename, contentType)
}

func (a *testParserAdapter) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return a.p.Parse(ctx, r, pc)
}
