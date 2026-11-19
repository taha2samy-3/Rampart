package conformance

import (
	"os"
	"path/filepath"
	"testing"

	"rampart/internal/config/parsers"
	"rampart/internal/integrations/lua"
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

	banditYAML, err := parsers.GetDefaultParser("bandit")
	if err != nil {
		t.Fatalf("failed to load default bandit manifest: %v", err)
	}

	p, err := lua.NewLuaParserFromSpec("bandit", banditYAML)
	if err != nil {
		t.Fatalf("failed to instantiate bandit lua parser: %v", err)
	}

	RunSuite(t, p, tmpDir)
}
