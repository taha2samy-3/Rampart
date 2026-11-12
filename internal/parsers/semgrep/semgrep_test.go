package semgrep_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/semgrep"
)

func parse(t *testing.T, doc string) ([]domain.RawFinding, error) {
	t.Helper()
	var out []domain.RawFinding
	for rf, err := range semgrep.NewParser().Parse(context.Background(), strings.NewReader(doc), domain.ParseContext{}) {
		if err != nil {
			return out, err
		}
		out = append(out, rf)
	}
	return out, nil
}

func fixture(t *testing.T) string {
	b, err := os.ReadFile("testdata/scan-1.45.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDetect(t *testing.T) {
	p := semgrep.NewParser()
	if s := p.Detect([]byte(fixture(t)), "semgrep.json", ""); s < 80 {
		t.Fatalf("a Semgrep report must be recognised, got %d", s)
	}
	for name, other := range map[string]string{
		"sarif": `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[{"ruleId":"x"}]}]}`,
		"trivy": `{"SchemaVersion":2,"Results":[]}`,
	} {
		if s := p.Detect([]byte(other), "x.json", ""); s >= 40 {
			t.Errorf("%s scored %d", name, s)
		}
	}
}

func TestParse(t *testing.T) {
	got, err := parse(t, fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%d findings", len(got))
	}
	cmd := got[0]
	if cmd.Category != domain.CategorySAST || cmd.Severity != domain.SeverityHigh || cmd.ScannerVersion != "1.45.0" {
		t.Fatalf("command injection: %+v", cmd)
	}
	if len(cmd.CWEs) != 1 || cmd.CWEs[0] != 78 {
		t.Fatalf("cwes %v (a list)", cmd.CWEs)
	}
	c := cmd.Location.Code
	if c.FilePath != "app/handlers/export.py" || c.StartLine != 42 || c.EndLine != 42 || c.StartColumn != 5 || c.Snippet == "" || c.SnippetHash == "" {
		t.Fatalf("location: %+v", c)
	}
	if strings.Contains(cmd.Title, "Use subprocess") || cmd.Title == "" {
		t.Fatalf("the title is the first sentence: %q", cmd.Title)
	}
	xss := got[1]
	if xss.Severity != domain.SeverityMedium || len(xss.CWEs) != 1 || xss.CWEs[0] != 79 {
		t.Fatalf("xss: %+v (cwe given as one string)", xss)
	}
	if xss.Location.Code.Snippet != "" {
		t.Fatal(`Semgrep's "requires login" is not a snippet`)
	}
}

// Findings keep their key when the code moves down a few lines, because the key rests on the code and not the line.
func TestFingerprintSurvivesAMove(t *testing.T) {
	key := func(doc string) string {
		got, err := parse(t, doc)
		if err != nil || len(got) == 0 {
			t.Fatal(err)
		}
		return normalize.ComputeFingerprint(normalize.FingerprintParams{Family: "semgrep", Category: got[0].Category, RuleID: got[0].RuleID, RawFinding: got[0], Scope: normalize.ScopeAsset}).FindingKey
	}
	moved := strings.ReplaceAll(fixture(t), `"line": 42`, `"line": 57`)
	if key(fixture(t)) != key(moved) {
		t.Fatal("the key changed when only the line number did")
	}
	changed := strings.ReplaceAll(fixture(t), "convert", "resize")
	if key(fixture(t)) == key(changed) {
		t.Fatal("the key must change when the code does")
	}
}

// A secret found by a Semgrep rule is not kept: not in the snippet, not in the raw record.
func TestSecretsAreNotStored(t *testing.T) {
	got, err := parse(t, fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	sec := got[2]
	if sec.Category != domain.CategorySecret || sec.SecretValue == "" {
		t.Fatalf("secret: %+v", sec)
	}
	if strings.Contains(string(sec.RawPayload), "AKIAIOSFODNN7EXAMPLE") || sec.Location.Code.Snippet != "" {
		t.Fatal("the secret must not be stored")
	}
}

func TestMalformed(t *testing.T) {
	full := fixture(t)
	for name, doc := range map[string]string{"truncated": full[:len(full)/2], "not json": "x", "results not a list": `{"results": {}}`} {
		if _, err := parse(t, doc); err == nil {
			t.Errorf("%s: an error is expected", name)
		}
	}
	if got, err := parse(t, `{"version":"1","results":[]}`); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}
