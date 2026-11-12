package integrations_test

import (
	"os"
	"testing"

	"rampart/internal/integrations"
)

// Every report format goes to its own parser when nobody says which it is (the processor falls back to this), and
// none takes another's report.
func TestAutodetectPicksTheRightParser(t *testing.T) {
	reg := integrations.DefaultRegistry()
	cases := map[string]string{
		"../parsers/trivy/testdata/image-0.50.json":      "builtin:trivy",
		"../parsers/grype/testdata/image-0.74.json":      "builtin:grype",
		"../parsers/semgrep/testdata/scan-1.45.json":     "builtin:semgrep",
		"../parsers/trufflehog/testdata/scan-3.63.jsonl": "builtin:trufflehog",
		"../parsers/gitleaks/testdata/repo-8.18.json":    "builtin:gitleaks",
		"../parsers/sarif/testdata/semgrep.sarif":        "builtin:sarif",
	}
	for path, want := range cases {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		head := b[:min(len(b), 64<<10)]
		got, score := reg.DetectParser(head, "", "")
		if got == nil || got.Descriptor().ID != want || score < 40 {
			id := ""
			if got != nil {
				id = got.Descriptor().ID
			}
			t.Errorf("%s: detected %q (score %d), want %q", path, id, score, want)
		}
	}
}
