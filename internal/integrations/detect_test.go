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
		"../testdata/reports/trivy/image-0.50.json":                        "builtin:trivy",
		"../testdata/reports/grype/image-0.74.json":                        "builtin:grype",
		"../testdata/reports/semgrep/scan-1.45.json":                       "builtin:semgrep",
		"../testdata/reports/trufflehog/scan-3.63.jsonl":                   "builtin:trufflehog",
		"../testdata/reports/gitleaks/repo-8.18.json":                      "builtin:gitleaks",
		"../testdata/reports/sarif/semgrep.sarif":                          "builtin:sarif",
		"../testdata/reports/gitlab/gl-sast-report-15.json":                "builtin:gitlab",
		"../testdata/reports/gitlab/gl-secret-detection-report-15.json":    "builtin:gitlab",
		"../testdata/reports/gitlab/gl-dependency-scanning-report-15.json": "builtin:gitlab",
		"../testdata/reports/gitlab/gl-container-scanning-report-15.json":  "builtin:gitlab",
		"../testdata/reports/gitlab/gl-dast-report-15.json":                "builtin:gitlab",
		"../testdata/reports/genericjson/rampart-generic-v1.json":          "builtin:genericjson",
		"../testdata/reports/genericjson/defectdojo-generic.json":          "builtin:genericjson",
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
