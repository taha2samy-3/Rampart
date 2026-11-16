package query

import (
	"testing"
	"time"

	"rampart/internal/domain"
)

// D101: coverage folds into one row per kind of testing, in a fixed order; a kind nobody scanned stays as a gap;
// an unclassified family counts for the categories of what it produced; open findings land on their category.
func TestScanCoverage(t *testing.T) {
	now := time.Now().UTC()
	d := domain.AppDetail{
		Coverage: []domain.CoverageRow{
			{Asset: "repo", Scanner: "semgrep", LastScan: now.Add(-time.Hour)},
			{Asset: "repo", Scanner: "gitleaks", LastScan: now.Add(-2 * time.Hour)},
			{Asset: "repo", Scanner: "generic:acme", LastScan: now.Add(-3 * time.Hour)},
		},
		OpenByCategory: map[string]map[string]int{"sast": {"high": 2}, "secrets": {"critical": 1}, "license": {"low": 1}},
	}
	rows := scanCoverage(d, map[string][]string{"generic:acme": {"dast"}})
	want := []string{"sast", "sca", "secret", "iac", "container", "dast", "cspm", "license"}
	if len(rows) != len(want) {
		t.Fatalf("rows: %+v", rows)
	}
	by := map[string]CategoryCoverage{}
	for i, r := range rows {
		if r.Category != want[i] {
			t.Fatalf("order: row %d is %s, want %s", i, r.Category, want[i])
		}
		by[r.Category] = r
	}
	if s := by["secret"].Scanners; len(s) != 2 || s[0] != "gitleaks" || s[1] != "semgrep" {
		t.Errorf("secret scanners: %v", s)
	}
	if by["secret"].Open["critical"] != 1 {
		t.Errorf("the old 'secrets' category counts as secret: %v", by["secret"].Open)
	}
	if by["sca"].LastScan != nil || len(by["sca"].Scanners) != 0 {
		t.Errorf("sca was never scanned and must stay a gap: %+v", by["sca"])
	}
	if by["dast"].LastScan == nil {
		t.Error("an unclassified family counts for the categories it produced")
	}
	if !by["sast"].LastScan.Equal(now.Add(-time.Hour)) || by["sast"].Open["high"] != 2 {
		t.Errorf("sast: %+v", by["sast"])
	}
}
