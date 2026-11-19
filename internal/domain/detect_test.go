package domain_test

import (
	"testing"

	"rampart/internal/domain"
)

func TestDetectSpec_SimpleForm(t *testing.T) {
	d := domain.DetectSpec{
		Filenames: []string{"*semgrep*.json"}, ContentTypes: []string{"*json*"},
		Probes: []domain.DetectProbe{{JSONHasKeys: []string{"results", "check_id"}}},
	}
	if got := d.Score(nil, "SemGrep-Out.json", ""); got != 50 {
		t.Errorf("a file name alone is 50 (and is not case sensitive): %d", got)
	}
	if got := d.Score([]byte(`{"results":[{"check_id":"x"}]}`), "", ""); got != 60 {
		t.Errorf("a probe alone is 60: %d", got)
	}
	if got := d.Score([]byte(`{"results":[{"check_id":"x"}]}`), "semgrep.json", "application/json"); got != 100 {
		t.Errorf("the total is capped at 100: %d", got)
	}
	if got := d.Score([]byte(`{"results":[]}`), "", ""); got != 0 {
		t.Errorf("a probe needs all its keys: %d", got)
	}
}

func TestDetectSpec_WeightedRulesReproduceTheOldScorers(t *testing.T) {
	// Semgrep's old scorer: results 40, check_id 40, extra or paths 15, the file name 10; a SARIF document is refused.
	d := domain.DetectSpec{
		Filenames: []string{"*semgrep*"}, FilenameWeight: 10, Reject: []string{`"runs"`},
		Rules: []domain.DetectRule{
			{AnyOf: []string{`"results"`}, Weight: 40},
			{AnyOf: []string{`"check_id"`}, Weight: 40},
			{AnyOf: []string{`"extra"`, `"paths"`}, Weight: 15},
		},
	}
	report := []byte(`{"version":"1.80.0","results":[{"check_id":"r","extra":{}}]}`)
	if got := d.Score(report, "", ""); got != 95 {
		t.Errorf("results, check_id and extra: %d", got)
	}
	if got := d.Score(report, "semgrep.json", ""); got != 100 {
		t.Errorf("plus the file name: %d", got)
	}
	// A Bandit report has results and errors but no check_id: it does not reach a parser's threshold of 40 for Semgrep
	// with the two keys the old probe asked for; here it scores 40 (results alone), below the 80 of a real match.
	bandit := []byte(`{"errors":[],"metrics":{},"results":[{"test_id":"B101"}]}`)
	if got := d.Score(bandit, "", ""); got != 40 {
		t.Errorf("a Bandit report must not look like Semgrep: %d", got)
	}
	if got := d.Score([]byte(`{"runs":[{"results":[],"check_id":"x"}]}`), "", ""); got != 0 {
		t.Errorf("a SARIF document is refused: %d", got)
	}
}

func TestDetectSpec_MinScoreReturnAndAllOf(t *testing.T) {
	d := domain.DetectSpec{
		MinScore: 40,
		Rules: []domain.DetectRule{
			{AnyOf: []string{`"RuleID"`}, Weight: 40},
			{AllOf: []string{`"StartLine"`, `"File"`}, Weight: 30},
			{AnyOf: []string{`"format":"rampart-generic"`}, Return: 95},
		},
	}
	if got := d.Score([]byte(`[{"File":"a","StartLine":1}]`), "", ""); got != 0 {
		t.Errorf("30 is below the minimum: %d", got)
	}
	if got := d.Score([]byte(`[{"RuleID":"r","File":"a","StartLine":1}]`), "", ""); got != 70 {
		t.Errorf("40 and 30: %d", got)
	}
	if got := d.Score([]byte(`{"format":"rampart-generic","RuleID":"r"}`), "", ""); got != 95 {
		t.Errorf("a document that names its format ends the detection: %d", got)
	}
}
