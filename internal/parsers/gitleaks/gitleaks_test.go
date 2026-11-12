package gitleaks_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/gitleaks"
)

func parse(t *testing.T, doc string) ([]domain.RawFinding, error) {
	t.Helper()
	var out []domain.RawFinding
	for rf, err := range gitleaks.NewParser().Parse(context.Background(), strings.NewReader(doc), domain.ParseContext{}) {
		if err != nil {
			return out, err
		}
		out = append(out, rf)
	}
	return out, nil
}

func fixture(t *testing.T) string {
	b, err := os.ReadFile("testdata/repo-8.18.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDetect(t *testing.T) {
	p := gitleaks.NewParser()
	if s := p.Detect([]byte(fixture(t)), "gitleaks-report.json", ""); s < 80 {
		t.Fatalf("a Gitleaks report must be recognised, got %d", s)
	}
	for name, other := range map[string]string{
		"an object":         `{"RuleID":"x"}`,
		"a list of numbers": `[1,2,3]`,
		"a list of objects": `[{"name":"a"},{"name":"b"}]`,
		"sarif":             `{"runs":[]}`,
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
	if len(got) != 2 {
		t.Fatalf("%d findings", len(got))
	}
	a := got[0]
	if a.Category != domain.CategorySecret || a.Severity != domain.SeverityHigh || a.RuleID != "aws-access-token" || a.Title != "AWS Access Key" {
		t.Fatalf("aws: %+v", a)
	}
	c := a.Location.Code
	if c.FilePath != "config/prod.env" || c.StartLine != 3 || c.StartColumn != 20 {
		t.Fatalf("location: %+v", c)
	}
	if got[1].Location.Code.FilePath != "scripts/deploy.py" {
		t.Fatalf("backslashes are normalized: %q", got[1].Location.Code.FilePath)
	}
}

// The secret tells two findings apart and is hashed by the pipeline; it is never stored.
func TestTheSecretIsNeverStored(t *testing.T) {
	got, err := parse(t, fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, rf := range got {
		if rf.SecretValue == "" {
			t.Fatal("the secret value is needed to tell findings apart")
		}
		raw := string(rf.RawPayload)
		if strings.Contains(raw, rf.SecretValue) || strings.Contains(raw, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(raw, "7f3a9c1e5b2d48f6") {
			t.Fatalf("the raw record holds the secret: %s", raw)
		}
		if !strings.Contains(raw, "[redacted]") || !strings.Contains(raw, "RuleID") {
			t.Fatalf("the rest of the record is kept: %s", raw)
		}
	}
	// Two different secrets of one rule in one file are two findings, and the same secret on another line is the same one.
	key := func(f domain.RawFinding) string {
		return normalize.ComputeFingerprint(normalize.FingerprintParams{Family: "gitleaks", Category: f.Category, RuleID: f.RuleID, RawFinding: f, Scope: normalize.ScopeAsset}).FindingKey
	}
	a, b := got[0], got[0]
	b.SecretValue = "a-different-secret"
	if key(a) == key(b) {
		t.Fatal("a different secret must be a different finding")
	}
	c := got[0]
	c.Location.Code = &domain.CodeLocation{FilePath: c.Location.Code.FilePath, StartLine: 99}
	if key(a) != key(c) {
		t.Fatal("the same secret on another line must be the same finding")
	}
}

func TestMalformed(t *testing.T) {
	full := fixture(t)
	for name, doc := range map[string]string{"truncated": full[:len(full)/2], "not json": "x", "an object": `{"a":1}`} {
		if _, err := parse(t, doc); err == nil {
			t.Errorf("%s: an error is expected", name)
		}
	}
	if got, err := parse(t, `[]`); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}
