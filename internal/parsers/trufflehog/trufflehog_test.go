package trufflehog_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/trufflehog"
)

func parse(t *testing.T, doc string) ([]domain.RawFinding, error) {
	t.Helper()
	var out []domain.RawFinding
	for rf, err := range trufflehog.NewParser().Parse(context.Background(), strings.NewReader(doc), domain.ParseContext{}) {
		if err != nil {
			return out, err
		}
		out = append(out, rf)
	}
	return out, nil
}

func fixture(t *testing.T) string {
	b, err := os.ReadFile("testdata/scan-3.63.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDetect(t *testing.T) {
	p := trufflehog.NewParser()
	if s := p.Detect([]byte(fixture(t)), "trufflehog.jsonl", ""); s < 80 {
		t.Fatalf("a TruffleHog report must be recognised, got %d", s)
	}
	for name, other := range map[string]string{
		"gitleaks": `[{"RuleID":"x","StartLine":1,"File":"a","Secret":"s"}]`,
		"sarif":    `{"runs":[]}`,
		"trivy":    `{"SchemaVersion":2,"Results":[]}`,
		"empty":    ``,
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
		t.Fatalf("%d findings, want 3 (the log line is not one)", len(got))
	}
	aws := got[0]
	if aws.Category != domain.CategorySecret || aws.RuleID != "aws" || !aws.SecretVerified || aws.Severity != domain.SeverityCritical || aws.ToolSeverity != "verified" {
		t.Fatalf("a verified secret is critical: %+v", aws)
	}
	if aws.Location.Code.FilePath != "config/prod.env" || aws.Location.Code.StartLine != 3 {
		t.Fatalf("location: %+v", aws.Location.Code)
	}
	gh := got[1]
	if gh.SecretVerified || gh.Severity != domain.SeverityHigh || gh.ToolSeverity != "unverified" || !strings.Contains(gh.Description, "not verified") {
		t.Fatalf("an unverified secret is high: %+v", gh)
	}
	if got[2].Location.Code.FilePath != "/work/.env.local" { // the filesystem source names its file the same way
		t.Fatalf("filesystem source: %+v", got[2].Location.Code)
	}
}

func TestTheCredentialIsNeverStored(t *testing.T) {
	got, err := parse(t, fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, rf := range got {
		raw := string(rf.RawPayload)
		for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI", "ghp_7f3a9c1e5b2d48f6a0c9e1d3b5a7f9c2e4d6b8", "xoxb-EXAMPLE-TOKEN-NOT-REAL-FOR-TESTING"} {
			if strings.Contains(raw, secret) {
				t.Fatalf("the raw record holds a credential: %s", raw)
			}
		}
		if strings.Contains(raw, `"Raw":"AKIA`) || strings.Contains(raw, `"RawV2":"AKIA`) {
			t.Fatalf("Raw or RawV2 is kept: %s", raw)
		}
		if strings.Contains(raw, "ghp_7f3a") && strings.Contains(raw, "ghp_7f3a9c") {
			t.Fatalf("more than the first characters of a credential are kept: %s", raw)
		}
		if !strings.Contains(raw, "[redacted]") || !strings.Contains(raw, "DetectorName") {
			t.Fatalf("the rest of the record is kept: %s", raw)
		}
		if rf.SecretValue == "" {
			t.Fatal("the secret value is needed to tell findings apart")
		}
	}
}

// Verifying a credential changes the severity, not which finding it is.
func TestVerificationDoesNotChangeTheKey(t *testing.T) {
	a, _ := parse(t, fixture(t))
	flipped := strings.Replace(fixture(t), `"Verified":true`, `"Verified":false`, 1)
	b, _ := parse(t, flipped)
	key := func(f domain.RawFinding) string {
		return normalize.ComputeFingerprint(normalize.FingerprintParams{Family: "trufflehog", Category: f.Category, RuleID: f.RuleID, RawFinding: f, Scope: normalize.ScopeAsset}).FindingKey
	}
	if key(a[0]) != key(b[0]) {
		t.Fatal("verifying must not make it another finding")
	}
	if a[0].Severity == b[0].Severity {
		t.Fatal("verifying must change the severity")
	}
}

func TestMalformed(t *testing.T) {
	for name, doc := range map[string]string{"not json": "this is not json", "truncated": fixture(t)[:300]} {
		if _, err := parse(t, doc); err == nil {
			t.Errorf("%s: an error is expected", name)
		}
	}
	if got, err := parse(t, ``); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}
