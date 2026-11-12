package grype_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/parsers/grype"
)

func parse(t *testing.T, doc string) ([]domain.RawFinding, error) {
	t.Helper()
	var out []domain.RawFinding
	for rf, err := range grype.NewParser().Parse(context.Background(), strings.NewReader(doc), domain.ParseContext{}) {
		if err != nil {
			return out, err
		}
		out = append(out, rf)
	}
	return out, nil
}

func fixture(t *testing.T) string {
	b, err := os.ReadFile("testdata/image-0.74.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDetect(t *testing.T) {
	p := grype.NewParser()
	if s := p.Detect([]byte(fixture(t)), "grype.json", ""); s < 80 {
		t.Fatalf("a Grype report must be recognised, got %d", s)
	}
	for name, other := range map[string]string{
		"sarif": `{"version":"2.1.0","runs":[{"results":[]}]}`,
		"trivy": `{"SchemaVersion":2,"Results":[]}`,
		"empty": `{}`,
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
		t.Fatalf("%d findings, want 3 (ignoredMatches is not read)", len(got))
	}
	log4j := got[0]
	if log4j.Category != domain.CategorySCA || log4j.ScannerFamily != "grype" || log4j.Severity != domain.SeverityCritical {
		t.Fatalf("log4j: %+v", log4j)
	}
	// The id Grype matched on, then the related CVE: the pipeline picks the CVE as canonical (D11).
	if len(log4j.VulnIDs) != 2 || log4j.VulnIDs[0] != "GHSA-jfh8-c2jp-5v3q" || log4j.VulnIDs[1] != "CVE-2021-44228" {
		t.Fatalf("vuln ids %v", log4j.VulnIDs)
	}
	pk := log4j.Location.Package
	if pk.PurlBase != "pkg:maven/org.apache.logging.log4j/log4j-core" || pk.InstalledVersion != "2.14.1" || pk.FixedVersion != "2.15.0" || pk.ManifestPath != "/app/lib/log4j-core-2.14.1.jar" {
		t.Fatalf("package: %+v", pk)
	}
	if !strings.Contains(log4j.CVSSVector, "CVSS:3.1/AV:N") {
		t.Fatalf("cvss %q", log4j.CVSSVector)
	}
	if got[1].Severity != domain.SeverityInfo || got[1].Location.Package.FixedVersion != "" {
		t.Fatalf("negligible and unfixed: %+v", got[1])
	}
	if got[2].Severity != domain.SeverityCritical || got[2].ToolSeverity != "Unknown" {
		t.Fatalf("an unknown severity takes the CVSS 9.8: %q", got[2].Severity)
	}
}

func TestMalformed(t *testing.T) {
	full := fixture(t)
	for name, doc := range map[string]string{
		"truncated":          full[:len(full)/2],
		"not json":           "nope",
		"matches not a list": `{"matches": 3}`,
	} {
		if _, err := parse(t, doc); err == nil {
			t.Errorf("%s: an error is expected", name)
		}
	}
	if got, err := parse(t, `{"matches":[]}`); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}
