package trivy_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/trivy"
)

func parse(t *testing.T, doc string) ([]domain.RawFinding, error) {
	t.Helper()
	var out []domain.RawFinding
	var firstErr error
	for rf, err := range trivy.NewParser().Parse(context.Background(), strings.NewReader(doc), domain.ParseContext{}) {
		if err != nil {
			firstErr = err
			break
		}
		out = append(out, rf)
	}
	return out, firstErr
}

func fixture(t *testing.T) string {
	b, err := os.ReadFile("testdata/image-0.50.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDetect(t *testing.T) {
	p := trivy.NewParser()
	if s := p.Detect([]byte(fixture(t)[:600]), "report.json", ""); s < 80 {
		t.Fatalf("a Trivy report must be recognised, got %d", s)
	}
	for name, other := range map[string]string{
		"sarif":  `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[]}]}`,
		"grype":  `{"matches":[],"descriptor":{"name":"grype"}}`,
		"empty":  `{}`,
		"a list": `[1,2,3]`,
	} {
		if s := p.Detect([]byte(other), "x.json", ""); s >= 40 {
			t.Errorf("%s scored %d: it must not be taken for Trivy", name, s)
		}
	}
}

func TestParseImageReport(t *testing.T) {
	got, err := parse(t, fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]domain.RawFinding{}
	for _, rf := range got {
		by[rf.RuleID] = rf
	}
	// not_affected is left out, a PASS misconfiguration is left out: 2 package vulns, 1 secret, 1 misconfig, 1 license.
	if len(got) != 5 {
		t.Fatalf("%d findings, want 5: %v", len(got), keys(by))
	}
	if _, ok := by["CVE-2099-0001"]; ok {
		t.Error("a vulnerability Trivy says is not affected must not be a finding")
	}

	ssl := by["CVE-2023-5363"]
	if ssl.Category != domain.CategorySCA || ssl.Severity != domain.SeverityHigh || ssl.ScannerFamily != "trivy" {
		t.Fatalf("os package vuln: %+v", ssl)
	}
	pk := ssl.Location.Package
	if pk.PurlBase != "pkg:apk/alpine/libssl3" || pk.InstalledVersion != "3.1.3-r0" || pk.FixedVersion != "3.1.4-r0" || pk.ManifestPath != "" {
		t.Fatalf("package: %+v", pk)
	}
	if ssl.Location.Image != "registry.acme.example/shop/api:2.14.0" || len(ssl.CWEs) != 1 || ssl.CWEs[0] != 1285 {
		t.Fatalf("image %q cwes %v", ssl.Location.Image, ssl.CWEs)
	}
	if !strings.HasPrefix(ssl.CVSSVector, "CVSS:3.1/AV:N/AC:L/PR:N") { // the highest v3 score of the sources, 7.5 not 5.9
		t.Fatalf("cvss vector %q", ssl.CVSSVector)
	}
	if len(ssl.RawPayload) == 0 {
		t.Fatal("the raw record is kept")
	}

	// A language package: the manifest is the target, the purl is derived (this report has none), and a UNKNOWN
	// severity is taken from the CVSS score.
	lodash := by["CVE-2021-23337"]
	if lodash.Location.Package.PurlBase != "pkg:npm/lodash" || lodash.Location.Package.ManifestPath != "app/package-lock.json" {
		t.Fatalf("lang package: %+v", lodash.Location.Package)
	}
	if lodash.Severity != domain.SeverityHigh || lodash.ToolSeverity != "UNKNOWN" {
		t.Fatalf("severity %q from tool %q: want high from the CVSS 7.2", lodash.Severity, lodash.ToolSeverity)
	}
	if lodash.Title == "" {
		t.Fatal("a title is made when Trivy gave none")
	}

	sec := by["aws-access-key-id"]
	if sec.Category != domain.CategorySecret || sec.Severity != domain.SeverityCritical || sec.Location.Code.FilePath != "app/.env" || sec.Location.Code.StartLine != 3 {
		t.Fatalf("secret: %+v", sec)
	}

	mis := by["DS002"]
	if mis.Category != domain.CategoryIaC || mis.Severity != domain.SeverityHigh || mis.Location.Resource.Address != "Dockerfile" || mis.Location.Code.StartLine != 1 {
		t.Fatalf("misconfiguration: %+v", mis)
	}
	if !strings.Contains(mis.Description, "Specify at least 1 USER") {
		t.Fatalf("the message is part of the description: %q", mis.Description)
	}

	lic := by["GPL-3.0"]
	if lic.Category != domain.CategoryLicense || lic.Location.Package.PurlBase != "pkg:generic/gnutls" {
		t.Fatalf("license: %+v", lic)
	}
}

// Two reports of the same image with the same problems give the same finding keys, whatever else changed.
func TestFingerprintsAreStable(t *testing.T) {
	key := func(doc string) map[string]bool {
		got, err := parse(t, doc)
		if err != nil {
			t.Fatal(err)
		}
		keys := map[string]bool{}
		for _, rf := range got {
			fp := normalize.ComputeFingerprint(normalize.FingerprintParams{Family: "trivy", Category: rf.Category, RuleID: rf.RuleID, RawFinding: rf, Scope: normalize.ScopeAsset})
			keys[fp.FindingKey] = true
		}
		return keys
	}
	a := key(fixture(t))
	// Same findings, but the report is formatted differently and the image tag changed.
	b := key(strings.ReplaceAll(strings.ReplaceAll(fixture(t), "2.14.0", "2.15.0"), "  ", " "))
	if len(a) != 5 || len(a) != len(b) {
		t.Fatalf("%d and %d distinct keys, want 5 and 5", len(a), len(b))
	}
	for k := range a {
		if !b[k] {
			t.Fatal("a finding's key changed between two reports of the same problems")
		}
	}
}

func TestMalformedReports(t *testing.T) {
	full := fixture(t)
	for name, doc := range map[string]string{
		"truncated":        full[:len(full)/2],
		"not json":         "this is not json",
		"results not list": `{"Results": 5}`,
		"wrong element":    `{"Results":[{"Target":"x","Vulnerabilities":[7]}]}`,
	} {
		if _, err := parse(t, doc); err == nil {
			t.Errorf("%s: an error is expected, not silence", name)
		}
	}
	// An empty report is a report with no findings.
	if got, err := parse(t, `{"SchemaVersion":2,"Results":[]}`); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	if got, err := parse(t, `{"SchemaVersion":2,"Results":null}`); err != nil || len(got) != 0 {
		t.Fatalf("null results: %v %v", got, err)
	}
}

func TestStopsWhenTheConsumerStops(t *testing.T) {
	n := 0
	for _, err := range trivy.NewParser().Parse(context.Background(), strings.NewReader(fixture(t)), domain.ParseContext{}) {
		if err != nil {
			t.Fatal(err)
		}
		if n++; n == 2 {
			break
		}
	}
	if n != 2 {
		t.Fatalf("consumed %d", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, err := range trivy.NewParser().Parse(ctx, strings.NewReader(fixture(t)), domain.ParseContext{}) {
		if err == nil {
			t.Fatal("a cancelled context must not yield findings")
		}
		break
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
