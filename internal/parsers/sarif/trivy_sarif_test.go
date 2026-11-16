package sarif_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/sarif"
)

func parseFixture(t *testing.T, name string) []domain.RawFinding {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []domain.RawFinding
	pc := domain.ParseContext{TenantID: domain.NewID(), ScanSourceID: domain.NewID(), ScannerFamily: "sarif", Track: "main"}
	for raw, err := range sarif.NewParser().Parse(context.Background(), f, pc) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}

// Trivy writes vulnerabilities, misconfigurations and secrets into one SARIF file. A finding read from it
// used to have the whole multi-line message as its title, the rule id as its only link to the vulnerability (no
// VulnIDs, so KEV, EPSS and the CVE page never matched), no package, and every Trivy result as SCA, so a
// Dockerfile setting was filed as a vulnerable package. Real Trivy output from the demo pipeline.
func TestSARIF_TrivyVulnerabilityKeepsItsDetails(t *testing.T) {
	got := parseFixture(t, "trivy-vuln.sarif")
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d", len(got))
	}
	for _, f := range got {
		if f.Category != domain.CategorySCA {
			t.Errorf("%s: want sca, got %s", f.RuleID, f.Category)
		}
		if len(f.VulnIDs) != 1 || f.VulnIDs[0] != strings.ToUpper(f.RuleID) {
			t.Errorf("%s: the CVE must be a vulnerability id, got %v", f.RuleID, f.VulnIDs)
		}
		if strings.Contains(f.Title, "\n") || strings.Contains(f.Title, "Installed Version") {
			t.Errorf("%s: the title is the whole message: %q", f.RuleID, f.Title)
		}
		p := f.Location.Package
		if p == nil || p.ComponentName != "libcrypto3" || p.InstalledVersion != "3.5.6-r0" || p.FixedVersion == "" {
			t.Fatalf("%s: package not read from the message: %+v", f.RuleID, p)
		}
		if p.PurlBase == "" {
			t.Errorf("%s: without a purl the fingerprint is weak", f.RuleID)
		}
		if !strings.Contains(f.Description, "Installed Version") {
			t.Errorf("%s: the record the title dropped must stay in the description: %q", f.RuleID, f.Description)
		}
		fp := normalize.ComputeFingerprint(normalize.FingerprintParams{TenantID: domain.NewID(), AssetID: domain.NewID(), Track: "main", Scope: normalize.ScopeAsset, Family: "trivy", Category: f.Category, RuleID: f.RuleID, RawFinding: f})
		if fp.WeakFingerprint {
			t.Errorf("%s: the fingerprint is weak", f.RuleID)
		}
	}
}

func TestSARIF_TrivyMisconfigurationIsNotAPackage(t *testing.T) {
	got := parseFixture(t, "trivy-misconfig.sarif")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Category != domain.CategoryIaC {
		t.Errorf("a Dockerfile rule is iac, got %s", f.Category)
	}
	if len(f.VulnIDs) != 0 || f.Location.Package != nil {
		t.Errorf("a misconfiguration has no vulnerability id or package: %v %+v", f.VulnIDs, f.Location.Package)
	}
	if f.Title == "" || strings.Contains(f.Title, "\n") {
		t.Errorf("title: %q", f.Title)
	}
}

// A rule id is a vulnerability id only when it is one: SAST rule ids and look-alikes are not.
func TestSARIF_OnlyRealVulnerabilityIdsLink(t *testing.T) {
	for _, tc := range []struct {
		rule string
		want bool
	}{
		{"CVE-2021-44228", true}, {"cve-2021-44228", true}, {"GHSA-jfh8-c2jp-5v3q", true}, {"PYSEC-2020-1", true},
		{"CVE-2021", false}, {"java.lang.security.audit.xss", false}, {"CVE-2021-44228-extra", false}, {"R1", false},
	} {
		doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"` + tc.rule + `","message":{"text":"m"}}]}]}`
		var got []domain.RawFinding
		for raw, err := range sarif.NewParser().Parse(context.Background(), strings.NewReader(doc), domain.ParseContext{ScannerFamily: "sarif"}) {
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, raw)
		}
		if len(got) != 1 || (len(got[0].VulnIDs) == 1) != tc.want {
			t.Errorf("%s: linked=%v, want %v (%v)", tc.rule, len(got) == 1 && len(got[0].VulnIDs) == 1, tc.want, got)
		}
	}
}
