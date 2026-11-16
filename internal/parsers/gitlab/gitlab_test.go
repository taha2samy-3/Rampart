package gitlab_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/gitlab"
)

func parse(t *testing.T, doc string) ([]domain.RawFinding, error) {
	t.Helper()
	var out []domain.RawFinding
	for rf, err := range gitlab.NewParser().Parse(context.Background(), strings.NewReader(doc), domain.ParseContext{}) {
		if err != nil {
			return out, err
		}
		out = append(out, rf)
	}
	return out, nil
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func parseFixture(t *testing.T, name string) []domain.RawFinding {
	t.Helper()
	got, err := parse(t, fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestDetect(t *testing.T) {
	p := gitlab.NewParser()
	for _, name := range []string{"gl-sast-report-15.json", "gl-secret-detection-report-15.json", "gl-dependency-scanning-report-15.json", "gl-container-scanning-report-15.json", "gl-dast-report-15.json"} {
		doc := []byte(fixture(t, name))
		if s := p.Detect(doc, "", ""); s < 40 {
			t.Errorf("%s without a file name scored %d", name, s)
		}
		if s := p.Detect(doc, "reports/gl-sast-report.json", ""); s < 80 {
			t.Errorf("%s with its file name scored %d", name, s)
		}
	}
	for name, other := range map[string]string{
		"sarif":     `{"runs":[{"results":[]}]}`,
		"cyclonedx": `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1"}]}`,
		"snyk":      `{"vulnerabilities":[{"identifiers":{"CVE":[]}}],"packageManager":"npm"}`,
		"grype":     `{"matches":[{"vulnerability":{"id":"CVE-1"}}]}`,
		"generic":   `{"findings":[{"title":"x","severity":"High"}]}`,
	} {
		if s := p.Detect([]byte(other), "x.json", ""); s >= 40 {
			t.Errorf("%s scored %d", name, s)
		}
	}
}

func TestSAST(t *testing.T) {
	got := parseFixture(t, "gl-sast-report-15.json")
	if len(got) != 2 {
		t.Fatalf("%d findings", len(got))
	}
	a := got[0]
	if a.Category != domain.CategorySAST || a.ScannerFamily != "gitlab-sast" || a.Severity != domain.SeverityHigh || a.ToolSeverity != "High" {
		t.Fatalf("sast: %+v", a)
	}
	if a.RuleID != "bandit.B608" || len(a.CWEs) != 1 || a.CWEs[0] != 89 || !strings.HasPrefix(a.Title, "Improper neutralization") {
		t.Fatalf("rule: %+v", a)
	}
	if c := a.Location.Code; c.FilePath != "app/db.py" || c.StartLine != 42 || c.LogicalLocation != "Repository.find_user" {
		t.Fatalf("location: %+v", c)
	}
	// Without a class or method, GitLab's tracking signature (scope_offset beats hash) keys the finding.
	b := got[1]
	if b.Location.Code.LogicalLocation != "" || b.Location.Code.SnippetHash != normalize.ComputeSnippetHash("scope_offset:app/crypto.py:5") {
		t.Fatalf("signature: %+v", b.Location.Code)
	}
	if !strings.Contains(b.Description, "Solution: Use SHA-256") {
		t.Fatalf("the solution is kept: %q", b.Description)
	}
}

func TestDependencyScanning(t *testing.T) {
	got := parseFixture(t, "gl-dependency-scanning-report-15.json")
	if len(got) != 2 {
		t.Fatalf("%d findings", len(got))
	}
	a := got[0]
	if a.Category != domain.CategorySCA || a.ScannerFamily != "gitlab-dependency-scanning" || a.Severity != domain.SeverityCritical {
		t.Fatalf("sca: %+v", a)
	}
	if normalize.CanonicalVulnID(a.VulnIDs) != "CVE-2021-44228" || len(a.VulnIDs) != 2 || a.CVSSVector == "" {
		t.Fatalf("ids: %v %q", a.VulnIDs, a.CVSSVector)
	}
	pkg := a.Location.Package
	if pkg.Purl != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" || pkg.PurlBase != "pkg:maven/org.apache.logging.log4j/log4j-core" || pkg.ManifestPath != "pom.xml" || pkg.InstalledVersion != "2.14.1" {
		t.Fatalf("package: %+v", pkg)
	}
	if p := got[1].Location.Package; p.Purl != "pkg:npm/minimist@1.2.5" || p.ManifestPath != "web/package-lock.json" {
		t.Fatalf("npm package: %+v", p)
	}
}

func TestContainerScanning(t *testing.T) {
	got := parseFixture(t, "gl-container-scanning-report-15.json")
	if len(got) != 1 {
		t.Fatalf("%d findings", len(got))
	}
	a := got[0]
	if a.Category != domain.CategorySCA || a.ScannerFamily != "gitlab-container-scanning" || a.Location.Image != "registry.example.com/shop/api:1.4.2" {
		t.Fatalf("container: %+v", a)
	}
	if p := a.Location.Package; p.Purl != "pkg:apk/alpine/libcrypto3@3.1.3-r0" || p.ComponentName != "libcrypto3" {
		t.Fatalf("package: %+v", p)
	}
}

func TestDAST(t *testing.T) {
	got := parseFixture(t, "gl-dast-report-15.json")
	if len(got) != 1 {
		t.Fatalf("%d findings", len(got))
	}
	a := got[0]
	if a.Category != domain.CategoryDAST || a.ScannerFamily != "gitlab-dast" || a.RuleID != "40012" || len(a.CWEs) != 1 || a.CWEs[0] != 79 {
		t.Fatalf("dast: %+v", a)
	}
	if w := a.Location.Web; w.NormalizedURL != "https://shop.example.com/search" || w.Method != "GET" || w.Parameter != "q" {
		t.Fatalf("web: %+v", w)
	}
	raw := string(a.RawPayload)
	if strings.Contains(raw, "f00dfeedcafe") || !strings.Contains(raw, "text/html") {
		t.Fatalf("the cookie must be redacted, the rest kept: %s", raw)
	}
}

// The secret tells two findings apart and is hashed by the pipeline; it is never stored.
func TestSecretDetection(t *testing.T) {
	got := parseFixture(t, "gl-secret-detection-report-15.json")
	if len(got) != 2 {
		t.Fatalf("%d findings", len(got))
	}
	for _, rf := range got {
		if rf.Category != domain.CategorySecret || rf.ScannerFamily != "gitlab-secret-detection" || rf.SecretValue == "" {
			t.Fatalf("secret: %+v", rf)
		}
		raw := string(rf.RawPayload)
		for _, s := range []string{"AKIAIOSFODNN7EXAMPLE", "glpat-7f3a9c1e5b2d48f6aa01"} {
			if strings.Contains(raw, s) || strings.Contains(rf.Title, s) || strings.Contains(rf.Description, s) {
				t.Fatalf("the secret is stored: %s", raw)
			}
		}
		if !strings.Contains(raw, "[redacted]") || !strings.Contains(raw, "identifiers") {
			t.Fatalf("the rest of the record is kept: %s", raw)
		}
	}
	if got[0].RuleID != "AWS" || got[0].Location.Code.FilePath != "config/prod.env" || got[0].Location.Code.StartLine != 3 {
		t.Fatalf("aws: %+v", got[0])
	}
	key := func(f domain.RawFinding) string {
		return normalize.ComputeFingerprint(normalize.FingerprintParams{Family: f.ScannerFamily, Category: f.Category, RuleID: f.RuleID, RawFinding: f, Scope: normalize.ScopeAsset}).FindingKey
	}
	a, moved := got[0], got[0]
	moved.Location.Code = &domain.CodeLocation{FilePath: a.Location.Code.FilePath, StartLine: 40}
	if key(a) != key(moved) {
		t.Fatal("the same secret on another line must be the same finding")
	}
}

// "scan" usually comes last; the kind of each finding is read from its location, so the order does not matter.
func TestScanFirstOrLast(t *testing.T) {
	last := `{"version":"15.0.7","vulnerabilities":[{"id":"1","name":"x","severity":"Low","identifiers":[{"type":"cve","name":"CVE-2024-1","value":"CVE-2024-1"}],
		"location":{"file":"go.sum","dependency":{"package":{"name":"golang.org/x/net"},"version":"0.1.0"}}}],
		"scan":{"type":"dependency_scanning","scanner":{"id":"gemnasium","name":"Gemnasium","version":"5"},"analyzer":{"id":"gemnasium"}}}`
	first := `{"version":"15.0.7","scan":{"type":"dependency_scanning","scanner":{"id":"gemnasium","name":"Gemnasium","version":"5"},"analyzer":{"id":"gemnasium"}},
		"vulnerabilities":[{"id":"1","name":"x","severity":"Low","identifiers":[{"type":"cve","name":"CVE-2024-1","value":"CVE-2024-1"}],
		"location":{"file":"go.sum","dependency":{"package":{"name":"golang.org/x/net"},"version":"0.1.0"}}}]}`
	a, err := parse(t, last)
	if err != nil || len(a) != 1 {
		t.Fatal(a, err)
	}
	b, err := parse(t, first)
	if err != nil || len(b) != 1 {
		t.Fatal(b, err)
	}
	if a[0].ScannerFamily != b[0].ScannerFamily || a[0].Category != b[0].Category || a[0].Location.Package.Purl != b[0].Location.Package.Purl {
		t.Fatalf("order changed the finding: %+v vs %+v", a[0], b[0])
	}
	if a[0].Location.Package.Purl != "pkg:golang/golang.org/x/net@0.1.0" || b[0].ScannerName != "gemnasium" || b[0].ScannerVersion != "5" {
		t.Fatalf("go package: %+v %+v", a[0].Location.Package, b[0])
	}
}

func TestMalformed(t *testing.T) {
	full := fixture(t, "gl-sast-report-15.json")
	for name, doc := range map[string]string{"truncated": full[:len(full)/2], "not json": "x", "an array": `[]`, "vulnerabilities not an array": `{"vulnerabilities":{}}`} {
		if _, err := parse(t, doc); err == nil {
			t.Errorf("%s: an error is expected", name)
		}
	}
	if got, err := parse(t, `{"version":"15.0.7","vulnerabilities":[],"scan":{"type":"sast"}}`); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	// A record of the wrong shape is reported and skipped; the others are read.
	var recs []domain.RecordError
	pc := domain.ParseContext{RecordError: func(re domain.RecordError) { recs = append(recs, re) }}
	doc := `{"vulnerabilities":[{"id":"1","identifiers":"nope"},{"id":"2","name":"ok","identifiers":[{"type":"cwe","name":"CWE-79","value":"79"}],"location":{"file":"a.go","start_line":1}}]}`
	n := 0
	for _, err := range gitlab.NewParser().Parse(context.Background(), strings.NewReader(doc), pc) {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 1 || len(recs) != 1 || recs[0].Where != "vulnerabilities 1" {
		t.Fatalf("findings %d, record errors %+v", n, recs)
	}
}
