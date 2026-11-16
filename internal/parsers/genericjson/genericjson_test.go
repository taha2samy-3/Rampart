package genericjson_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/normalize"
	"rampart/internal/parsers/genericjson"
)

func parse(t *testing.T, doc string) ([]domain.RawFinding, error) {
	t.Helper()
	var out []domain.RawFinding
	for rf, err := range genericjson.NewParser().Parse(context.Background(), strings.NewReader(doc), domain.ParseContext{}) {
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

func TestDetect(t *testing.T) {
	p := genericjson.NewParser()
	if s := p.Detect([]byte(fixture(t, "rampart-generic-v1.json")), "", ""); s < 90 {
		t.Fatalf("a document with the format marker scored %d", s)
	}
	// Without the marker it is recognised, but low: any parser that knows the document scores higher.
	if s := p.Detect([]byte(fixture(t, "defectdojo-generic.json")), "", ""); s < 40 || s > 45 {
		t.Fatalf("a DefectDojo generic document scored %d", s)
	}
	for name, other := range map[string]string{
		"dependency-track": `{"version":"1.2","findings":[{"component":{"name":"a"},"vulnerability":{"vulnId":"CVE-1"},"title":"x","severity":"HIGH"}]}`,
		"gitlab":           `{"version":"15.0.7","vulnerabilities":[{"identifiers":[]}],"findings":[{"title":"x","severity":"High"}]}`,
		"sarif":            `{"runs":[{"results":[]}],"findings":[{"title":"x"}]}`,
		"no findings":      `{"title":"x","severity":"high"}`,
		"an array":         `[{"title":"x","severity":"high"}]`,
	} {
		if s := p.Detect([]byte(other), "x.json", ""); s > 0 {
			t.Errorf("%s scored %d", name, s)
		}
	}
}

func TestParseRampartFormat(t *testing.T) {
	got, err := parse(t, fixture(t, "rampart-generic-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("%d findings", len(got))
	}
	for _, rf := range got {
		if rf.ScannerFamily != "generic:acme-audit" || rf.ScannerName != "Acme Audit" || rf.ScannerVersion != "2.3.0" {
			t.Fatalf("scanner: %+v", rf)
		}
	}

	sast := got[0]
	if sast.Category != domain.CategorySAST || sast.RuleID != "acme.sql-concat" || sast.Severity != domain.SeverityHigh || sast.ToolRecordID != "ACME-0001" {
		t.Fatalf("sast: %+v", sast)
	}
	if c := sast.Location.Code; c.FilePath != "src/auth/login.go" || c.StartLine != 42 || c.EndLine != 44 {
		t.Fatalf("code: %+v", c)
	}
	if len(sast.CWEs) != 1 || sast.CWEs[0] != 89 || !strings.Contains(sast.Description, "Mitigation: Use bound parameters.") {
		t.Fatalf("cwe/description: %v %q", sast.CWEs, sast.Description)
	}

	sca := got[1]
	if sca.Category != domain.CategorySCA || normalize.CanonicalVulnID(sca.VulnIDs) != "CVE-2021-23337" || sca.RuleID != "CVE-2021-23337" || sca.CVSSVector == "" {
		t.Fatalf("sca: %+v", sca)
	}
	if p := sca.Location.Package; p.PurlBase != "pkg:npm/lodash" || p.InstalledVersion != "4.17.20" || p.FixedVersion != "4.17.21" || p.ManifestPath != "web/package-lock.json" {
		t.Fatalf("package: %+v", p)
	}

	secret := got[2]
	if secret.Category != domain.CategorySecret || secret.SecretValue == "" || secret.Severity != domain.SeverityCritical {
		t.Fatalf("secret: %+v", secret)
	}
	if strings.Contains(string(secret.RawPayload), "mock_stripe_secret_token") || !strings.Contains(string(secret.RawPayload), "[redacted]") {
		t.Fatalf("the secret must not be stored: %s", secret.RawPayload)
	}

	dast := got[3]
	if dast.Category != domain.CategoryDAST || dast.Severity != domain.SeverityMedium || len(dast.CWEs) != 1 || dast.CWEs[0] != 601 {
		t.Fatalf("dast (severity from the CVSS score): %+v", dast)
	}
	if w := dast.Location.Web; w.NormalizedURL != "https://app.example.com/login" || w.Method != "GET" || w.Parameter != "next" {
		t.Fatalf("web: %+v", w)
	}

	cspm := got[4]
	if cspm.Category != domain.CategoryCSPM || cspm.Location.Resource.Key != "arn:aws:s3:::acme-uploads" || cspm.ToolRecordID != "" {
		t.Fatalf("cspm: %+v", cspm)
	}
}

// A document written for DefectDojo's Generic Findings Import loads unchanged.
func TestParseDefectDojoFormat(t *testing.T) {
	got, err := parse(t, fixture(t, "defectdojo-generic.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d findings", len(got))
	}
	tls := got[0]
	if tls.ScannerFamily != "generic:homegrown-scanner" || tls.Category != domain.CategoryDAST || tls.RuleID != "TLS-OLD" || tls.ToolRecordID != "hs-77" {
		t.Fatalf("tls: %+v", tls)
	}
	if tls.Location.Web == nil || tls.Location.Web.NormalizedURL != "https://api.example.com:8443/health" || tls.Location.Code != nil {
		t.Fatalf("endpoint: %+v", tls.Location)
	}
	if len(tls.CWEs) != 1 || tls.CWEs[0] != 326 || len(tls.VulnIDs) != 0 {
		t.Fatalf("ids: %v %v", tls.CWEs, tls.VulnIDs)
	}
	jq := got[1]
	if jq.Category != domain.CategorySCA || normalize.CanonicalVulnID(jq.VulnIDs) != "CVE-2020-11022" || len(jq.VulnIDs) != 2 {
		t.Fatalf("jquery: %+v", jq)
	}
	if p := jq.Location.Package; p.ComponentName != "jquery" || p.InstalledVersion != "1.12.4" || p.PurlBase != "pkg:generic/jquery" {
		t.Fatalf("package: %+v", p)
	}
	if jq.Location.Code == nil || jq.Location.Code.StartLine != 1 {
		t.Fatalf("a line given as a string is read: %+v", jq.Location.Code)
	}
}

func TestMalformed(t *testing.T) {
	full := fixture(t, "rampart-generic-v1.json")
	for name, doc := range map[string]string{"truncated": full[:len(full)/2], "not json": "x", "an array": `[]`, "findings not an array": `{"findings":{}}`} {
		if _, err := parse(t, doc); err == nil {
			t.Errorf("%s: an error is expected", name)
		}
	}
	if got, err := parse(t, `{"findings":[]}`); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	// A finding without a title, or of the wrong shape, is reported and skipped; the others are read.
	var recs []domain.RecordError
	pc := domain.ParseContext{RecordError: func(re domain.RecordError) { recs = append(recs, re) }}
	doc := `{"findings":[{"severity":"high"},{"title":"x","line":{}},{"title":"ok","severity":"low"}]}`
	n := 0
	for _, err := range genericjson.NewParser().Parse(context.Background(), strings.NewReader(doc), pc) {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 1 || len(recs) != 2 || recs[0].Where != "findings 1" || recs[1].Where != "findings 2" {
		t.Fatalf("findings %d, record errors %+v", n, recs)
	}
}
