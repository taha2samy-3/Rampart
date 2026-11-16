package mapping

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"rampart/internal/domain"
)

// A declarative parser could fill only the rule, title, severity, vulnerability ids, file and package. It could not
// say which weakness a finding is, its CVSS vector, the file that declares the package, or its category per record,
// and a purl alone left the fingerprint weak. Now it fills the fields the built-in parsers fill.
const richYAML = `
apiVersion: rampart.aspm.dev/v1alpha1
kind: IntegrationPackage
metadata:
  name: rich
spec:
  kind: parser
  runtime: mapping
  version: 1.0.0
  family: rich
  category: sca
  detect:
    probes:
      - jsonHasKeys: [issues]
  input:
    format: json
    records: $.issues[*]
  map:
    ruleId: rec.id
    title: rec.title
    severity: rec.sev
    vulnIds: '[rec.id]'
    cwes: 'rec.cwes'
    cvssVector: rec.cvss
    category: 'rec.kind == "config" ? "iac" : ""'
    location:
      package:
        purl: rec.purl
        name: rec.name
        installedVersion: rec.version
        manifestPath: rec.manifest
  severityMap: {HIGH: high}
  limits: {maxRecords: 100, maxDepth: 32}
`

func parseRich(t *testing.T, doc string) []domain.RawFinding {
	t.Helper()
	p, err := NewMappingParser([]byte(richYAML))
	if err != nil {
		t.Fatal(err)
	}
	var out []domain.RawFinding
	for f, err := range p.Parse(context.Background(), strings.NewReader(doc), domain.ParseContext{}) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

func TestMappingParser_FillsWeaknessCVSSManifestAndCategory(t *testing.T) {
	got := parseRich(t, `{"issues":[
	  {"id":"CVE-1","title":"t","sev":"HIGH","cwes":["CWE-79","79","cwe-89: SQLi","x",0],"cvss":"CVSS:3.1/AV:N","purl":"pkg:npm/lodash@4.17.20?type=x","name":"lodash","version":"4.17.20","manifest":"package-lock.json","kind":"pkg"},
	  {"id":"CFG-1","title":"c","sev":"HIGH","cwes":[],"cvss":"","purl":"","name":"","version":"","manifest":"","kind":"config"}]}`)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	a, b := got[0], got[1]
	if !reflect.DeepEqual(a.CWEs, []int{79, 89}) { // each once, bad entries dropped, "CWE-89: SQLi" read
		t.Errorf("cwes: %v", a.CWEs)
	}
	if a.CVSSVector != "CVSS:3.1/AV:N" || a.Category != domain.CategorySCA {
		t.Errorf("cvss %q category %q", a.CVSSVector, a.Category)
	}
	p := a.Location.Package
	if p == nil || p.PurlBase != "pkg:npm/lodash" || p.ManifestPath != "package-lock.json" || p.InstalledVersion != "4.17.20" {
		t.Errorf("package: %+v", p)
	}
	if b.Category != domain.CategoryIaC || b.Location.Package != nil || len(b.CWEs) != 0 {
		t.Errorf("a record's own category wins over the package's: %+v", b)
	}
}

func TestMappingParser_AnInvalidCategoryFallsBackToThePackages(t *testing.T) {
	got := parseRich(t, `{"issues":[{"id":"A","title":"t","sev":"HIGH","kind":"config"}]}`)
	if len(got) != 1 || got[0].Category != domain.CategoryIaC {
		t.Fatalf("%+v", got)
	}
	bad := strings.Replace(richYAML, `'rec.kind == "config" ? "iac" : ""'`, `'"banana"'`, 1)
	p, err := NewMappingParser([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	for f, err := range p.Parse(context.Background(), strings.NewReader(`{"issues":[{"id":"A","title":"t","sev":"HIGH"}]}`), domain.ParseContext{}) {
		if err != nil || f.Category != domain.CategorySCA {
			t.Fatalf("an unknown category must not be stored, want sca: %v %q", err, f.Category)
		}
	}
}

func TestPurlBase(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/lodash@4.17.20":             "pkg:npm/lodash",
		"pkg:npm/%40angular/core@12.0.0":     "pkg:npm/%40angular/core",
		"pkg:maven/org.x/y@1.0?type=jar#sub": "pkg:maven/org.x/y",
		"pkg:golang/github.com/a/b":          "pkg:golang/github.com/a/b",
		"":                                   "",
	} {
		if got := purlBase(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
