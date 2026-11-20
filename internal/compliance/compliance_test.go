package compliance

import (
	"strings"
	"testing"
)

func TestFrameworksLoadAndAreWellFormed(t *testing.T) {
	fs, err := All()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"owasp-top10-2021": 10, "owasp-top10-2025": 10, "cwe-top25": 25}
	got := map[string]bool{}
	for _, f := range fs {
		got[f.ID] = true
		if n, ok := want[f.ID]; ok && len(f.Controls) != n {
			t.Errorf("%s has %d controls, want %d", f.ID, len(f.Controls), n)
		}
		if f.Source == "" || f.Version == "" {
			t.Errorf("%s: a framework says where it comes from and which version", f.ID)
		}
	}
	for _, id := range []string{"owasp-top10-2021", "owasp-top10-2025", "cwe-top25", "pci-dss-4.0.1-req6", "iso27001-2022-a8", "nist-ssdf-1.1"} {
		if !got[id] {
			t.Errorf("framework %s is missing", id)
		}
	}
	// A weakness belongs where OWASP says: injection and cross-site scripting are A03, SSRF is A10.
	o, _ := Get("owasp-top10-2021")
	has := func(ctl string, cwe int) bool {
		for _, c := range o.Controls {
			if c.ID == ctl {
				for _, n := range c.CWEs {
					if n == cwe {
						return true
					}
				}
			}
		}
		return false
	}
	if !has("A03:2021", 89) || !has("A03:2021", 79) || !has("A10:2021", 918) {
		t.Fatal("the OWASP mapping lost CWE-89, CWE-79 or CWE-918")
	}
}

func TestStatusRule(t *testing.T) {
	none := map[string]bool{}
	sast := Control{ID: "x", Name: "x", Categories: []string{"sast"}}
	if sast.Assessed(map[string]bool{"sca": true}, none) || !sast.Assessed(map[string]bool{"sast": true}, none) {
		t.Fatal("a control is assessed by the kinds of scan it names")
	}
	// D102: a weakness in the application's own code is found by a code scan; a dependency or image scan alone does
	// not assess an injection control.
	byCWE := Control{ID: "y", Name: "y", CWEs: []int{89}}
	if !byCWE.Assessed(map[string]bool{"dast": true}, none) || byCWE.Assessed(map[string]bool{"sca": true, "container": true}, none) {
		t.Fatal("a control matched by weakness needs a code scan (SAST or DAST)")
	}
	withEvidence := Control{ID: "z", Name: "z", CWEs: []int{89}, Evidence: []string{"sca"}}
	if !withEvidence.Assessed(map[string]bool{"sca": true}, none) {
		t.Fatal("evidence named by the control replaces the default")
	}
	byRule := Control{ID: "r", Name: "r", Rules: []RuleMatch{{ScannerFamily: "semgrep", RuleID: "python.*"}}}
	if byRule.Assessed(map[string]bool{"sast": true}, none) || !byRule.Assessed(none, map[string]bool{"semgrep": true}) {
		t.Fatal("a control matched by rules is assessed by its rules' scanner")
	}
	if q, exact := byCWE.Query(); q != "cwe:89 state:open,under_investigation,affected" || !exact {
		t.Fatalf("query: %q %v", q, exact)
	}
	if q, exact := sast.Query(); q != "category:sast state:open,under_investigation,affected" || !exact {
		t.Fatalf("query: %q %v", q, exact)
	}
	mixed := Control{ID: "m", Name: "m", CWEs: []int{89}, Categories: []string{"secret"}}
	if _, exact := mixed.Query(); exact {
		t.Fatal("a control matched two ways cannot be listed by one filter, and must say so")
	}
	if _, exact := byRule.Query(); exact {
		t.Fatal("a wildcard rule cannot be listed exactly")
	}
}

// D102: a clean run is recorded under its parser's id; it still counts for the parser's categories, and a family
// nothing knows takes what the tenant says about it.
func TestCategoriesOf(t *testing.T) {
	if c := CategoriesOf("cluster:semgrep", nil); len(c) == 0 || c[0] != "sast" {
		t.Fatalf("cluster:semgrep: %v", c)
	}
	if c := CategoriesOf("builtin:semgrep", nil); len(c) == 0 || c[0] != "sast" {
		t.Fatalf("builtin:semgrep: %v", c)
	}
	if c := CategoriesOf("cluster:dependencycheck", nil); len(c) != 1 || c[0] != "sca" {
		t.Fatalf("cluster:dependencycheck: %v", c)
	}
	if c := CategoriesOf("builtin:dependencycheck", nil); len(c) != 1 || c[0] != "sca" {
		t.Fatalf("builtin:dependencycheck: %v", c)
	}
	if c := CategoriesOf("codeql", nil); len(c) != 1 || c[0] != "sast" {
		t.Fatalf("codeql: %v", c)
	}
	if c := CategoriesOf("generic:acme", map[string][]string{"generic:acme": {"dast"}}); len(c) != 1 || c[0] != "dast" {
		t.Fatalf("an unknown family takes the tenant's categories: %v", c)
	}
	if c := CategoriesOf("sarif:unknown", nil); len(c) != 0 {
		t.Fatalf("a family nothing knows evidences nothing: %v", c)
	}
}

// D102: a framework resource is checked strictly, and every refusal names the control and what to do.
func TestParseFrameworkSpec(t *testing.T) {
	good := `{"displayName":"ACME policy","version":"2026.1","appliesTo":{"complianceScope":"pci"},"controls":[
	  {"id":"SC-1","name":"No hard-coded credentials","match":{"categories":["secret"]}},
	  {"id":"SC-2","name":"No critical or high injection","match":{"cwes":[89,79],"minSeverity":"high"},"evidence":{"categories":["sast","dast"]}},
	  {"id":"SC-3","name":"Threat model each release","manual":true},
	  {"id":"SC-4","name":"No eval","match":{"rules":[{"scannerFamily":"semgrep","ruleId":"python.lang.security.audit.eval*"}]}}]}`
	spec, err := ParseFrameworkSpec([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	f := spec.Framework("acme", "tenant")
	if f.Scope != "pci" || len(f.Controls) != 4 || !f.Controls[2].Manual || f.Controls[1].MinSeverity != "high" || f.Window() != DefaultWindowDays {
		t.Fatalf("framework: %+v", f)
	}
	for name, raw := range map[string]string{
		"misspelled field":  `{"displayName":"x","version":"1","controls":[{"id":"a","name":"a","match":{"categories":["sast"]}}],"evidenceWindow":3}`,
		"no version":        `{"displayName":"x","controls":[{"id":"a","name":"a","match":{"categories":["sast"]}}]}`,
		"no controls":       `{"displayName":"x","version":"1","controls":[]}`,
		"matches nothing":   `{"displayName":"x","version":"1","controls":[{"id":"a","name":"a"}]}`,
		"unknown category":  `{"displayName":"x","version":"1","controls":[{"id":"a","name":"a","match":{"categories":["sasst"]}}]}`,
		"repeated id":       `{"displayName":"x","version":"1","controls":[{"id":"a","name":"a","manual":true},{"id":"a","name":"b","manual":true}]}`,
		"manual with match": `{"displayName":"x","version":"1","controls":[{"id":"a","name":"a","manual":true,"match":{"categories":["sast"]}}]}`,
		"bad severity":      `{"displayName":"x","version":"1","controls":[{"id":"a","name":"a","match":{"cwes":[89],"minSeverity":"severe"}}]}`,
		"wildcard mid-rule": `{"displayName":"x","version":"1","controls":[{"id":"a","name":"a","match":{"rules":[{"scannerFamily":"semgrep","ruleId":"a*b"}]}}]}`,
		"window too long":   `{"displayName":"x","version":"1","evidenceWindowDays":400,"controls":[{"id":"a","name":"a","manual":true}]}`,
		"scope upper case":  `{"displayName":"x","version":"1","appliesTo":{"complianceScope":"PCI"},"controls":[{"id":"a","name":"a","manual":true}]}`,
		"empty evidence":    `{"displayName":"x","version":"1","controls":[{"id":"a","name":"a","match":{"cwes":[89]},"evidence":{}}]}`,
	} {
		if _, err := ParseFrameworkSpec([]byte(raw)); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}

// The 2025 list as OWASP's category pages print it (D58): the counts each page states, weaknesses where 2025 moved
// them (SSRF into broken access control, XXE into misconfiguration, a new category for exceptional conditions),
// the A03 correction, and the newer version listed first.
func TestOWASP2025(t *testing.T) {
	o, ok := Get("owasp-top10-2025")
	if !ok {
		t.Fatal("owasp-top10-2025 is missing")
	}
	want := map[string]int{"A01:2025": 40, "A02:2025": 16, "A03:2025": 6, "A04:2025": 32, "A05:2025": 37,
		"A06:2025": 39, "A07:2025": 36, "A08:2025": 14, "A09:2025": 5, "A10:2025": 24}
	has := map[string]map[int]bool{}
	for _, c := range o.Controls {
		if len(c.CWEs) != want[c.ID] {
			t.Errorf("%s maps %d weaknesses, the OWASP page says %d", c.ID, len(c.CWEs), want[c.ID])
		}
		has[c.ID] = map[int]bool{}
		for _, n := range c.CWEs {
			has[c.ID][n] = true
		}
	}
	for ctl, cwe := range map[string]int{"A01:2025": 918, "A02:2025": 611, "A05:2025": 89, "A10:2025": 703, "A03:2025": 477} {
		if !has[ctl][cwe] {
			t.Errorf("CWE-%d should be under %s", cwe, ctl)
		}
	}
	if has["A03:2025"][447] {
		t.Error("CWE-447 is the page's typo for CWE-477")
	}
	fs, _ := All()
	var order []string
	for _, f := range fs {
		if f.Name == "OWASP Top 10" {
			order = append(order, f.Version)
		}
	}
	if len(order) != 2 || order[0] != "2025" {
		t.Errorf("the newer OWASP list should come first: %v", order)
	}
}

func TestFrameworkSpec_LogoURL(t *testing.T) {
	doc := func(logo string) []byte {
		return []byte(`{"displayName":"Acme","version":"1","logoUrl":"` + logo + `","controls":[{"id":"A-1","name":"x","manual":true}]}`)
	}
	for _, ok := range []string{"", "https://logos.acme.example/mark.svg", "https://cdn.example.com/a/b.png?v=2"} {
		spec, err := ParseFrameworkSpec(doc(ok))
		if err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
			continue
		}
		if f := spec.Framework("acme", "tenant"); f.LogoURL != ok {
			t.Errorf("the framework must carry the address to the server: %q", f.LogoURL)
		}
	}
	long := "https://example.com/" + strings.Repeat("a", 2100)
	for _, bad := range []string{"http://logos.acme.example/mark.png", "ftp://x/y.png", "data:image/png;base64,AAAA", "//logos.acme.example/m.png", "javascript:alert(1)", "https://user:pw@logos.acme.example/m.png", "https:///m.png", long} {
		if _, err := ParseFrameworkSpec(doc(bad)); err == nil || !strings.Contains(err.Error(), "logoUrl") {
			t.Errorf("%q must be refused, naming logoUrl: %v", bad[:min(len(bad), 30)], err)
		}
	}
	// A built-in framework has no logoUrl: the screen draws its mark.
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all {
		if f.LogoURL != "" {
			t.Errorf("built-in %s must not point at another site", f.ID)
		}
	}
}
