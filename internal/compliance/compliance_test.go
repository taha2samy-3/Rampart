package compliance

import "testing"

func TestFrameworksLoadAndAreWellFormed(t *testing.T) {
	fs, err := All()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"owasp-top10-2021": 10, "cwe-top25": 25}
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
	for _, id := range []string{"owasp-top10-2021", "cwe-top25", "pci-dss-4.0.1-req6", "iso27001-2022-a8", "nist-ssdf-1.1"} {
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
	sast := Control{ID: "x", Name: "x", Categories: []string{"sast"}}
	if sast.Assessed(map[string]bool{"sca": true}) || !sast.Assessed(map[string]bool{"sast": true}) {
		t.Fatal("a control is assessed by the kinds of scan it names")
	}
	byCWE := Control{ID: "y", Name: "y", CWEs: []int{89}}
	if !byCWE.Assessed(map[string]bool{"dast": true}) || byCWE.Assessed(map[string]bool{"secret": true}) {
		t.Fatal("a control matched by weakness needs a code or component scan")
	}
	if q := byCWE.Query(); q != "cwe:89 state:open,under_investigation,affected" {
		t.Fatalf("query: %q", q)
	}
	if q := sast.Query(); q != "category:sast state:open,under_investigation,affected" {
		t.Fatalf("query: %q", q)
	}
}
