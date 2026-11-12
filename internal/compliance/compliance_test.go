package compliance

import "testing"

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
